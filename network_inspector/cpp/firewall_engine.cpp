#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <map>
#include <memory>
#include <string>
#include <iostream>
#include <sstream>

#include "brain_client.hpp"

// --- CONFIGURATION ---
#define ZMQ_ENDPOINT "ipc:///tmp/firewall_pipeline"
#define RESCAN_INTERVAL_PACKETS 50  // Re-check with AI every 50 packets
#define CACHE_TTL_SECONDS 10        // Flow stays valid for 10 seconds before re-check
#define DEFAULT_BRAIN_TIMEOUT_MS 1500   // give up on a brain that does not answer (BRAIN_TIMEOUT_MS)
#define DEFAULT_BRAIN_COOLDOWN_MS 3000  // after a failure, skip the brain this long (BRAIN_COOLDOWN_MS)

// --- DATA STRUCTURES ---

struct FlowKey {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t protocol;
    uint16_t sport;
    uint16_t dport;

    bool operator<(const FlowKey& other) const {
        if (saddr != other.saddr) return saddr < other.saddr;
        if (daddr != other.daddr) return daddr < other.daddr;
        if (protocol != other.protocol) return protocol < other.protocol;
        if (sport != other.sport) return sport < other.sport;
        return dport < other.dport;
    }
};

struct FlowState {
    bool is_allowed;
    int packets_until_rescan;
    time_t expiration_time;
};

// Global Cache
std::map<FlowKey, FlowState> flow_cache;

// AI brain connection. Created in main(); see brain_client.hpp for the timeout / rebuild / cool-down logic.
static std::unique_ptr<BrainClient> brain;
static bool brain_fail_open_policy = true;  // BRAIN_FAIL_MODE=closed drops packets while the brain is down
static bool brain_down = false;             // only to log state changes once, not once per packet

// --- IPC HELPERS ---

// Integer from the environment in [min_value, 600000]; anything else is reported and replaced by the default.
static int env_int(const char* name, int fallback, int min_value) {
    const char* v = getenv(name);
    if (!v || !*v) return fallback;
    char* end = nullptr;
    long n = strtol(v, &end, 10);
    if (end && *end == '\0' && n >= min_value && n < 600000) return static_cast<int>(n);
    fprintf(stderr, "[CPP] ignoring %s=\"%s\" (need an integer >= %d); using %d\n", name, v, min_value, fallback);
    return fallback;
}

void init_zmq() {
    const int timeout_ms = env_int("BRAIN_TIMEOUT_MS", DEFAULT_BRAIN_TIMEOUT_MS, 1);
    const int cooldown_ms = env_int("BRAIN_COOLDOWN_MS", DEFAULT_BRAIN_COOLDOWN_MS, 0);
    brain_fail_open_policy = brain_fail_open(getenv("BRAIN_FAIL_MODE"));
    printf("[CPP] Connecting to AI Brain via ZeroMQ (%s), timeout %d ms, cool-down %d ms, fail-%s...\n",
           ZMQ_ENDPOINT, timeout_ms, cooldown_ms, brain_fail_open_policy ? "open" : "closed");
    brain = std::make_unique<BrainClient>(ZMQ_ENDPOINT, timeout_ms, cooldown_ms);
}

// Returns the BrainReply; `cacheable` is false when the brain could not be asked (do not remember a
// fail-open/closed guess as if it were a real verdict, so the flow is re-checked once the brain is back).
BrainReply ask_python_brain(const FlowKey& key, const unsigned char* payload, int payload_len) {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = key.saddr;
    dst_addr.s_addr = key.daddr;
    inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

    // Prepare Header: "check <src_ip> <dst_ip> <sport> <dport> <payload_len>"
    std::stringstream ss;
    ss << "check " << src_ip << " " << dst_ip << " "
       << key.sport << " " << key.dport << " " << payload_len;

    BrainReply reply = brain->check(ss.str(), payload, static_cast<std::size_t>(payload_len));

    if (reply.verdict == BrainVerdict::Unavailable) {
        if (!brain_down) {
            brain_down = true;
            fprintf(stderr, "[CPP] AI brain unavailable (%s): failing %s until it answers again\n",
                    brain->last_error().c_str(), brain_fail_open_policy ? "OPEN" : "CLOSED");
        }
    } else if (brain_down) {
        brain_down = false;
        fprintf(stderr, "[CPP] AI brain is answering again\n");
    }
    return reply;
}

// --- PACKET PROCESSING ---

void get_ports(const unsigned char* data, uint8_t proto, int ip_len, uint16_t* sport, uint16_t* dport) {
    int offset = 20; 
    if (proto == IPPROTO_TCP) {
        *sport = (data[offset] << 8) | data[offset+1];
        *dport = (data[offset+2] << 8) | data[offset+3];
    } else if (proto == IPPROTO_UDP) {
        *sport = (data[offset] << 8) | data[offset+1];
        *dport = (data[offset+2] << 8) | data[offset+3];
    } else {
        *sport = 0;
        *dport = 0;
    }
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload_data;
    int ret;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    ret = nfq_get_payload(nfa, &payload_data);
    if (ret >= 20) {
        uint8_t protocol = payload_data[9];
        uint32_t saddr = *((uint32_t*)(payload_data + 12));
        uint32_t daddr = *((uint32_t*)(payload_data + 16));
        
        uint16_t sport = 0, dport = 0;
        get_ports(payload_data, protocol, 20, &sport, &dport);

        FlowKey key = {saddr, daddr, protocol, sport, dport};
        
        bool decision_made = false;
        bool verdict = false;
        
        if (flow_cache.count(key)) {
            FlowState &state = flow_cache[key];
            time_t now = time(NULL);
            if (state.packets_until_rescan > 0 && now < state.expiration_time) {
                verdict = state.is_allowed;
                state.packets_until_rescan--;
                decision_made = true;
            }
        }

        if (!decision_made) {
            const BrainReply reply = ask_python_brain(key, payload_data, ret);
            if (reply.verdict == BrainVerdict::Unavailable) {
                // Brain dead or hung: apply the failure policy but do not cache it as a real verdict.
                verdict = brain_fail_open_policy;
            } else {
                verdict = (reply.verdict == BrainVerdict::Allow);

                FlowState new_state;
                new_state.is_allowed = verdict;
                new_state.packets_until_rescan = RESCAN_INTERVAL_PACKETS;
                new_state.expiration_time = time(NULL) + CACHE_TTL_SECONDS;
                flow_cache[key] = new_state;
            }
        }

        return nfq_set_verdict(qh, id, verdict ? NF_ACCEPT : NF_DROP, 0, NULL);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    init_zmq();

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 1, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        // ENOBUFS = the kernel's netlink queue overflowed while we were busy (e.g. waiting on the brain);
        // that drops some packets but must not take the whole engine down. EINTR = a signal arrived.
        if (errno == ENOBUFS) {
            fprintf(stderr, "[CPP] netlink buffer overflow: some queued packets were dropped; continuing\n");
            continue;
        }
        if (errno == EINTR) continue;
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}