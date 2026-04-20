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
#include <zmq.hpp>
#include <map>
#include <string>
#include <iostream>
#include <sstream>

// --- CONFIGURATION ---
#define ZMQ_ENDPOINT "ipc:///tmp/firewall_pipeline"
#define RESCAN_INTERVAL_PACKETS 50  // Re-check with AI every 50 packets
#define CACHE_TTL_SECONDS 10        // Flow stays valid for 10 seconds before re-check

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

// ZeroMQ Context and Sockets
zmq::context_t zmq_context(1);
zmq::socket_t brain_push_socket(zmq_context, zmq::socket_type::req); // Using REQ for direct Allow/Block feedback

// --- IPC HELPERS ---

void init_zmq() {
    printf("[CPP] Connecting to AI Brain via ZeroMQ (%s)...\n", ZMQ_ENDPOINT);
    brain_push_socket.connect(ZMQ_ENDPOINT);
}

bool ask_python_brain(const FlowKey& key, const unsigned char* payload, int payload_len) {
    try {
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
        std::string header = ss.str();

        // Send Header and Payload as a Multi-part Message
        zmq::message_t header_msg(header.size());
        memcpy(header_msg.data(), header.data(), header.size());
        brain_push_socket.send(header_msg, zmq::send_flags::sndmore);

        zmq::message_t payload_msg(payload_len);
        memcpy(payload_msg.data(), payload, payload_len);
        brain_push_socket.send(payload_msg, zmq::send_flags::none);

        // Wait for Response (ALLOW/BLOCK)
        zmq::message_t reply;
        auto res = brain_push_socket.recv(reply, zmq::recv_flags::none);
        
        std::string result(static_cast<char*>(reply.data()), reply.size());
        
        if (result == "ALLOW") return true;
        return false;
    } catch (const zmq::error_t& e) {
        fprintf(stderr, "[CPP] ZMQ Error: %s\n", e.what());
        return true; // Fail Open on ZMQ error for demo, or False for Fail Closed
    }
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
            verdict = ask_python_brain(key, payload_data, ret);
            
            FlowState new_state;
            new_state.is_allowed = verdict;
            new_state.packets_until_rescan = RESCAN_INTERVAL_PACKETS;
            new_state.expiration_time = time(NULL) + CACHE_TTL_SECONDS;
            flow_cache[key] = new_state;
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

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}