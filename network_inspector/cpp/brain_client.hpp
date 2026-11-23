// Client for the Python "AI brain" (network_inspector/ai_brain.py) over a ZeroMQ REQ socket.
//
// The engine calls this from inside the NFQUEUE callback, so it must never block for long. Before this
// class the engine did a bare blocking recv(): when the brain died or hung, the callback waited forever
// and every queued packet (all DNS for the lab) waited with it. It also kept using one REQ socket, which
// cannot send again after a request lost its reply.
//
//  * A request that is not answered within `timeout_ms` yields Unavailable instead of blocking.
//  * ZMQ_IMMEDIATE makes a send fail when no connection exists, so a dead brain (nothing bound) is
//    detected within ~send_timeout_ms rather than after the full receive timeout.
//  * After any failure the socket is closed and rebuilt, so the client recovers when the brain returns.
//  * After a failure the client skips the brain for `cooldown_ms` (reply.skipped == true, no waiting), so a
//    dead brain costs one short stall per cooldown instead of one per flow.
//
// What to do with Unavailable (fail open or closed) is the caller's decision: see brain_fail_open().
#pragma once

#include <zmq.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>

enum class BrainVerdict { Allow, Block, Unavailable };

struct BrainReply {
    BrainVerdict verdict;
    bool skipped;  // true when the brain was not contacted because a recent failure is still cooling down
};

// "closed" (any case) fails closed; anything else, including unset, fails open (the project default).
inline bool brain_fail_open(const char* mode) {
    if (mode == nullptr) return true;
    std::string m(mode);
    std::transform(m.begin(), m.end(), m.begin(), [](unsigned char c) { return std::tolower(c); });
    return m != "closed";
}

class BrainClient {
public:
    using Clock = std::chrono::steady_clock;

    BrainClient(std::string endpoint, int timeout_ms, int cooldown_ms)
        : endpoint_(std::move(endpoint)),
          // A non-positive timeout would mean ZeroMQ's "wait forever" (-1), the very bug this class removes.
          timeout_ms_(timeout_ms > 0 ? timeout_ms : kDefaultTimeoutMs),
          cooldown_(std::chrono::milliseconds(std::max(0, cooldown_ms))),
          retry_after_(Clock::now()) {
        reconnect();
    }

    BrainReply check(const std::string& header, const unsigned char* payload, std::size_t payload_len) {
        if (Clock::now() < retry_after_) return {BrainVerdict::Unavailable, true};
        if (!sock_) reconnect();
        if (!sock_) return fail("cannot create socket");

        try {
            zmq::message_t header_msg(header.data(), header.size());
            if (!sock_->send(header_msg, zmq::send_flags::sndmore)) return fail("send timed out (no brain?)");

            zmq::message_t payload_msg(payload, payload_len);
            if (!sock_->send(payload_msg, zmq::send_flags::none)) return fail("send timed out");

            zmq::message_t reply;
            if (!sock_->recv(reply, zmq::recv_flags::none)) return fail("no reply (brain hung?)");

            const std::string result(static_cast<const char*>(reply.data()), reply.size());
            return {result == "ALLOW" ? BrainVerdict::Allow : BrainVerdict::Block, false};
        } catch (const std::exception& e) {  // zmq::error_t, std::bad_alloc...: never unwind into the C callback
            return fail(e.what());
        }
    }

    const std::string& last_error() const { return last_error_; }

private:
    BrainReply fail(const char* why) {
        last_error_ = why;
        reconnect();  // a REQ socket that lost its reply can never send again: start over
        retry_after_ = Clock::now() + cooldown_;
        return {BrainVerdict::Unavailable, false};
    }

    void reconnect() {
        try {
            sock_.reset();  // closes the old socket (linger 0: pending messages are dropped)
            auto sock = std::make_unique<zmq::socket_t>(ctx_, zmq::socket_type::req);
            sock->set(zmq::sockopt::linger, 0);
            sock->set(zmq::sockopt::immediate, 1);  // do not queue requests for a peer that is not connected
            sock->set(zmq::sockopt::rcvtimeo, timeout_ms_);
            sock->set(zmq::sockopt::sndtimeo, std::min(timeout_ms_, kSendTimeoutMs));
            sock->connect(endpoint_);
            sock_ = std::move(sock);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[CPP] brain socket setup failed: %s\n", e.what());
            sock_.reset();
        }
    }

    static constexpr int kSendTimeoutMs = 250;
    static constexpr int kDefaultTimeoutMs = 1500;

    std::string endpoint_;
    int timeout_ms_;
    std::chrono::milliseconds cooldown_;
    Clock::time_point retry_after_;
    std::string last_error_;
    zmq::context_t ctx_{1};
    std::unique_ptr<zmq::socket_t> sock_;
};
