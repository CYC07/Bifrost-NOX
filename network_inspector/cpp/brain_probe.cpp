// Test driver for BrainClient (see tests/test_firewall_engine_brain.py). Not part of the engine.
//
//   brain_probe <endpoint> <timeout_ms> <cooldown_ms> <open|closed>
//
// Reads commands on stdin, one per line:
//   ask     -> prints "<ALLOW|BLOCK|UNAVAILABLE> <skipped 0|1> <elapsed_ms>"
//   policy  -> prints "open" or "closed" (how the engine would treat UNAVAILABLE)
//   quit
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include "brain_client.hpp"

int main(int argc, char** argv) {
    if (argc != 5) {
        std::fprintf(stderr, "usage: %s <endpoint> <timeout_ms> <cooldown_ms> <open|closed>\n", argv[0]);
        return 2;
    }
    BrainClient client(argv[1], std::atoi(argv[2]), std::atoi(argv[3]));
    const bool fail_open = brain_fail_open(argv[4]);

    const unsigned char payload[4] = {1, 2, 3, 4};
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "quit") break;
        if (line == "policy") {
            std::printf("%s\n", fail_open ? "open" : "closed");
        } else if (line == "ask") {
            const auto t0 = std::chrono::steady_clock::now();
            const BrainReply r = client.check("check 1.1.1.1 8.8.8.8 1234 53 4", payload, sizeof(payload));
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t0).count();
            const char* name = r.verdict == BrainVerdict::Allow ? "ALLOW"
                             : r.verdict == BrainVerdict::Block ? "BLOCK" : "UNAVAILABLE";
            std::printf("%s %d %lld\n", name, r.skipped ? 1 : 0, static_cast<long long>(ms));
        }
        std::fflush(stdout);
    }
    return 0;
}
