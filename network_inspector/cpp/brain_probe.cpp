// Test driver for BrainClient (see tests/test_firewall_engine_brain.py). Not part of the engine.
//
//   brain_probe <endpoint> <timeout_ms> <cooldown_ms> <open|closed>
//
// Reads commands on stdin, one per line:
//   ask     -> prints "<ALLOW|BLOCK|UNAVAILABLE> <skipped 0|1> <elapsed_ms>" (fixed 4-byte payload, port 53)
//   askhex <dport> <hex>  -> same, but sends the given packet bytes (hex) as the payload to <dport>
//   policy  -> prints "open" or "closed" (how the engine would treat UNAVAILABLE)
//   quit
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "brain_client.hpp"

static std::vector<unsigned char> from_hex(const std::string& hex) {
    std::vector<unsigned char> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

static void report(const BrainReply& r, long long ms) {
    const char* name = r.verdict == BrainVerdict::Allow ? "ALLOW"
                     : r.verdict == BrainVerdict::Block ? "BLOCK" : "UNAVAILABLE";
    std::printf("%s %d %lld\n", name, r.skipped ? 1 : 0, ms);
}

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
            report(r, static_cast<long long>(ms));
        } else if (line.rfind("askhex ", 0) == 0) {
            std::istringstream in(line.substr(7));
            std::string dport, hex;
            in >> dport >> hex;
            const std::vector<unsigned char> bytes = from_hex(hex);
            const std::string header = "check 10.0.0.2 8.8.8.8 40000 " + dport + " " + std::to_string(bytes.size());
            const auto t0 = std::chrono::steady_clock::now();
            const BrainReply r = client.check(header, bytes.data(), bytes.size());
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t0).count();
            report(r, static_cast<long long>(ms));
        }
        std::fflush(stdout);
    }
    return 0;
}
