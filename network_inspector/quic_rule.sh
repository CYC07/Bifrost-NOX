#!/bin/bash
# Sourced by start_network.sh, stop_all.sh and vm-lab/vm_lab.sh (and testable on its own).
#
# block_quic <client_iface>    refuse UDP 443 arriving from the client side, so QUIC (HTTP/3) cannot bypass inspection
# unblock_quic <client_iface>  remove that rule (every copy)
#
# Why: the firewall redirects TCP 80/443 to its inspecting proxy. QUIC rides on UDP 443, which that redirect never sees,
# so a browser that has learned a site supports HTTP/3 (Google advertises it via Alt-Svc) talks to it directly and
# nothing on that connection is inspected: images, uploads and pages all pass unchecked. Refusing UDP 443 with an ICMP
# port-unreachable (not a silent drop) makes the browser fall back to TCP immediately, where the firewall can see it.
#
# BLOCK_QUIC=0 turns the rule off (e.g. to compare behaviour). Other UDP (DNS, NTP, calls on other ports) is untouched.

_quic_rule() {
    printf '%s\n' -i "$1" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
}

block_quic() {
    if [ "${BLOCK_QUIC:-1}" = "0" ]; then
        echo "  QUIC blocking disabled (BLOCK_QUIC=0): HTTP/3 traffic will bypass inspection"
        return 0
    fi
    local iface="$1"
    local -a rule
    mapfile -t rule < <(_quic_rule "$iface")
    iptables -C FORWARD "${rule[@]}" 2>/dev/null || iptables -I FORWARD 1 "${rule[@]}"
}

unblock_quic() {
    local iface="$1"
    local -a rule
    mapfile -t rule < <(_quic_rule "$iface")
    while iptables -C FORWARD "${rule[@]}" 2>/dev/null; do
        iptables -D FORWARD "${rule[@]}" 2>/dev/null || break
    done
    return 0
}
