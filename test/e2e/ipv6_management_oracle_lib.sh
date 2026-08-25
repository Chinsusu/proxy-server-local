#!/usr/bin/env bash

# These helpers deliberately inspect kernel/process state instead of opening an
# IPv6 connection to a management port that the firewall is expected to drop.

pgw_ipv6_listener_is_live() {
    local namespace="$1" pid="$2" address="$3" port="$4" interface_name="$5"
    local sockets

    kill -0 "${pid}" 2>/dev/null || return 1
    ip -n "${namespace}" -6 -o address show dev "${interface_name}" | \
        grep -F " ${address}/" | grep -Evq ' tentative| dadfailed' || return 1
    sockets="$(ip netns exec "${namespace}" ss -Hlnpt6 "sport = :${port}")" || return 1
    grep -Fq "${address}" <<<"${sockets}" || return 1
    grep -Fq ":${port}" <<<"${sockets}" || return 1
    grep -Fq "pid=${pid}," <<<"${sockets}" || return 1
}

pgw_nft_counter_packets() {
    local namespace="$1" table_name="$2" counter_name="$3"
    local output packets

    output="$(ip netns exec "${namespace}" nft list counter inet \
        "${table_name}" "${counter_name}" 2>&1)" || return 1
    packets="$(awk '{for (i=1; i<=NF; i++) if ($i=="packets") {print $(i+1); exit}}' \
        <<<"${output}")"
    [[ "${packets}" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "${packets}"
}

pgw_send_one_ipv6_tcp_syn() {
    local namespace="$1" source_address="$2" destination_address="$3" destination_port="$4"

    ip netns exec "${namespace}" python3 - "${source_address}" \
        "${destination_address}" "${destination_port}" <<'PY'
import socket
import struct
import sys

source, destination, port_text = sys.argv[1:]
port = int(port_text)
if not 1 <= port <= 65535:
    raise SystemExit("invalid destination port")

# One raw TCP SYN has no kernel TCP retransmission state.  IPV6_CHECKSUM asks
# Linux to fill the checksum field at byte offset 16 of the TCP header.
header = struct.pack("!HHIIBBHHH", 49151, port, 1, 0, 0x50, 0x02, 64240, 0, 0)
sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
try:
    sock.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_CHECKSUM", 7), 16)
    sock.bind((source, 0))
    sent = sock.sendto(header, (destination, 0))
    if sent != len(header):
        raise SystemExit("short raw IPv6 TCP send")
finally:
    sock.close()
PY
}

pgw_assert_one_ipv6_management_drop() {
    local gateway_namespace="$1" source_namespace="$2" source_address="$3"
    local destination_address="$4" destination_port="$5" table_name="$6" counter_name="$7"
    local before after expected attempt

    # Let the deliberately failed curl socket close before taking the exact
    # one-packet baseline; otherwise an already-scheduled TCP retry could race
    # the raw SYN oracle.
    sleep 0.1
    before="$(pgw_nft_counter_packets "${gateway_namespace}" "${table_name}" "${counter_name}")" || return 1
    pgw_send_one_ipv6_tcp_syn "${source_namespace}" "${source_address}" \
        "${destination_address}" "${destination_port}" || return 1
    after="${before}"
    for attempt in {1..20}; do
        after="$(pgw_nft_counter_packets "${gateway_namespace}" "${table_name}" "${counter_name}")" || return 1
        [[ "${after}" != "${before}" ]] && break
        sleep 0.05
    done
    expected=$((before + 1))
    [[ "${after}" -eq "${expected}" ]] || {
        printf 'IPv6 management counter delta was %s, expected exactly 1 (before=%s after=%s)\n' \
            "$((after - before))" "${before}" "${after}" >&2
        return 1
    }
}
