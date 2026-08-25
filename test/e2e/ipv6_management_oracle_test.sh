#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/e2e/ipv6_management_oracle_lib.sh
source "${SCRIPT_DIR}/ipv6_management_oracle_lib.sh"

[[ "$(uname -s)" == Linux ]] || { printf 'IPv6 management oracle: SKIP non-Linux\n'; exit 0; }
((EUID == 0)) || { printf 'IPv6 management oracle: SKIP requires root\n'; exit 0; }
for command_name in ip nft ss python3 curl sha256sum awk; do
    command -v "${command_name}" >/dev/null || { printf 'missing %s\n' "${command_name}" >&2; exit 1; }
done

token="${BASHPID}"
client_ns="pgw-v6-oracle-c-${token}"
gateway_ns="pgw-v6-oracle-g-${token}"
client_veth="oc${token: -6}"
gateway_veth="og${token: -6}"
tmp_dir="$(mktemp -d)"
server_pid=""

cleanup() {
    set +e
    [[ -z "${server_pid}" ]] || kill "${server_pid}" 2>/dev/null
    ip netns delete "${client_ns}" 2>/dev/null
    ip netns delete "${gateway_ns}" 2>/dev/null
    rm -rf -- "${tmp_dir}"
}
trap cleanup EXIT

ip netns add "${client_ns}"
ip netns add "${gateway_ns}"
ip link add "${client_veth}" type veth peer name "${gateway_veth}"
ip link set "${client_veth}" netns "${client_ns}"
ip link set "${gateway_veth}" netns "${gateway_ns}"
ip -n "${client_ns}" link set lo up
ip -n "${gateway_ns}" link set lo up
ip -n "${client_ns}" link set "${client_veth}" name lan0
ip -n "${gateway_ns}" link set "${gateway_veth}" name lan0
ip -n "${client_ns}" address add fd66:1::2/64 dev lan0 nodad
ip -n "${gateway_ns}" address add fd66:1::1/64 dev lan0 nodad
ip -n "${client_ns}" link set lan0 up
ip -n "${gateway_ns}" link set lan0 up

ip netns exec "${gateway_ns}" python3 -m http.server 18081 --bind fd66:1::1 \
    --directory "${tmp_dir}" >"${tmp_dir}/listener.log" 2>&1 &
server_pid="$!"
for _ in {1..50}; do
    pgw_ipv6_listener_is_live "${gateway_ns}" "${server_pid}" fd66:1::1 18081 lan0 && break
    sleep 0.1
done
pgw_ipv6_listener_is_live "${gateway_ns}" "${server_pid}" fd66:1::1 18081 lan0
ip netns exec "${client_ns}" curl --noproxy '*' --globoff --ipv6 --fail --silent \
    --connect-timeout 1 --max-time 2 'http://[fd66:1::1]:18081/' >/dev/null
listener_hash="$(sha256sum "${tmp_dir}/listener.log" | awk '{print $1}')"

ip netns exec "${gateway_ns}" nft -f - <<'NFT'
table inet pgw_oracle {
    counter management_input_drop_total { }
    chain input_guard {
        type filter hook input priority -10; policy accept;
        meta nfproto ipv6 tcp dport 18081 counter name management_input_drop_total drop
    }
}
NFT
if ip netns exec "${client_ns}" curl --noproxy '*' --globoff --ipv6 --fail --silent \
    --connect-timeout 1 --max-time 1 'http://[fd66:1::1]:18081/' >/dev/null; then
    printf 'IPv6 management connection unexpectedly passed\n' >&2
    exit 1
fi
pgw_ipv6_listener_is_live "${gateway_ns}" "${server_pid}" fd66:1::1 18081 lan0
pgw_assert_one_ipv6_management_drop "${gateway_ns}" "${client_ns}" fd66:1::2 \
    fd66:1::1 18081 pgw_oracle management_input_drop_total
[[ "$(sha256sum "${tmp_dir}/listener.log" | awk '{print $1}')" == "${listener_hash}" ]]
printf 'IPv6 management independent-liveness oracle: PASS\n'
