#!/bin/bash
readonly SAFE_PATH="/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH
set -Eeuo pipefail

[[ "${PGW_LAN_IFACE:-}" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || { printf 'invalid PGW_LAN_IFACE\n' >&2; exit 1; }
[[ "${PGW_UI_ADDR:-}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:8081$ ]] || { printf 'UI must bind numeric LAN IPv4:8081\n' >&2; exit 1; }
configured="${PGW_UI_ADDR%:8081}"
mapfile -t addresses < <(ip -4 -o addr show dev "${PGW_LAN_IFACE}" scope global | awk '{sub(/\/.*/,"",$4); print $4}')
[[ "${#addresses[@]}" == 1 && "${addresses[0]}" == "${configured}" ]] \
    || { printf 'UI bind does not equal the sole LAN IPv4\n' >&2; exit 1; }
