#!/bin/bash
readonly SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH
set -Eeuo pipefail

readonly BASE_TABLE="pgw_base"
readonly PERSISTED_RULESET="/etc/nftables.d/pgw-base.nft"
readonly NFTABLES_CONFIG="/etc/nftables.conf"

agent_binary="/usr/local/bin/pgw-agent"
lan_interface="${PGW_LAN_IFACE:-ens19}"
wan_interface="${PGW_WAN_IFACE:-eth0}"
management_ports="${PGW_MANAGEMENT_TCP_PORTS:-8080,8081}"
candidate=""
replacement=""
persisted_stage=""
config_stage=""
persisted_backup=""
config_backup=""
validation_wrapper=""
live_backup=""
live_restore_transaction=""
live_verify=""
live_had_base=0
live_changed=0
boot_changed=0
check_only=0
service_prior_state=""
service_state_changed=0
service_persistent_before=""
service_runtime_before=""
service_persistent_after=""
service_runtime_after=""
saved_forwarding=""
forwarding_forced=0

force_forwarding_off() {
    sysctl -q -w net.ipv4.ip_forward=0 >/dev/null || return 1
    [[ "$(sysctl -n net.ipv4.ip_forward)" == 0 ]] || return 1
    forwarding_forced=1
}

restore_forwarding_final() {
    PGW_LAN_IFACE="${lan_interface}" PGW_WAN_IFACE="${wan_interface}" \
        PGW_MANAGEMENT_TCP_PORTS="${management_ports}" "${agent_binary}" verify-base >/dev/null || return 1
    sysctl -q -w "net.ipv4.ip_forward=${saved_forwarding}" >/dev/null || {
        force_forwarding_off || true
        return 1
    }
    [[ "$(sysctl -n net.ipv4.ip_forward)" == "${saved_forwarding}" ]] || {
        force_forwarding_off || true
        return 1
    }
    forwarding_forced=0
}

cleanup() {
    local rc=$?
    trap - EXIT
    set +e
    if [[ "${rc}" -ne 0 && "${forwarding_forced}" -eq 1 ]]; then
        if ! force_forwarding_off; then
            printf 'CRITICAL: failed to preserve fail-close IPv4 forwarding state\n' >&2
        fi
    fi
    if [[ "${rc}" -ne 0 && "${boot_changed}" -eq 1 ]]; then
        if ! restore_boot_files; then
            printf 'CRITICAL: failed to restore prior nftables boot files after installer error\n' >&2
        fi
    fi
    if [[ "${rc}" -ne 0 && "${service_state_changed}" -eq 1 ]]; then
        if ! restore_service_state; then
            printf 'CRITICAL: failed to restore prior nftables.service enablement state\n' >&2
        fi
    fi
    if [[ "${rc}" -ne 0 && "${live_changed}" -eq 1 ]]; then
        if ! restore_live_base; then
            printf 'CRITICAL: failed to restore prior live pgw_base after installer error\n' >&2
        fi
    fi
    [[ -z "${candidate}" ]] || rm -f -- "${candidate}"
    [[ -z "${replacement}" ]] || rm -f -- "${replacement}"
    [[ -z "${persisted_stage}" ]] || rm -f -- "${persisted_stage}"
    [[ -z "${config_stage}" ]] || rm -f -- "${config_stage}"
    [[ -z "${persisted_backup}" ]] || rm -f -- "${persisted_backup}"
    [[ -z "${config_backup}" ]] || rm -f -- "${config_backup}"
    [[ -z "${validation_wrapper}" ]] || rm -f -- "${validation_wrapper}"
    [[ -z "${live_backup}" ]] || rm -f -- "${live_backup}"
    [[ -z "${live_restore_transaction}" ]] || rm -f -- "${live_restore_transaction}"
    [[ -z "${live_verify}" ]] || rm -f -- "${live_verify}"
    [[ -z "${service_persistent_before}" ]] || rm -f -- "${service_persistent_before}"
    [[ -z "${service_runtime_before}" ]] || rm -f -- "${service_runtime_before}"
    [[ -z "${service_persistent_after}" ]] || rm -f -- "${service_persistent_after}"
    [[ -z "${service_runtime_after}" ]] || rm -f -- "${service_runtime_after}"
    exit "${rc}"
}
trap cleanup EXIT

restore_boot_files() {
    local failed=0
    if [[ -n "${persisted_backup}" ]]; then
        mv -f -- "${persisted_backup}" "${PERSISTED_RULESET}" || failed=1
        persisted_backup=""
    else
        rm -f -- "${PERSISTED_RULESET}" || failed=1
    fi
    if [[ -n "${config_backup}" ]]; then
        mv -f -- "${config_backup}" "${NFTABLES_CONFIG}" || failed=1
        config_backup=""
    else
        rm -f -- "${NFTABLES_CONFIG}" || failed=1
    fi
    boot_changed=0
    return "${failed}"
}

restore_live_base() {
    if [[ "${live_had_base}" -eq 1 ]]; then
        live_restore_transaction="$(mktemp)"
        printf 'delete table inet %s\n' "${BASE_TABLE}" >"${live_restore_transaction}"
        while IFS= read -r rule_line; do
            printf '%s\n' "${rule_line}" >>"${live_restore_transaction}"
        done <"${live_backup}"
        nft -c -f "${live_restore_transaction}" || return 1
        nft -f "${live_restore_transaction}" || return 1
        live_verify="$(mktemp)"
        nft -s list table inet "${BASE_TABLE}" >"${live_verify}" || return 1
        cmp -s "${live_backup}" "${live_verify}" || return 1
    else
        nft delete table inet "${BASE_TABLE}" >/dev/null 2>&1 || return 1
        if nft list table inet "${BASE_TABLE}" >/dev/null 2>&1; then
            return 1
        fi
    fi
    live_changed=0
}

restore_service_state() {
    systemctl unmask nftables.service >/dev/null || return 1
    systemctl unmask --runtime nftables.service >/dev/null || return 1
    systemctl disable nftables.service >/dev/null || return 1
    systemctl disable --runtime nftables.service >/dev/null || return 1
    case "${service_prior_state}" in
        enabled)
            systemctl enable nftables.service >/dev/null || return 1
            ;;
        enabled-runtime)
            systemctl enable --runtime nftables.service >/dev/null || return 1
            ;;
        disabled)
            systemctl disable nftables.service >/dev/null || return 1
            ;;
        masked)
            systemctl mask nftables.service >/dev/null || return 1
            ;;
        masked-runtime)
            systemctl mask --runtime nftables.service >/dev/null || return 1
            ;;
        *)
            return 1
            ;;
    esac
    local restored_state
    restored_state="$(systemctl is-enabled nftables.service 2>/dev/null || true)"
    [[ "${restored_state}" == "${service_prior_state}" ]] || return 1
    service_persistent_after="$(mktemp)"
    service_runtime_after="$(mktemp)"
    capture_service_links /etc/systemd/system "${service_persistent_after}" || return 1
    capture_service_links /run/systemd/system "${service_runtime_after}" || return 1
    cmp -s "${service_persistent_before}" "${service_persistent_after}" || return 1
    cmp -s "${service_runtime_before}" "${service_runtime_after}" || return 1
    service_state_changed=0
}

capture_service_links() {
    local systemd_root="$1" output_file="$2"
    if [[ -d "${systemd_root}" ]]; then
        find "${systemd_root}" -type l -name nftables.service \
            -printf '%P\t%l\n' | sort >"${output_file}"
    else
        : >"${output_file}"
    fi
}

while (($# > 0)); do
    case "$1" in
        --agent)
            (($# >= 2)) || { printf '%s requires a value\n' "$1" >&2; exit 2; }
            agent_binary="$2"
            shift 2
            ;;
        --lan)
            (($# >= 2)) || { printf '%s requires a value\n' "$1" >&2; exit 2; }
            lan_interface="$2"
            shift 2
            ;;
        --wan)
            (($# >= 2)) || { printf '%s requires a value\n' "$1" >&2; exit 2; }
            wan_interface="$2"
            shift 2
            ;;
        --management-ports)
            (($# >= 2)) || { printf '%s requires a value\n' "$1" >&2; exit 2; }
            management_ports="$2"
            shift 2
            ;;
        --check)
            check_only=1
            shift
            ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            exit 2
            ;;
    esac
done

[[ "${EUID}" -eq 0 ]] || { printf 'pgw base firewall installation requires root\n' >&2; exit 1; }
for command_name in ip nft sysctl install grep mktemp systemctl cp mv cmp find sort; do
    command -v "${command_name}" >/dev/null 2>&1 || {
        printf 'missing required command: %s\n' "${command_name}" >&2
        exit 1
    }
done
[[ -x "${agent_binary}" ]] || { printf 'agent renderer is not executable: %s\n' "${agent_binary}" >&2; exit 1; }
[[ "${lan_interface}" != "${wan_interface}" ]] || { printf 'LAN and WAN interfaces must differ\n' >&2; exit 1; }
[[ ",${management_ports}," != *",9090,"* ]] || { printf 'management TCP port 9090 is loopback-only and must not be opened by the firewall\n' >&2; exit 2; }
ip link show dev "${lan_interface}" >/dev/null 2>&1 || { printf 'LAN interface does not exist: %s\n' "${lan_interface}" >&2; exit 1; }
ip link show dev "${wan_interface}" >/dev/null 2>&1 || { printf 'WAN interface does not exist: %s\n' "${wan_interface}" >&2; exit 1; }
service_prior_state="$(systemctl is-enabled nftables.service 2>/dev/null || true)"
case "${service_prior_state}" in
    enabled|enabled-runtime|disabled|masked|masked-runtime) ;;
    *) printf 'unsupported nftables.service enablement state: %s\n' "${service_prior_state:-unknown}" >&2; exit 1 ;;
esac
service_persistent_before="$(mktemp)"
service_runtime_before="$(mktemp)"
capture_service_links /etc/systemd/system "${service_persistent_before}"
capture_service_links /run/systemd/system "${service_runtime_before}"

# Progress marks bound every silent bare-command interval: an errexit death
# in this script must be attributable to one step from the caller's log.
printf '[pgw-install-base] preflight passed; rendering base ruleset\n'
candidate="$(mktemp)"
"${agent_binary}" render-base \
    --lan "${lan_interface}" \
    --wan "${wan_interface}" \
    --management-ports "${management_ports}" >"${candidate}"

apply_file="${candidate}"
if nft list table inet "${BASE_TABLE}" >/dev/null 2>&1; then
    live_had_base=1
    live_backup="$(mktemp)"
    nft -s list table inet "${BASE_TABLE}" >"${live_backup}"
    replacement="$(mktemp)"
    printf 'delete table inet %s\n' "${BASE_TABLE}" >"${replacement}"
    while IFS= read -r rule_line; do
        printf '%s\n' "${rule_line}" >>"${replacement}"
    done <"${candidate}"
    apply_file="${replacement}"
fi
nft -c -f "${apply_file}"
if [[ "${check_only}" -eq 1 ]]; then
    printf 'validated static PGW base firewall candidate: lan=%s wan=%s\n' \
        "${lan_interface}" "${wan_interface}"
    exit 0
fi
saved_forwarding="$(sysctl -n net.ipv4.ip_forward)"
[[ "${saved_forwarding}" == 0 || "${saved_forwarding}" == 1 ]] \
    || { printf 'invalid IPv4 forwarding state\n' >&2; exit 1; }
force_forwarding_off || { printf 'could not force IPv4 forwarding off before nft mutation\n' >&2; exit 1; }
printf '[pgw-install-base] candidate validated; applying live base table\n'
nft -f "${apply_file}"
live_changed=1

PGW_LAN_IFACE="${lan_interface}" PGW_WAN_IFACE="${wan_interface}" \
    PGW_MANAGEMENT_TCP_PORTS="${management_ports}" "${agent_binary}" verify-base >/dev/null

for object in \
    'chain forward_guard' \
    'chain input_guard' \
    'counter wan_lan_established_accept_total' \
    'counter ipv6_policy_drop_total' \
    'counter udp_policy_drop_total' \
    'counter lan_wan_direct_drop_total' \
    'counter dns_input_accept_total' \
    'counter management_input_accept_total' \
    'counter management_input_drop_total'; do
    read -r object_kind object_name <<<"${object}"
    nft list "${object_kind}" inet "${BASE_TABLE}" "${object_name}" >/dev/null
done

printf '[pgw-install-base] live base verified; persisting boot configuration\n'
install -d -m 0755 /etc/nftables.d
persisted_stage="$(mktemp /etc/nftables.d/.pgw-base.nft.XXXXXX)"
install -m 0644 "${candidate}" "${persisted_stage}"

config_stage="$(mktemp /etc/.nftables.conf.XXXXXX)"
if [[ -e "${NFTABLES_CONFIG}" ]]; then
    cp -a -- "${NFTABLES_CONFIG}" "${config_stage}"
else
    printf '#!/usr/sbin/nft -f\n' >"${config_stage}"
    chmod 0644 "${config_stage}"
fi
if ! grep -Eq '^[[:space:]]*include[[:space:]]+"/etc/nftables\.d/(pgw-base|\*)\.nft"' "${config_stage}"; then
    printf '\ninclude "%s"\n' "${PERSISTED_RULESET}" >>"${config_stage}"
fi

# Validate the current complete boot configuration before publishing, then
# publish each staged file with a same-filesystem atomic rename. If validation
# of the new complete boot configuration fails, restore both prior files.
validation_wrapper="$(mktemp /etc/.nftables.validate.XXXXXX)"
printf 'flush ruleset\ninclude "%s"\n' "${NFTABLES_CONFIG}" >"${validation_wrapper}"
if [[ -e "${NFTABLES_CONFIG}" ]]; then
    nft -c -f "${validation_wrapper}"
fi
if [[ -e "${PERSISTED_RULESET}" ]]; then
    persisted_backup="$(mktemp /etc/nftables.d/.pgw-base.backup.XXXXXX)"
    cp -a -- "${PERSISTED_RULESET}" "${persisted_backup}"
fi
if [[ -e "${NFTABLES_CONFIG}" ]]; then
    config_backup="$(mktemp /etc/.nftables.conf.backup.XXXXXX)"
    cp -a -- "${NFTABLES_CONFIG}" "${config_backup}"
fi

mv -f -- "${persisted_stage}" "${PERSISTED_RULESET}"
persisted_stage=""
boot_changed=1
if ! mv -f -- "${config_stage}" "${NFTABLES_CONFIG}"; then
    restore_boot_files || printf 'CRITICAL: boot file rollback failed\n' >&2
    printf 'could not publish nftables boot configuration; restored prior files\n' >&2
    exit 1
fi
config_stage=""
if ! nft -c -f "${validation_wrapper}"; then
    restore_boot_files || printf 'CRITICAL: boot file rollback failed\n' >&2
    printf 'new nftables boot configuration failed validation; restored prior files\n' >&2
    exit 1
fi
service_state_changed=1
if ! systemctl enable nftables.service >/dev/null || ! systemctl is-enabled --quiet nftables.service; then
    restore_boot_files || printf 'CRITICAL: boot file rollback failed\n' >&2
    printf 'nftables.service enable verification failed; restored prior boot files\n' >&2
    exit 1
fi
live_changed=0
boot_changed=0
service_state_changed=0

restore_forwarding_final || {
    force_forwarding_off || true
    printf 'could not safely restore prior IPv4 forwarding state\n' >&2
    exit 1
}

printf 'installed static PGW base firewall: lan=%s wan=%s\n' \
    "${lan_interface}" "${wan_interface}"
