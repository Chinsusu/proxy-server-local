#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=test/e2e/ipv6_management_oracle_lib.sh
source "${SCRIPT_DIR}/ipv6_management_oracle_lib.sh"
EVIDENCE_FORMAT="$(<"${SCRIPT_DIR}/EVIDENCE_FORMAT")"
readonly EVIDENCE_FORMAT
readonly RUN_ID="${BASHPID}"
readonly RESOURCE_TOKEN="${PGW_E2E_RUN_TOKEN:-${RUN_ID}}"
readonly NAMESPACE_PREFIX="${PGW_E2E_PREFIX:-pgw-e2e-${RUN_ID}}"
readonly CLIENT_NS="${NAMESPACE_PREFIX}-product-client"
readonly GATEWAY_NS="${NAMESPACE_PREFIX}-product-gateway"
readonly WAN_NS="${NAMESPACE_PREFIX}-product-wan"
readonly CLIENT_VETH="cl${RESOURCE_TOKEN}"
readonly GATEWAY_LAN_VETH="gl${RESOURCE_TOKEN}"
readonly GATEWAY_WAN_VETH="gw${RESOURCE_TOKEN}"
readonly WAN_VETH="we${RESOURCE_TOKEN}"
readonly READINESS_TIMEOUT_SECONDS=30

server_pids=()
capture_pids=()
created_namespaces=()
created_host_interfaces=()
artifact_dir=""
probe_log=""
resource_manifest=""
tmp_dir=""
spawn_registration_guard=0
deferred_signal_status=0
spawned_capture_pid=""
spawned_server_pid=""
readiness_deadline=0
startup_diagnostic_file=""

record() {
    local message="$*"

    printf '%s\n' "${message}"
    if [[ -n "${probe_log}" ]]; then
        printf '%s\n' "${message}" >>"${probe_log}"
    fi
}

fail() {
    local message="FAIL: $*"

    printf '%s\n' "${message}" >&2
    if [[ -n "${probe_log}" ]]; then
        printf '%s\n' "${message}" >>"${probe_log}"
    fi
    exit 1
}

[[ "${EVIDENCE_FORMAT}" =~ ^pgw-wave[0-9]+-e2e-v[0-9]+$ ]] || \
    fail "invalid canonical E2E evidence format"

handle_signal() {
    local signal_status="$1"

    if [[ "${spawn_registration_guard}" -eq 1 ]]; then
        if [[ "${deferred_signal_status}" -eq 0 ]]; then
            deferred_signal_status="${signal_status}"
        fi
        return 0
    fi
    exit "${signal_status}"
}

finish_spawn_registration() {
    local signal_status

    spawn_registration_guard=0
    if [[ "${deferred_signal_status}" -ne 0 ]]; then
        signal_status="${deferred_signal_status}"
        deferred_signal_status=0
        exit "${signal_status}"
    fi
}

capture_product_state() {
    local phase="$1"
    local counters_error_tmp counters_tmp rules_json_tmp rules_text_tmp

    [[ -n "${artifact_dir}" ]] || return 0
    rules_json_tmp="$(mktemp "${artifact_dir}/.product-applied-ruleset.json.XXXXXX")"
    rules_text_tmp="$(mktemp "${artifact_dir}/.product-applied-ruleset.txt.XXXXXX")"
    counters_tmp="$(mktemp "${artifact_dir}/.product-counters.json.XXXXXX")"
    counters_error_tmp="$(mktemp "${artifact_dir}/.product-counters.stderr.XXXXXX")"

    if ! ip netns exec "${GATEWAY_NS}" nft -j list ruleset >"${rules_json_tmp}"; then
        rm -f -- "${rules_json_tmp}" "${rules_text_tmp}" "${counters_tmp}"
        mv -- "${counters_error_tmp}" "${artifact_dir}/product-counters.capture-error.txt"
        return 1
    fi
    if ! ip netns exec "${GATEWAY_NS}" nft -a list ruleset >"${rules_text_tmp}"; then
        rm -f -- "${rules_json_tmp}" "${rules_text_tmp}" "${counters_tmp}"
        mv -- "${counters_error_tmp}" "${artifact_dir}/product-counters.capture-error.txt"
        return 1
    fi
    if ! ip netns exec "${GATEWAY_NS}" nft -j list counters \
        >"${counters_tmp}" 2>"${counters_error_tmp}"; then
        rm -f -- "${rules_json_tmp}" "${rules_text_tmp}" "${counters_tmp}"
        mv -- "${counters_error_tmp}" "${artifact_dir}/product-counters.capture-error.txt"
        return 1
    fi
    if ! python3 -m json.tool "${rules_json_tmp}" >/dev/null || \
        ! python3 -m json.tool "${counters_tmp}" >/dev/null || \
        ! grep -Fq '"pgw_base"' "${rules_json_tmp}" || \
        ! grep -Fq '"pgw_dynamic"' "${rules_json_tmp}"; then
        rm -f -- "${rules_json_tmp}" "${rules_text_tmp}" "${counters_tmp}" "${counters_error_tmp}"
        return 1
    fi

    mv -- "${rules_json_tmp}" "${artifact_dir}/product-applied-ruleset.json"
    mv -- "${rules_text_tmp}" "${artifact_dir}/product-applied-ruleset.txt"
    mv -- "${counters_tmp}" "${artifact_dir}/product-counters.json"
    rm -f -- "${counters_error_tmp}" "${artifact_dir}/product-counters.capture-error.txt"
    printf 'state_capture=%s\n' "${phase}" >>"${probe_log}"
}

publish_artifact_permissions() {
    [[ -n "${artifact_dir}" && -d "${artifact_dir}" ]] || return 0

    chmod 0755 -- "${artifact_dir}" || return 1
    find "${artifact_dir}" -xdev -type d -exec chmod 0755 -- {} + || return 1
    find "${artifact_dir}" -xdev -type f -exec chmod 0644 -- {} + || return 1
}

cleanup() {
    local original_rc=$?
    local cleanup_rc=0
    local capture_status final_rc interface_name namespace pid
    local -a cleanup_capture_pids=("${capture_pids[@]}")

    trap - EXIT INT TERM
    set +e

    for pid in "${cleanup_capture_pids[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
            kill -KILL "${pid}" 2>/dev/null
        fi
        wait "${pid}" 2>/dev/null
        capture_status="$?"
        if [[ "${capture_status}" -ne 0 && \
            "${capture_status}" -ne 137 && "${capture_status}" -ne 143 ]]; then
            printf 'capture cleanup wait failed pid=%s status=%s\n' \
                "${pid}" "${capture_status}" >&2
            cleanup_rc=1
        fi
        untrack_capture_pid "${pid}"
    done
    for pid in "${cleanup_capture_pids[@]}"; do
        if kill -0 "${pid}" 2>/dev/null; then
            printf 'cleanup residue capture_pid=%s\n' "${pid}" >&2
            cleanup_rc=1
        fi
    done

    for pid in "${server_pids[@]}"; do
        # Background test servers are best-effort cleanup only.
        if ! kill "${pid}" 2>/dev/null; then
            :
        fi
        if ! wait "${pid}" 2>/dev/null; then
            :
        fi
    done

    for namespace in "${created_namespaces[@]}"; do
        case "${namespace}" in
            "${NAMESPACE_PREFIX}"-product-*)
                if namespace_exists "${namespace}" && \
                    ! ip netns delete "${namespace}" 2>/dev/null; then
                    cleanup_rc=1
                fi
                ;;
            *)
                printf 'refusing to delete unexpected namespace %s\n' "${namespace}" >&2
                ;;
        esac
    done

    for interface_name in "${created_host_interfaces[@]}"; do
        case "${interface_name}" in
            "${CLIENT_VETH}"|"${GATEWAY_LAN_VETH}"|"${GATEWAY_WAN_VETH}"|"${WAN_VETH}")
                # A veth may remain on the host after a partially completed move.
                if ip link show dev "${interface_name}" >/dev/null 2>&1 && \
                    ! ip link delete "${interface_name}" 2>/dev/null; then
                    cleanup_rc=1
                fi
                ;;
            *)
                printf 'refusing to delete unexpected interface %s\n' "${interface_name}" >&2
                ;;
        esac
    done

    for namespace in "${CLIENT_NS}" "${GATEWAY_NS}" "${WAN_NS}"; do
        if namespace_exists "${namespace}"; then
            printf 'cleanup residue namespace=%s\n' "${namespace}" >&2
            cleanup_rc=1
        fi
    done
    for interface_name in "${CLIENT_VETH}" "${GATEWAY_LAN_VETH}" "${GATEWAY_WAN_VETH}" "${WAN_VETH}"; do
        if ip link show dev "${interface_name}" >/dev/null 2>&1; then
            printf 'cleanup residue interface=%s\n' "${interface_name}" >&2
            cleanup_rc=1
        fi
    done

    if [[ -n "${tmp_dir}" && -d "${tmp_dir}" ]]; then
        if ! rm -r -- "${tmp_dir}"; then
            cleanup_rc=1
        fi
    fi
    if ! publish_artifact_permissions; then
        printf 'failed to publish runner-readable product artifacts\n' >&2
        cleanup_rc=1
    fi
    if [[ -n "${probe_log}" && -f "${probe_log}" ]]; then
        printf 'cleanup_rc=%d\n' "${cleanup_rc}" >>"${probe_log}"
    fi

    final_rc="${original_rc}"
    if [[ "${cleanup_rc}" -ne 0 && "${final_rc}" -eq 0 ]]; then
        final_rc=1
    fi
    exit "${final_rc}"
}

require_command() {
    local command_name="$1"
    command -v "${command_name}" >/dev/null 2>&1 || fail "missing required command: ${command_name}"
}

register_resource() {
    local resource_type="$1"
    local resource_name="$2"

    if [[ -n "${resource_manifest}" ]]; then
        printf '%s\t%s\n' "${resource_type}" "${resource_name}" >>"${resource_manifest}"
    fi
}

untrack_capture_pid() {
    local completed_pid="$1"
    local tracked_pid
    local -a remaining_pids=()

    for tracked_pid in "${capture_pids[@]}"; do
        if [[ "${tracked_pid}" != "${completed_pid}" ]]; then
            remaining_pids+=("${tracked_pid}")
        fi
    done
    capture_pids=("${remaining_pids[@]}")
}

namespace_exists() {
    local namespace="$1"
    ip netns list | awk '{print $1}' | grep -Fxq -- "${namespace}"
}

assert_resources_absent() {
    local interface_name namespace

    for namespace in "${CLIENT_NS}" "${GATEWAY_NS}" "${WAN_NS}"; do
        if namespace_exists "${namespace}"; then
            fail "refusing to reuse existing namespace ${namespace}"
        fi
    done
    for interface_name in "${CLIENT_VETH}" "${GATEWAY_LAN_VETH}" "${GATEWAY_WAN_VETH}" "${WAN_VETH}"; do
        if ip link show dev "${interface_name}" >/dev/null 2>&1; then
            fail "refusing to reuse existing interface ${interface_name}"
        fi
    done
}

capture_startup_diagnostics() {
    local reason="$1"
    local log_file log_line namespace pid_name pid_value

    startup_diagnostic_file="${artifact_dir}/startup-readiness-diagnostics.txt"
    {
        printf 'reason=%s\n' "${reason}"
        printf 'seconds=%s readiness_deadline=%s\n' "${SECONDS}" "${readiness_deadline}"
        for pid_name in gateway dns management management_ipv6 wan_direct wan_ipv4 wan_ipv6; do
            case "${pid_name}" in
                gateway) pid_value="${gateway_server_pid:-}" ;;
                dns) pid_value="${dns_server_pid:-}" ;;
                management) pid_value="${management_server_pid:-}" ;;
                management_ipv6) pid_value="${management_ipv6_server_pid:-}" ;;
                wan_direct) pid_value="${wan_direct_server_pid:-}" ;;
                wan_ipv4) pid_value="${wan_ipv4_server_pid:-}" ;;
                wan_ipv6) pid_value="${wan_ipv6_server_pid:-}" ;;
            esac
            if [[ -n "${pid_value}" ]] && kill -0 "${pid_value}" 2>/dev/null; then
                printf 'server_%s_pid=%s state=alive\n' "${pid_name}" "${pid_value}"
            else
                printf 'server_%s_pid=%s state=not-running\n' "${pid_name}" "${pid_value:-unset}"
            fi
        done
        for namespace in "${CLIENT_NS}" "${GATEWAY_NS}" "${WAN_NS}"; do
            printf '\n[%s addresses]\n' "${namespace}"
            ip -n "${namespace}" -details address show 2>&1 || true
            printf '[%s IPv4 routes]\n' "${namespace}"
            ip -n "${namespace}" -4 route show table all 2>&1 || true
            printf '[%s IPv6 routes]\n' "${namespace}"
            ip -n "${namespace}" -6 route show table all 2>&1 || true
            printf '[%s neighbors]\n' "${namespace}"
            ip -n "${namespace}" neighbor show 2>&1 || true
        done
        for log_file in \
            "${artifact_dir}/gateway-http.log" \
            "${artifact_dir}/gateway-dns-tcp.log" \
            "${artifact_dir}/gateway-management.log" \
            "${artifact_dir}/gateway-management-ipv6.log" \
            "${artifact_dir}/wan-direct-sentinel.log" \
            "${artifact_dir}/wan-http.log" \
            "${artifact_dir}/wan-http6.log"; do
            if [[ -f "${log_file}" ]]; then
                printf '\n[%s]\n' "${log_file}"
                while IFS= read -r log_line; do
                    printf '%s\n' "${log_line}"
                done <"${log_file}"
            fi
        done
    } >"${startup_diagnostic_file}"
}

fail_startup_readiness() {
    local reason="$1"

    capture_startup_diagnostics "${reason}"
    fail "${reason}; diagnostics: ${startup_diagnostic_file}"
}

wait_for_http_server() {
    local namespace="$1"
    local address="$2"
    local port="$3"
    local server_pid="$4"
    local server_log="$5"

    while ((SECONDS < readiness_deadline)); do
        if ! kill -0 "${server_pid}" 2>/dev/null; then
            fail_startup_readiness \
                "HTTP server ${address}:${port} exited in ${namespace}; log: ${server_log}"
        fi
        if ip netns exec "${namespace}" python3 -c \
            'import socket, sys; connection = socket.create_connection((sys.argv[1], int(sys.argv[2])), 0.2); connection.close()' \
            "${address}" "${port}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    fail_startup_readiness \
        "HTTP server ${address}:${port} did not listen before the readiness deadline in ${namespace}; log: ${server_log}"
}

wait_for_route() {
    local namespace="$1"
    local family="$2"
    local destination="$3"
    local source_address="$4"
    local expected_device="$5"
    local route_output=""

    while ((SECONDS < readiness_deadline)); do
        if route_output="$(ip -n "${namespace}" "-${family}" route get \
            "${destination}" from "${source_address}" 2>&1)" && \
            grep -Fq "dev ${expected_device}" <<<"${route_output}"; then
            return 0
        fi
        sleep 0.1
    done
    fail_startup_readiness \
        "IPv${family} route ${source_address} -> ${destination} via ${expected_device} was not ready in ${namespace}; last result: ${route_output}"
}

wait_for_ipv6_address() {
    local namespace="$1"
    local interface_name="$2"
    local address="$3"

    while ((SECONDS < readiness_deadline)); do
        if ip -n "${namespace}" -6 -o address show dev "${interface_name}" 2>/dev/null | \
            grep -F " ${address}/" | grep -Evq ' tentative| dadfailed'; then
            return 0
        fi
        sleep 0.1
    done
    fail_startup_readiness \
        "IPv6 address ${address} did not leave tentative/DAD state on ${namespace}:${interface_name}"
}

wait_for_http_control() {
    local label="$1"
    local namespace="$2"
    local family="$3"
    local source_address="$4"
    local url="$5"
    local error_log="${artifact_dir}/readiness-${label}.curl.log"
    local -a family_args=("--ipv${family}")

    while ((SECONDS < readiness_deadline)); do
        if ip netns exec "${namespace}" curl --noproxy '*' \
            "${family_args[@]}" --globoff --interface "${source_address}" \
            --fail --silent --show-error --connect-timeout 1 --max-time 2 \
            "${url}" >/dev/null 2>"${error_log}"; then
            rm -f -- "${error_log}"
            return 0
        fi
        sleep 0.1
    done
    fail_startup_readiness \
        "${label} HTTP control ${source_address} -> ${url} did not succeed before the readiness deadline; last curl error: ${error_log}"
}

assert_named_counter_positive() {
    local table_name="$1"
    local counter_name="$2"
    local counter_output=""

    if ! counter_output="$(ip netns exec "${GATEWAY_NS}" nft list counter inet \
        "${table_name}" "${counter_name}" 2>&1)"; then
        fail "named counter ${table_name}/${counter_name} is unavailable: ${counter_output}"
    fi
    if ! grep -Eq 'packets [1-9][0-9]*' <<<"${counter_output}"; then
        fail "named counter ${table_name}/${counter_name} did not observe a packet: ${counter_output}"
    fi
    record "PASS named counter ${table_name}/${counter_name} observed traffic"
}

named_counter_packets() {
    local table_name="$1"
    local counter_name="$2"

    pgw_nft_counter_packets "${GATEWAY_NS}" "${table_name}" "${counter_name}" || \
        fail "named counter ${table_name}/${counter_name} has invalid packet evidence"
}

assert_management_ipv6_listener_live() {
    local sockets

    if ! pgw_ipv6_listener_is_live "${GATEWAY_NS}" "${management_ipv6_server_pid}" \
        fd44:1::1 8081 lan0; then
        sockets="$(ip netns exec "${GATEWAY_NS}" ss -Hlnpt6 'sport = :8081' 2>&1 || true)"
        fail "IPv6 management listener lost independent PID/address/socket liveness: ${sockets}"
    fi
}

render_fixture_layer() {
    local layer="$1"

    if [[ -n "${PGW_E2E_RENDER_FIXTURE:-}" ]]; then
        "${PGW_E2E_RENDER_FIXTURE}" -layer "${layer}"
        return
    fi
    (cd -- "${REPO_ROOT}" && go run ./test/e2e/cmd/renderfixture -layer "${layer}")
}

start_http_server() {
    local namespace="$1"
    local bind_address="$2"
    local port="$3"
    local log_file="$4"

    spawn_registration_guard=1
    ip netns exec "${namespace}" python3 -m http.server "${port}" \
        --bind "${bind_address}" --directory "${tmp_dir}" >"${log_file}" 2>&1 &
    spawned_server_pid="$!"
    server_pids+=("${spawned_server_pid}")
    finish_spawn_registration
}

spawn_udp_capture() {
    local capture_log="$1"

    spawn_registration_guard=1
    ip netns exec "${WAN_NS}" tcpdump -n -i wan0 -c 1 'udp port 5300' \
        >"${capture_log}" 2>&1 &
    spawned_capture_pid="$!"
    capture_pids+=("${spawned_capture_pid}")
    finish_spawn_registration
}

wait_for_udp_capture_ready() {
    local capture_pid="$1"
    local capture_log="$2"
    local attempt

    for attempt in {1..40}; do
        if grep -Fq 'listening on wan0' "${capture_log}" && \
            kill -0 "${capture_pid}" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "${capture_pid}" 2>/dev/null; then
            printf 'capture exited before readiness\n' >>"${capture_log}"
            return 70
        fi
        sleep 0.05
    done

    printf 'capture readiness deadline expired\n' >>"${capture_log}"
    return 71
}

probe_udp_capture() {
    local source_namespace="$1"
    local source_address="$2"
    local capture_log="$3"
    local attempt capture_pid capture_status readiness_status send_status
    local timeout_killed=0

    spawn_udp_capture "${capture_log}"
    capture_pid="${spawned_capture_pid}"
    wait_for_udp_capture_ready "${capture_pid}" "${capture_log}"
    readiness_status="$?"
    if [[ "${readiness_status}" -ne 0 ]]; then
        if kill -0 "${capture_pid}" 2>/dev/null; then
            kill "${capture_pid}" 2>/dev/null || true
        fi
        wait "${capture_pid}" 2>/dev/null
        capture_status="$?"
        untrack_capture_pid "${capture_pid}"
        printf 'capture readiness failed status=%s; wait status=%s\n' \
            "${readiness_status}" "${capture_status}" >>"${capture_log}"
        return "${readiness_status}"
    fi

    if ip netns exec "${source_namespace}" python3 -c \
        'import socket, sys; sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind((sys.argv[1], 0)); sent = sock.sendto(b"pgw-e2e", ("10.45.0.2", 5300)); sock.close(); raise SystemExit(0 if sent == 7 else 1)' \
        "${source_address}"; then
        send_status=0
    else
        send_status="$?"
    fi
    if [[ "${send_status}" -ne 0 ]]; then
        printf 'UDP sender failed with status %s\n' "${send_status}" >>"${capture_log}"
        if kill -0 "${capture_pid}" 2>/dev/null; then
            kill "${capture_pid}" 2>/dev/null || true
        fi
        wait "${capture_pid}" 2>/dev/null
        capture_status="$?"
        untrack_capture_pid "${capture_pid}"
        printf 'capture wait after sender failure status=%s\n' \
            "${capture_status}" >>"${capture_log}"
        return 72
    fi

    # The capture deadline starts only after readiness and a successful send.
    for attempt in {1..40}; do
        if ! kill -0 "${capture_pid}" 2>/dev/null; then
            if wait "${capture_pid}"; then
                untrack_capture_pid "${capture_pid}"
                return 0
            else
                capture_status="$?"
            fi
            untrack_capture_pid "${capture_pid}"
            printf 'capture exited after send with status %s\n' \
                "${capture_status}" >>"${capture_log}"
            return 73
        fi
        sleep 0.05
    done

    if kill -0 "${capture_pid}" 2>/dev/null; then
        if kill -KILL "${capture_pid}" 2>/dev/null; then
            timeout_killed=1
        fi
    fi
    if wait "${capture_pid}" 2>/dev/null; then
        capture_status=0
    else
        capture_status="$?"
    fi
    untrack_capture_pid "${capture_pid}"
    if [[ "${capture_status}" -eq 0 ]]; then
        return 0
    fi
    if [[ "${timeout_killed}" -eq 1 && "${capture_status}" -eq 137 ]]; then
        printf 'capture deadline expired without a packet; harness killed pid %s\n' \
            "${capture_pid}" >>"${capture_log}"
        return 124
    fi
    printf 'capture exited at deadline with status %s\n' \
        "${capture_status}" >>"${capture_log}"
    return 73
}

publish_product_artifacts() {
    local rendered_sha256 rules_file="$1" base_rules_file="$2" dynamic_rules_file="$3"

    install -m 0644 "${rules_file}" "${artifact_dir}/product-rendered-ruleset.nft"
    install -m 0644 "${base_rules_file}" "${artifact_dir}/product-base-ruleset.nft"
    install -m 0644 "${dynamic_rules_file}" "${artifact_dir}/product-dynamic-ruleset.nft"
    (
        cd -- "${artifact_dir}"
        sha256sum product-rendered-ruleset.nft >product-rendered-ruleset.sha256
    )
    read -r rendered_sha256 _ <"${artifact_dir}/product-rendered-ruleset.sha256"

    {
        printf 'format=%s\n' "${EVIDENCE_FORMAT}"
        printf 'renderer=pkg/nft.RenderBase+RenderDynamic\n'
        printf 'counter_mode=required\n'
        printf 'rendered_sha256=%s\n' "${rendered_sha256}"
        printf 'run_token=%s\n' "${RESOURCE_TOKEN}"
        printf 'namespace_prefix=%s\n' "${NAMESPACE_PREFIX}"
        printf 'client_namespace=%s\n' "${CLIENT_NS}"
        printf 'gateway_namespace=%s\n' "${GATEWAY_NS}"
        printf 'wan_namespace=%s\n' "${WAN_NS}"
        printf 'client_veth=%s\n' "${CLIENT_VETH}"
        printf 'gateway_lan_veth=%s\n' "${GATEWAY_LAN_VETH}"
        printf 'gateway_wan_veth=%s\n' "${GATEWAY_WAN_VETH}"
        printf 'wan_veth=%s\n' "${WAN_VETH}"
        printf 'lan_interface=lan0\n'
        printf 'wan_interface=wan0\n'
        printf 'mapped_client_ipv4=10.44.0.2/32\n'
        printf 'unmapped_client_ipv4=10.44.0.3/32\n'
        printf 'require_base_kill_switch=1\n'
        printf 'rendered_ruleset=product-rendered-ruleset.nft\n'
        printf 'base_ruleset=product-base-ruleset.nft\n'
        printf 'dynamic_ruleset=product-dynamic-ruleset.nft\n'
        printf 'applied_ruleset_json=product-applied-ruleset.json\n'
        printf 'applied_ruleset_text=product-applied-ruleset.txt\n'
        printf 'counters=product-counters.json\n'
        printf 'probe_log=product-probes.log\n'
    } >"${artifact_dir}/product-manifest.txt"
}

[[ "$(uname -s)" == "Linux" ]] || fail "network namespace lab requires Linux"
[[ "${EUID}" -eq 0 ]] || fail "network namespace lab requires root"
[[ "${NAMESPACE_PREFIX}" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "invalid PGW_E2E_PREFIX"
((${#NAMESPACE_PREFIX} <= 180)) || fail "PGW_E2E_PREFIX is too long"
[[ "${RESOURCE_TOKEN}" =~ ^[A-Za-z0-9]+$ ]] || fail "invalid PGW_E2E_RUN_TOKEN"
((${#RESOURCE_TOKEN} <= 12)) || fail "PGW_E2E_RUN_TOKEN exceeds veth name budget"
[[ "${PGW_E2E_REQUIRE_BASE_KILL_SWITCH:-1}" == "1" ]] || \
    fail "Wave 1 E2E requires PGW_E2E_REQUIRE_BASE_KILL_SWITCH=1"

for command_name in ip nft ss python3 curl tcpdump sysctl install sha256sum awk grep find chmod mktemp mv rm cmp; do
    require_command "${command_name}"
done
if [[ -n "${PGW_E2E_RENDER_FIXTURE:-}" ]]; then
    [[ -x "${PGW_E2E_RENDER_FIXTURE}" ]] || \
        fail "PGW_E2E_RENDER_FIXTURE is not executable: ${PGW_E2E_RENDER_FIXTURE}"
else
    require_command go
fi

for interface_name in "${CLIENT_VETH}" "${GATEWAY_LAN_VETH}" "${GATEWAY_WAN_VETH}" "${WAN_VETH}"; do
    ((${#interface_name} <= 15)) || fail "generated interface name exceeds Linux limit: ${interface_name}"
done

tmp_dir="$(mktemp -d)"
artifact_dir="${PGW_E2E_ARTIFACT_DIR:-${PGW_EVIDENCE_DIR:-${tmp_dir}/artifacts}}"
resource_manifest="${PGW_E2E_RESOURCE_MANIFEST:-}"
if [[ -n "${resource_manifest}" && "${NAMESPACE_PREFIX}" != *"${RESOURCE_TOKEN}"* ]]; then
    fail "PGW_E2E_PREFIX must contain PGW_E2E_RUN_TOKEN when a resource manifest is used"
fi
install -d -m 0755 "${artifact_dir}"
probe_log="${artifact_dir}/product-probes.log"
: >"${probe_log}"
trap cleanup EXIT
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

assert_resources_absent
register_resource netns "${CLIENT_NS}"
register_resource netns "${GATEWAY_NS}"
register_resource netns "${WAN_NS}"
register_resource link "${CLIENT_VETH}"
register_resource link "${GATEWAY_LAN_VETH}"
register_resource link "${GATEWAY_WAN_VETH}"
register_resource link "${WAN_VETH}"

ip netns add "${CLIENT_NS}"
created_namespaces+=("${CLIENT_NS}")
ip netns add "${GATEWAY_NS}"
created_namespaces+=("${GATEWAY_NS}")
ip netns add "${WAN_NS}"
created_namespaces+=("${WAN_NS}")

ip link add "${CLIENT_VETH}" type veth peer name "${GATEWAY_LAN_VETH}"
created_host_interfaces+=("${CLIENT_VETH}" "${GATEWAY_LAN_VETH}")
ip link set "${CLIENT_VETH}" netns "${CLIENT_NS}"
ip link set "${GATEWAY_LAN_VETH}" netns "${GATEWAY_NS}"

ip link add "${GATEWAY_WAN_VETH}" type veth peer name "${WAN_VETH}"
created_host_interfaces+=("${GATEWAY_WAN_VETH}" "${WAN_VETH}")
ip link set "${GATEWAY_WAN_VETH}" netns "${GATEWAY_NS}"
ip link set "${WAN_VETH}" netns "${WAN_NS}"

ip -n "${CLIENT_NS}" link set "${CLIENT_VETH}" name lan0
ip -n "${GATEWAY_NS}" link set "${GATEWAY_LAN_VETH}" name lan0
ip -n "${GATEWAY_NS}" link set "${GATEWAY_WAN_VETH}" name wan0
ip -n "${WAN_NS}" link set "${WAN_VETH}" name wan0

for namespace in "${CLIENT_NS}" "${GATEWAY_NS}" "${WAN_NS}"; do
    ip -n "${namespace}" link set lo up
done
ip -n "${CLIENT_NS}" link set lan0 up
ip -n "${GATEWAY_NS}" link set lan0 up
ip -n "${GATEWAY_NS}" link set wan0 up
ip -n "${WAN_NS}" link set wan0 up

ip -n "${CLIENT_NS}" address add 10.44.0.2/24 dev lan0
ip -n "${CLIENT_NS}" address add 10.44.0.3/24 dev lan0
ip -n "${GATEWAY_NS}" address add 10.44.0.1/24 dev lan0
ip -n "${GATEWAY_NS}" address add 10.45.0.1/24 dev wan0
ip -n "${WAN_NS}" address add 10.45.0.2/24 dev wan0
ip -n "${CLIENT_NS}" route add default via 10.44.0.1
ip -n "${WAN_NS}" route add 10.44.0.0/24 via 10.45.0.1

ip -n "${CLIENT_NS}" -6 address add fd44:1::2/64 dev lan0
ip -n "${GATEWAY_NS}" -6 address add fd44:1::1/64 dev lan0
ip -n "${GATEWAY_NS}" -6 address add fd44:2::1/64 dev wan0
ip -n "${WAN_NS}" -6 address add fd44:2::2/64 dev wan0

readiness_deadline=$((SECONDS + READINESS_TIMEOUT_SECONDS))
wait_for_route "${CLIENT_NS}" 4 10.45.0.2 10.44.0.2 lan0
wait_for_route "${CLIENT_NS}" 4 10.45.0.2 10.44.0.3 lan0
wait_for_route "${WAN_NS}" 4 10.44.0.2 10.45.0.2 wan0
wait_for_ipv6_address "${CLIENT_NS}" lan0 fd44:1::2
wait_for_ipv6_address "${GATEWAY_NS}" lan0 fd44:1::1
wait_for_ipv6_address "${GATEWAY_NS}" wan0 fd44:2::1
wait_for_ipv6_address "${WAN_NS}" wan0 fd44:2::2

ip -n "${CLIENT_NS}" -6 route add default via fd44:1::1
ip -n "${WAN_NS}" -6 route add fd44:1::/64 via fd44:2::1
wait_for_route "${CLIENT_NS}" 6 fd44:2::2 fd44:1::2 lan0
wait_for_route "${WAN_NS}" 6 fd44:1::2 fd44:2::2 wan0

ip netns exec "${GATEWAY_NS}" sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "${GATEWAY_NS}" sysctl -q -w net.ipv6.conf.all.forwarding=1 >/dev/null

start_http_server "${GATEWAY_NS}" 0.0.0.0 15001 "${artifact_dir}/gateway-http.log"
gateway_server_pid="${spawned_server_pid}"
start_http_server "${GATEWAY_NS}" 10.44.0.1 53 "${artifact_dir}/gateway-dns-tcp.log"
dns_server_pid="${spawned_server_pid}"
start_http_server "${GATEWAY_NS}" 10.44.0.1 8081 "${artifact_dir}/gateway-management.log"
management_server_pid="${spawned_server_pid}"
start_http_server "${GATEWAY_NS}" fd44:1::1 8081 "${artifact_dir}/gateway-management-ipv6.log"
management_ipv6_server_pid="${spawned_server_pid}"
start_http_server "${WAN_NS}" 10.45.0.2 80 "${artifact_dir}/wan-direct-sentinel.log"
wan_direct_server_pid="${spawned_server_pid}"
start_http_server "${WAN_NS}" 10.45.0.2 8443 "${artifact_dir}/wan-http.log"
wan_ipv4_server_pid="${spawned_server_pid}"
start_http_server "${WAN_NS}" fd44:2::2 8444 "${artifact_dir}/wan-http6.log"
wan_ipv6_server_pid="${spawned_server_pid}"
wait_for_http_server "${GATEWAY_NS}" 127.0.0.1 15001 \
    "${gateway_server_pid}" "${artifact_dir}/gateway-http.log"
wait_for_http_server "${GATEWAY_NS}" 10.44.0.1 53 \
    "${dns_server_pid}" "${artifact_dir}/gateway-dns-tcp.log"
wait_for_http_server "${GATEWAY_NS}" 10.44.0.1 8081 \
    "${management_server_pid}" "${artifact_dir}/gateway-management.log"
wait_for_http_server "${GATEWAY_NS}" fd44:1::1 8081 \
    "${management_ipv6_server_pid}" "${artifact_dir}/gateway-management-ipv6.log"
wait_for_http_server "${WAN_NS}" 10.45.0.2 80 \
    "${wan_direct_server_pid}" "${artifact_dir}/wan-direct-sentinel.log"
wait_for_http_server "${WAN_NS}" 10.45.0.2 8443 \
    "${wan_ipv4_server_pid}" "${artifact_dir}/wan-http.log"
wait_for_http_server "${WAN_NS}" fd44:2::2 8444 \
    "${wan_ipv6_server_pid}" "${artifact_dir}/wan-http6.log"
record "CONTROL startup readiness: IPv4 routes, IPv6 DAD, and HTTP listeners ready"

# Positive controls prove forwarding, services, IPv6 routing, and packet
# capture work before any product rules can make negative probes pass.
wait_for_http_control mapped-ipv4 "${CLIENT_NS}" 4 10.44.0.2 \
    http://10.45.0.2:8443/
record "CONTROL mapped IPv4 forwarding reaches WAN before rules"

wait_for_http_control unmapped-ipv4 "${CLIENT_NS}" 4 10.44.0.3 \
    http://10.45.0.2:8443/
record "CONTROL unmapped IPv4 forwarding reaches WAN before rules"

wait_for_http_control ipv6 "${CLIENT_NS}" 6 fd44:1::2 \
    'http://[fd44:2::2]:8444/'
record "CONTROL IPv6 forwarding reaches WAN before rules"

wait_for_http_control management-ipv6 "${CLIENT_NS}" 6 fd44:1::2 \
    'http://[fd44:1::1]:8081/'
record "CONTROL same-LAN IPv6 reaches the management listener before rules"

wait_for_http_control direct-sentinel "${CLIENT_NS}" 4 10.44.0.2 \
    'http://10.45.0.2/'
record "CONTROL mapped source reaches the direct-WAN sentinel before rules"

control_udp_status=0
set +e
probe_udp_capture "${CLIENT_NS}" 10.44.0.2 \
    "${artifact_dir}/udp-control-before-rules.log"
control_udp_status="$?"
set -e
if [[ "${control_udp_status}" -eq 0 ]]; then
    record "CONTROL mapped UDP reaches WAN capture before rules"
else
    fail "pre-rules UDP capture control failed with status ${control_udp_status}"
fi

base_rules_file="${tmp_dir}/base.nft"
dynamic_rules_file="${tmp_dir}/dynamic.nft"
rules_file="${tmp_dir}/combined.nft"
render_fixture_layer base >"${base_rules_file}"
render_fixture_layer dynamic >"${dynamic_rules_file}"
while IFS= read -r rule_line; do
    printf '%s\n' "${rule_line}" >>"${rules_file}"
done <"${base_rules_file}"
while IFS= read -r rule_line; do
    printf '%s\n' "${rule_line}" >>"${rules_file}"
done <"${dynamic_rules_file}"
publish_product_artifacts "${rules_file}" "${base_rules_file}" "${dynamic_rules_file}"
ip netns exec "${GATEWAY_NS}" nft -c -f "${base_rules_file}"
ip netns exec "${GATEWAY_NS}" nft -f "${base_rules_file}"
ip netns exec "${GATEWAY_NS}" nft -c -f "${dynamic_rules_file}"
ip netns exec "${GATEWAY_NS}" nft -f "${dynamic_rules_file}"
dynamic_replace_file="${artifact_dir}/product-valid-dynamic-replacement.nft"
printf 'delete table inet pgw_dynamic\n' >"${dynamic_replace_file}"
while IFS= read -r rule_line; do
    printf '%s\n' "${rule_line}" >>"${dynamic_replace_file}"
done <"${dynamic_rules_file}"
ip netns exec "${GATEWAY_NS}" nft -c -f "${dynamic_replace_file}"
ip netns exec "${GATEWAY_NS}" nft -f "${dynamic_replace_file}"
capture_product_state applied
record "PASS static base is independent and dynamic LKG replacement is one checked transaction"

ip netns exec "${CLIENT_NS}" curl --noproxy '*' --interface 10.44.0.2 \
    --fail --silent --show-error \
    --connect-timeout 1 --max-time 3 http://10.45.0.2/ >/dev/null || \
    fail "mapped TCP/80 was not redirected to the local forwarder port"
record "PASS mapped TCP/80 is redirected to port 15001"

# A dead transparent Forwarder must fail closed. The destination-side port 80
# sentinel remains healthy, so any success here would prove direct fallback.
kill "${gateway_server_pid}"
wait "${gateway_server_pid}" 2>/dev/null || true
if ip netns exec "${CLIENT_NS}" curl --noproxy '*' --interface 10.44.0.2 \
    --fail --silent --connect-timeout 1 --max-time 2 \
    http://10.45.0.2/ >/dev/null; then
    fail "mapped traffic used direct WAN after Forwarder failure"
fi
ip netns exec "${WAN_NS}" curl --noproxy '*' --fail --silent --show-error \
    --connect-timeout 1 --max-time 2 http://10.45.0.2/ >/dev/null || \
    fail "Forwarder-failure negative is ambiguous because the direct sentinel is unreachable"
start_http_server "${GATEWAY_NS}" 0.0.0.0 15001 "${artifact_dir}/gateway-http-restarted.log"
gateway_server_pid="${spawned_server_pid}"
wait_for_http_server "${GATEWAY_NS}" 127.0.0.1 15001 \
    "${gateway_server_pid}" "${artifact_dir}/gateway-http-restarted.log"
record "PASS Forwarder failure has no direct-WAN fallback and restart restores readiness"

ip netns exec "${CLIENT_NS}" curl --noproxy '*' --interface 10.44.0.3 \
    --fail --silent --show-error --connect-timeout 1 --max-time 3 \
    http://10.44.0.1:53/ >/dev/null || \
    fail "explicit gateway DNS TCP allowance failed"
record "PASS explicit gateway DNS input allowance"

ip netns exec "${CLIENT_NS}" curl --noproxy '*' --interface 10.44.0.3 \
    --fail --silent --show-error --connect-timeout 1 --max-time 3 \
    http://10.44.0.1:8081/ >/dev/null || \
    fail "explicit gateway management allowance failed"
record "PASS explicit gateway management input allowance"

assert_management_ipv6_listener_live
management_ipv6_log_before="$(sha256sum \
    "${artifact_dir}/gateway-management-ipv6.log" | awk '{print $1}')"
management_drop_before_lan6="$(named_counter_packets pgw_base management_input_drop_total)"
if ip netns exec "${CLIENT_NS}" curl --noproxy '*' --globoff --ipv6 \
    --fail --silent --connect-timeout 1 --max-time 2 \
    'http://[fd44:1::1]:8081/' >/dev/null; then
    fail "LAN IPv6 reached the IPv4-only management UI policy"
fi
management_drop_after_lan6="$(named_counter_packets pgw_base management_input_drop_total)"
((management_drop_after_lan6 > management_drop_before_lan6)) || \
    fail "LAN IPv6 management denial did not increment management_input_drop_total"
assert_management_ipv6_listener_live
pgw_assert_one_ipv6_management_drop "${GATEWAY_NS}" "${CLIENT_NS}" fd44:1::2 \
    fd44:1::1 8081 pgw_base management_input_drop_total || \
    fail "LAN IPv6 one-packet management drop evidence failed"
record "PASS LAN IPv6 is denied while PID/address/socket liveness remains healthy"

if ip netns exec "${WAN_NS}" curl --noproxy '*' --fail --silent \
    --connect-timeout 1 --max-time 2 http://10.44.0.1:8081/ >/dev/null; then
    fail "WAN IPv4 reached the management UI port"
fi
management_drop_after_wan4="$(named_counter_packets pgw_base management_input_drop_total)"
((management_drop_after_wan4 > management_drop_after_lan6)) || \
    fail "WAN IPv4 management denial did not increment management_input_drop_total"
if ip netns exec "${WAN_NS}" curl --noproxy '*' --globoff --ipv6 --fail --silent \
    --connect-timeout 1 --max-time 2 'http://[fd44:1::1]:8081/' >/dev/null; then
    fail "WAN IPv6 reached the management UI port"
fi
management_drop_after_wan6="$(named_counter_packets pgw_base management_input_drop_total)"
((management_drop_after_wan6 > management_drop_after_wan4)) || \
    fail "WAN IPv6 management denial did not increment management_input_drop_total"
assert_management_ipv6_listener_live
pgw_assert_one_ipv6_management_drop "${GATEWAY_NS}" "${WAN_NS}" fd44:2::2 \
    fd44:1::1 8081 pgw_base management_input_drop_total || \
    fail "WAN IPv6 one-packet management drop evidence failed"
ip netns exec "${GATEWAY_NS}" curl --noproxy '*' --fail --silent --show-error \
    --connect-timeout 1 --max-time 2 http://10.44.0.1:8081/ >/dev/null || \
    fail "WAN management negative probe is ambiguous because IPv4 service is unreachable"
management_ipv6_log_after="$(sha256sum \
    "${artifact_dir}/gateway-management-ipv6.log" | awk '{print $1}')"
[[ "${management_ipv6_log_after}" == "${management_ipv6_log_before}" ]] || \
    fail "dropped IPv6 management probes unexpectedly reached the destination listener log"
record "PASS LAN/WAN IPv6 management probes have exact one-packet counter evidence and zero listener accepts"

if ip netns exec "${CLIENT_NS}" curl --noproxy '*' --interface 10.44.0.3 \
    --fail --silent --connect-timeout 1 --max-time 2 \
    http://10.44.0.1:15001/ >/dev/null; then
    fail "unmapped client reached a protected forwarder input port"
fi
ip netns exec "${GATEWAY_NS}" curl --noproxy '*' --fail --silent --show-error \
    --connect-timeout 1 --max-time 2 http://127.0.0.1:15001/ >/dev/null || \
    fail "forwarder input negative probe is ambiguous because local service became unreachable"
record "PASS dynamic input protection denies unmapped forwarder access"

if ip netns exec "${CLIENT_NS}" curl --noproxy '*' --interface 10.44.0.2 \
    --fail --silent \
    --connect-timeout 1 --max-time 2 http://10.45.0.2:8443/ >/dev/null; then
    fail "mapped TCP/8443 reached the WAN endpoint"
fi
ip netns exec "${WAN_NS}" curl --noproxy '*' --fail --silent --show-error \
    --connect-timeout 1 --max-time 2 http://10.45.0.2:8443/ >/dev/null || \
    fail "TCP/8443 negative probe is ambiguous because WAN service became unreachable"
record "PASS mapped TCP/8443 is policy-blocked while WAN service remains reachable"

udp_block_status=0
set +e
probe_udp_capture "${CLIENT_NS}" 10.44.0.2 \
    "${artifact_dir}/udp-blocked-client.log"
udp_block_status="$?"
set -e
case "${udp_block_status}" in
    0)
        fail "mapped UDP reached the WAN namespace"
        ;;
    124)
        ;;
    *)
        fail "mapped UDP probe failed unexpectedly with status ${udp_block_status}"
        ;;
esac

udp_control_status=0
set +e
probe_udp_capture "${GATEWAY_NS}" 10.45.0.1 \
    "${artifact_dir}/udp-control-after-rules.log"
udp_control_status="$?"
set -e
if [[ "${udp_control_status}" -eq 0 ]]; then
    record "CONTROL UDP capture remains reachable outside managed-client policy"
else
    fail "UDP negative probe is ambiguous; post-rules control failed with status ${udp_control_status}"
fi
record "PASS mapped UDP is policy-blocked"

if ip netns exec "${CLIENT_NS}" curl --noproxy '*' --globoff --ipv6 --fail --silent \
    --connect-timeout 1 --max-time 2 'http://[fd44:2::2]:8444/' >/dev/null; then
    fail "managed IPv6 reached the WAN endpoint"
fi
ip netns exec "${WAN_NS}" curl --noproxy '*' --globoff --ipv6 \
    --fail --silent --show-error --connect-timeout 1 --max-time 2 \
    'http://[fd44:2::2]:8444/' >/dev/null || \
    fail "IPv6 negative probe is ambiguous because WAN service became unreachable"
record "PASS managed IPv6 is policy-blocked while WAN service remains reachable"

if ip netns exec "${CLIENT_NS}" curl --noproxy '*' --interface 10.44.0.3 \
    --fail --silent --connect-timeout 1 --max-time 2 \
    http://10.45.0.2:8443/ >/dev/null; then
    fail "base kill-switch required but unmapped client reached direct WAN"
fi
ip netns exec "${WAN_NS}" curl --noproxy '*' --fail --silent --show-error \
    --connect-timeout 1 --max-time 2 http://10.45.0.2:8443/ >/dev/null || \
    fail "unmapped negative probe is ambiguous because WAN service became unreachable"
record "PASS unmapped client is policy-blocked by required base kill-switch"

for counter_spec in \
    'pgw_base ipv6_policy_drop_total' \
    'pgw_base udp_policy_drop_total' \
    'pgw_base lan_wan_direct_drop_total' \
    'pgw_base dns_input_accept_total' \
    'pgw_base management_input_accept_total' \
    'pgw_base management_input_drop_total' \
    'pgw_dynamic web_redirect_total' \
    'pgw_dynamic forwarder_input_accept_total' \
    'pgw_dynamic forwarder_input_drop_total'; do
    read -r counter_table counter_name <<<"${counter_spec}"
    assert_named_counter_positive "${counter_table}" "${counter_name}"
done

capture_product_state final

invalid_dynamic_file="${artifact_dir}/product-invalid-dynamic-candidate.nft"
dynamic_before_invalid="${artifact_dir}/product-dynamic-before-invalid.json"
dynamic_after_invalid="${artifact_dir}/product-dynamic-after-invalid.json"
ip netns exec "${GATEWAY_NS}" nft -j list table inet pgw_dynamic >"${dynamic_before_invalid}" || \
    fail "could not capture dynamic LKG before invalid candidate"
python3 -m json.tool "${dynamic_before_invalid}" >/dev/null || \
    fail "dynamic LKG before-invalid evidence is not valid JSON"
printf 'delete table inet pgw_dynamic\nadd table inet pgw_dynamic\nadd rule inet pgw_dynamic missing_chain counter\n' \
    >"${invalid_dynamic_file}"
if ip netns exec "${GATEWAY_NS}" nft -f "${invalid_dynamic_file}" \
    >"${artifact_dir}/product-invalid-dynamic.stdout.log" \
    2>"${artifact_dir}/product-invalid-dynamic.stderr.log"; then
    fail "invalid dynamic candidate unexpectedly applied"
fi
ip netns exec "${GATEWAY_NS}" nft -j list table inet pgw_dynamic >"${dynamic_after_invalid}" || \
    fail "invalid candidate removed the dynamic LKG"
python3 -m json.tool "${dynamic_after_invalid}" >/dev/null || \
    fail "dynamic LKG after-invalid evidence is not valid JSON"
cmp -s "${dynamic_before_invalid}" "${dynamic_after_invalid}" || \
    fail "dynamic LKG changed after invalid candidate validation"
ip netns exec "${GATEWAY_NS}" nft -j list table inet pgw_base \
    >"${artifact_dir}/product-base-after-invalid.json" || \
    fail "invalid dynamic reconcile removed pgw_base"
python3 -m json.tool "${artifact_dir}/product-base-after-invalid.json" >/dev/null || \
    fail "base-after-invalid evidence is not valid JSON"
ip netns exec "${CLIENT_NS}" curl --noproxy '*' --interface 10.44.0.2 \
    --fail --silent --show-error --connect-timeout 1 --max-time 3 \
    http://10.45.0.2/ >/dev/null || \
    fail "mapped redirect LKG stopped working after invalid candidate"
if ip netns exec "${CLIENT_NS}" curl --noproxy '*' --interface 10.44.0.3 \
    --fail --silent --connect-timeout 1 --max-time 2 \
    http://10.44.0.1:15001/ >/dev/null; then
    fail "invalid candidate exposed a protected forwarder port to an unmapped client"
fi
ip netns exec "${GATEWAY_NS}" curl --noproxy '*' --fail --silent --show-error \
    --connect-timeout 1 --max-time 2 http://127.0.0.1:15001/ >/dev/null || \
    fail "post-invalid forwarder denial is ambiguous because local service is unreachable"
ip netns exec "${WAN_NS}" curl --noproxy '*' --fail --silent --show-error \
    --connect-timeout 1 --max-time 2 http://10.45.0.2:8443/ >/dev/null || \
    fail "post-invalid direct-WAN denial is ambiguous because WAN service is unreachable"
if ip netns exec "${CLIENT_NS}" curl --noproxy '*' --interface 10.44.0.2 \
    --fail --silent --connect-timeout 1 --max-time 2 \
    http://10.45.0.2:8443/ >/dev/null; then
    fail "mapped client reached direct WAN after dynamic reconcile failure"
fi
if ip netns exec "${CLIENT_NS}" curl --noproxy '*' --interface 10.44.0.3 \
    --fail --silent --connect-timeout 1 --max-time 2 \
    http://10.45.0.2:8443/ >/dev/null; then
    fail "unmapped client reached direct WAN after dynamic reconcile failure"
fi
record "PASS invalid dynamic transaction preserves redirect/input LKG and static base fail-closed"
record "PASS Wave 1 namespace enforcement completed"
