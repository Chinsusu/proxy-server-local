#!/bin/bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
required="${PGW_REQUIRE_BASE_INSTALLER_EVIDENCE:-0}"
[[ "${required}" == 0 || "${required}" == 1 ]] || {
    printf 'invalid PGW_REQUIRE_BASE_INSTALLER_EVIDENCE\n' >&2
    exit 2
}
skip_or_fail() {
    local diagnostic="$1"
    printf 'base installer fail-close test unavailable: %s\n' "${diagnostic}" >&2
    [[ "${required}" != 1 ]] || exit 77
    exit 0
}
[[ "$(uname -s)" == Linux ]] || skip_or_fail 'Linux is required'
((EUID == 0)) || skip_or_fail 'isolated root is required'
command -v unshare >/dev/null && command -v mount >/dev/null || \
    skip_or_fail 'unshare/mount command is missing'
unshare_error="$(mktemp)"
set +e
unshare --mount --fork /bin/true 2>"${unshare_error}"
unshare_probe_rc=$?
set -e
if ((unshare_probe_rc != 0)); then
    diagnostic="$(tr '\n' ' ' <"${unshare_error}")"
    rm -f -- "${unshare_error}"
    skip_or_fail "mount namespace creation denied (rc=${unshare_probe_rc}): ${diagnostic}"
fi
rm -f -- "${unshare_error}"

fixture="$(mktemp -d /var/lib/pgw-base-installer-test.XXXXXXXX)"
trap 'rm -rf -- "${fixture}"' EXIT
chmod 0700 "${fixture}"
install -d "${fixture}/fake-bin" "${fixture}/etc/nftables.d" "${fixture}/etc/systemd/system"
printf '#!/usr/sbin/nft -f\ninclude "/etc/nftables.d/pgw-base.nft"\n' >"${fixture}/etc/nftables.conf"
[[ -d "${fixture}/etc/nftables.d" && -d "${fixture}/etc/systemd/system" && \
   -f "${fixture}/etc/nftables.conf" && ! -L "${fixture}/etc/nftables.conf" ]] \
    || { printf 'base installer fixture /etc topology is incomplete\n' >&2; exit 1; }

for command_name in nft sysctl ip systemctl; do
    printf '#!/bin/bash\nexec /bin/bash %q %q "$@"\n' "${fixture}/fake-command" "${command_name}" >"${fixture}/fake-bin/${command_name}"
    chmod 0755 "${fixture}/fake-bin/${command_name}"
done

cat >"${fixture}/fake-command" <<'FAKE'
#!/bin/bash
set -Eeuo pipefail
root="${PGW_BASE_TEST_ROOT:?}"
name="$1"; shift
case "${name}" in
    sysctl)
        if [[ "${1:-}" == -n ]]; then cat "${root}/forward"; exit; fi
        [[ "${1:-}" == -q && "${2:-}" == -w ]]
        printf '%s\n' "${3#*=}" >"${root}/forward"
        ;;
    ip)
        [[ "${1:-}" == link && "${2:-}" == show && "${3:-}" == dev && ("${4:-}" == lan0 || "${4:-}" == wan0) ]]
        ;;
    systemctl)
        case "${1:-}" in
            is-enabled) printf 'enabled\n' ;;
            enable)
                if [[ "${PGW_BASE_TEST_MODE:-}" == cleanup-failure ]]; then exit 42; fi
                ;;
            unmask|disable|mask) ;;
            *) exit 2 ;;
        esac
        ;;
    nft)
        if [[ "$*" == 'list table inet pgw_base' ]]; then exit 0; fi
        if [[ "$*" == '-s list table inet pgw_base' ]]; then cat "${root}/rules"; exit; fi
        if [[ "${1:-}" == list && ("${2:-}" == chain || "${2:-}" == counter) ]]; then exit 0; fi
        if [[ "${1:-}" == -c && "${2:-}" == -f ]]; then exit 0; fi
        if [[ "${1:-}" == -f ]]; then
            [[ "$(cat "${root}/forward")" == 0 ]] || { printf 'WAN SENTINEL OPEN\n' >>"${root}/sentinel"; exit 90; }
            printf 'closed:%s\n' "${PGW_BASE_TEST_MODE:-success}" >>"${root}/sentinel"
            count=0; [[ ! -f "${root}/apply-count" ]] || count="$(cat "${root}/apply-count")"
            count=$((count+1)); printf '%s\n' "${count}" >"${root}/apply-count"
            if [[ "${PGW_BASE_TEST_MODE:-}" == apply-failure && "${count}" == 1 ]]; then exit 41; fi
            if [[ "${PGW_BASE_TEST_MODE:-}" == cleanup-failure && "${count}" == 2 ]]; then exit 43; fi
            sed '1{/^delete table inet pgw_base$/d;}' "$2" >"${root}/rules"
            exit 0
        fi
        exit 2
        ;;
esac
FAKE
chmod 0755 "${fixture}/fake-command"

cat >"${fixture}/agent" <<'AGENT'
#!/bin/bash
set -Eeuo pipefail
case "${1:-}" in
    render-base) printf 'table inet pgw_base { chain exact { } }\n' ;;
    verify-base)
        [[ "$(cat "${PGW_BASE_TEST_ROOT}/forward")" == 0 ]]
        grep -q 'table inet pgw_base' "${PGW_BASE_TEST_ROOT}/rules"
        ;;
    *) exit 2 ;;
esac
AGENT
chmod 0755 "${fixture}/agent"

run_case() {
    local mode="$1"
    local expected_rc expected_apply_count expected_forward actual_apply_count actual_closed_count
    local critical_count service_critical_count live_critical_count
    local case_root="${fixture}/${mode}"
    case "${mode}" in
        success)
            expected_rc=0; expected_apply_count=1; expected_forward=1
            ;;
        apply-failure)
            expected_rc=41; expected_apply_count=1; expected_forward=0
            ;;
        cleanup-failure)
            expected_rc=1; expected_apply_count=2; expected_forward=0
            ;;
        *) printf 'invalid base installer evidence mode: %s\n' "${mode}" >&2; return 2 ;;
    esac
    install -d "${case_root}"
    printf '1\n' >"${case_root}/forward"
    printf 'table inet pgw_base { chain old { } }\n' >"${case_root}/rules"
    : >"${case_root}/sentinel"
    set +e
    unshare --mount --fork /bin/bash -c '
        set -Eeuo pipefail
        fixture="$1"; case_root="$2"; root="$3"; mode="$4"
        mount --bind "${fixture}/fake-bin" /usr/local/sbin
        # Bind the complete writable fixture tree once.  Binding the individual
        # destination file makes /etc/nftables.conf a mountpoint and causes the
        # production same-directory atomic rename to fail with EBUSY.
        mount --bind "${fixture}/etc" /etc
        export PGW_BASE_TEST_ROOT="${case_root}" PGW_BASE_TEST_MODE="${mode}"
        /bin/bash "${root}/deploy/install-pgw-base.sh" --agent "${fixture}/agent" --lan lan0 --wan wan0
    ' _ "${fixture}" "${case_root}" "${ROOT}" "${mode}" >/dev/null 2>"${case_root}/error.log"
    rc=$?
    set -e
    [[ "${rc}" == "${expected_rc}" ]] || {
        printf 'base installer mode %s returned %s, expected %s\n' \
            "${mode}" "${rc}" "${expected_rc}" >&2
        return 1
    }
    actual_apply_count="$(<"${case_root}/apply-count")"
    actual_closed_count="$(grep -Fxc "closed:${mode}" "${case_root}/sentinel" || true)"
    [[ "${actual_apply_count}" == "${expected_apply_count}" && \
       "${actual_closed_count}" == "${expected_apply_count}" ]] || {
        printf 'base installer mode %s apply evidence mismatch: apply=%s closed=%s expected=%s\n' \
            "${mode}" "${actual_apply_count}" "${actual_closed_count}" "${expected_apply_count}" >&2
        return 1
    }
    [[ "$(<"${case_root}/forward")" == "${expected_forward}" ]] || {
        printf 'base installer mode %s forwarding state mismatch\n' "${mode}" >&2
        return 1
    }
    ! grep -Fq 'WAN SENTINEL OPEN' "${case_root}/sentinel"
    critical_count="$(grep -c '^CRITICAL:' "${case_root}/error.log" || true)"
    if [[ "${mode}" == cleanup-failure ]]; then
        service_critical_count="$(grep -Fxc \
            'CRITICAL: failed to restore prior nftables.service enablement state' \
            "${case_root}/error.log" || true)"
        live_critical_count="$(grep -Fxc \
            'CRITICAL: failed to restore prior live pgw_base after installer error' \
            "${case_root}/error.log" || true)"
        [[ "${critical_count}" == 2 && "${service_critical_count}" == 1 && \
           "${live_critical_count}" == 1 ]] || {
            printf 'cleanup failure CRITICAL diagnostics mismatch: total=%s service=%s live=%s\n' \
                "${critical_count}" "${service_critical_count}" "${live_critical_count}" >&2
            return 1
        }
    elif [[ "${critical_count}" != 0 ]]; then
        printf 'base installer mode %s emitted unexpected CRITICAL diagnostics: %s\n' \
            "${mode}" "${critical_count}" >&2
        return 1
    fi
}

run_case success
run_case apply-failure
run_case cleanup-failure
printf 'base installer independent fail-close tests: PASS\n'
