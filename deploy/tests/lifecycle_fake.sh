#!/usr/bin/env bash
set -Eeuo pipefail

root="${PGW_FAKE_ROOT:?}"
state="${root}/runtime/services"
printf '%s %s\n' "$(basename -- "$0")" "$*" >>"${root}/commands.log"

field() { awk -F '\t' -v unit="$1" -v column="$2" '$1==unit {print $column; exit}' "${state}"; }
update_field() {
    local unit="$1" column="$2" value="$3" temporary
    temporary="${state}.new"
    awk -F '\t' -v OFS='\t' -v unit="${unit}" -v column="${column}" -v value="${value}" \
        '$1==unit {$column=value} {print}' "${state}" >"${temporary}"
    mv -f -- "${temporary}" "${state}"
}

fake_systemctl() {
    local operation="${1:-}" runtime=0 quiet=0 unit value config
    shift || true
    case "${operation}" in
        list-units)
            awk -F '\t' '$1 ~ /^pgw-fwd@[0-9]+\.service$/ {print $1,"loaded",$3,$3,"fixture"}' "${state}"
            ;;
        list-unit-files)
            awk -F '\t' '$1 ~ /^pgw-fwd@[0-9]+\.service$/ {print $1,$2}' "${state}"
            ;;
        is-enabled)
            unit="${1}"; value="$(field "${unit}" 2)"; [[ -n "${value}" ]] || value=not-found
            printf '%s\n' "${value}"
            [[ "${value}" != not-found ]]
            ;;
        is-active)
            quiet=0; [[ "${1:-}" == --quiet ]] && { quiet=1; shift; }
            unit="${1}"; value="$(field "${unit}" 3)"; [[ -n "${value}" ]] || value=inactive
            ((quiet)) || printf '%s\n' "${value}"
            [[ "${value}" == active ]]
            ;;
        show)
            unit="${@: -1}"
            if [[ "$*" == *MainPID* ]]; then field "${unit}" 4; else [[ -n "$(field "${unit}" 1)" ]] && printf 'loaded\n' || printf 'not-found\n'; fi
            ;;
        --no-block)
            [[ "${1}" == stop ]]; shift
            update_field "${1}" 3 inactive
            ;;
        start|restart)
            for unit in "$@"; do
                update_field "${unit}" 3 active
                if [[ "${unit}" == nftables.service ]]; then
                    config="${root}/system/etc/nftables.conf"
                    [[ -f "${config}" ]] || return 2
                    sed '1{/^flush ruleset$/d;}' "${config}" >"${root}/runtime/ruleset.nft"
                elif [[ "${unit}" == systemd-sysctl.service ]]; then
                    grep -Eq '^net[.]ipv4[.]ip_forward[[:space:]]*=[[:space:]]*1$' \
                        "${root}/system/etc/sysctl.d/99-pgw.conf" || return 2
                    printf '1\n' >"${root}/runtime/ip-forward"
                fi
            done
            ;;
        stop)
            unit="${1}"; [[ -n "$(field "${unit}" 1)" ]] && update_field "${unit}" 3 inactive
            ;;
        daemon-reload) ;;
        unmask|disable|enable|mask)
            if [[ "${1:-}" == --runtime ]]; then runtime=1; shift; fi
            [[ "${1:-}" != --now ]] || shift
            for unit in "$@"; do
                value="$(field "${unit}" 2)"
                case "${operation}:${runtime}:${value}" in
                    disable:0:enabled) value=disabled ;;
                    disable:0:masked) value=disabled ;;
                    disable:1:enabled-runtime|disable:1:masked-runtime) value=disabled ;;
                    enable:0:*) value=enabled ;;
                    enable:1:*) value=enabled-runtime ;;
                    mask:0:*) value=masked ;;
                    mask:1:*) value=masked-runtime ;;
                    unmask:0:masked) value=disabled ;;
                    unmask:1:masked-runtime) value=disabled ;;
                esac
                update_field "${unit}" 2 "${value}"
                [[ "${operation}" != disable || "${1:-}" != --now ]] || update_field "${unit}" 3 inactive
            done
            ;;
        cat) return 1 ;;
        *) printf 'unsupported fake systemctl: %s %s\n' "${operation}" "$*" >&2; return 2 ;;
    esac
}

fake_nft() {
    if [[ "$*" == '-s list ruleset' ]]; then
        cat "${root}/runtime/ruleset.nft"
    elif [[ "${1:-}" == -c && "${2:-}" == -f ]]; then
        grep -q '^flush ruleset$' "$3"
    elif [[ "${1:-}" == -f ]]; then
        sed '1{/^flush ruleset$/d;}' "$2" >"${root}/runtime/ruleset.nft"
    else
        return 2
    fi
}

fake_sysctl() {
    if [[ "${1:-}" == -n ]]; then
        cat "${root}/runtime/ip-forward"
    elif [[ "${1:-}" == -q && "${2:-}" == -w ]]; then
        printf '%s\n' "${3#*=}" >"${root}/runtime/ip-forward"
        if [[ "${3#*=}" == 1 && -f "${root}/system/var/lib/pgw-lifecycle/recovery.journal" ]]; then
            printf 'journal-present-at-forwarding-final\n' >>"${root}/commands.log"
        fi
    else
        return 2
    fi
}

fake_readlink() {
    local path="${@: -1}" pid unit command_name
    if [[ "${path}" == "${root}/system/proc/"*/exe ]]; then
        pid="${path#${root}/system/proc/}"; pid="${pid%/exe}"
        unit="$(awk -F '\t' -v pid="${pid}" '$4==pid {print $1; exit}' "${state}")"
        case "${unit}" in
            pgw-fwd@*) command_name=fwd ;;
            pgw-*.service) command_name="${unit#pgw-}"; command_name="${command_name%.service}" ;;
            *) return 1 ;;
        esac
        printf '%s/system/usr/local/bin/pgw-%s\n' "${root}" "${command_name}"
    else
        printf '%s\n' "${path}"
    fi
}

fake_openssl() {
    if [[ "${1:-}" == rand ]]; then
        if [[ "${2:-}" == -base64 ]]; then
            printf 'fixture-random-base64-material-0000000000000000000000000000000000000000\n'
        else
            printf '0123456789abcdef0123456789abcdef'
        fi
    elif [[ "$*" == *'-ext subjectAltName'* ]]; then
        printf 'X509v3 Subject Alternative Name:\n    DNS:pgw.fixture.test\n'
    elif [[ "$*" == *'-subject'* ]]; then
        printf 'subject=CN=pgw.fixture.test\n'
    elif [[ "$*" == *'-pubkey'* || "$*" == *'-pubout'* || "$*" == *'-outform DER'* ]]; then
        printf 'fixture-public-key-der'
    elif [[ "$*" == *'-noout'* ]]; then
        return 0
    else
        return 2
    fi
}

fake_install() {
    local -a forwarded=()
    while (($#)); do
        case "$1" in
            -o|-g|--owner|--group) (($# >= 2)) || return 2; shift 2 ;;
            --owner=*|--group=*) shift ;;
            *) forwarded+=("$1"); shift ;;
        esac
    done
    /usr/bin/install "${forwarded[@]}"
}

fake_stat() {
    local format='' path="${@: -1}"
    if [[ "${1:-}" == -c ]]; then format="${2:-}"; fi
    if [[ "${format}" == %a:%u && "${path}" == */var/lib/pgw-lifecycle/recovery.journal ]]; then
        printf '600:%s\n' "${EUID}"
        return
    fi
    if [[ "${format}" == %U:%G:%a ]]; then
        case "${path#${root}/system}" in
            /usr/local/bin/pgw-*) printf 'root:root:755\n'; return ;;
            /var/lib/pgw) printf 'pgw-api:pgw-control:750\n'; return ;;
            /var/lib/pgw/rules) printf 'pgw-agent:pgw-agent:750\n'; return ;;
            /run/pgw/forwarders) printf 'pgw-agent:pgw-fwd:750\n'; return ;;
            /usr/local/share/pgw/web) printf 'pgw-ui:pgw-ui:550\n'; return ;;
        esac
    fi
    /usr/bin/stat "$@"
}

fake_curl() {
    local url="${@: -1}"
    printf '%s\n' "${url}" >>"${root}/ui-smoke.log"
    [[ "${url}" != */login ]] || printf '<link href="/static/styles.css"><script src="/static/login.js"></script>\n'
}

mutate_fixture() {
    local system="${root}/system" phase="$1"
    [[ "$(tr -d '[:space:]' <"${root}/runtime/ip-forward")" == 0 ]] || {
        printf 'forwarding-open-before:%s\n' "${phase}" >>"${root}/wan-sentinel.log"
        return 90
    }
    printf 'forwarding-closed-before:%s\n' "${phase}" >>"${root}/wan-sentinel.log"
    printf 'new:%s\n' "${phase}" >"${system}/var/lib/pgw/pgw.db"
    printf 'new:%s\n' "${phase}" >"${system}/usr/local/bin/pgw-api"
    printf 'new:%s\n' "${phase}" >"${system}/usr/local/share/pgw/web/static/app.js"
    printf 'created:%s\n' "${phase}" >"${system}/usr/local/sbin/pgw-verify-base"
    update_field pgw-api.service 3 inactive
    update_field pgw-fwd@15001.service 3 inactive
    update_field pgw-fwd@15002.service 3 active
    update_field pgw-fwd@15002.service 2 enabled
    printf 'table inet pgw_base { chain changed { } }\n' >"${root}/runtime/ruleset.nft"
    printf '1\n' >"${root}/runtime/ip-forward"
}

dispatch_restore_crash() {
    local expected_state expected_logical expected_point expected_nonce expected_operation_id
    local helper state_arg source_arg target_arg metadata_arg logical_arg uid_arg snapshot_root
    [[ -f "${root}/restore-crash-control" ]] || return 1
    IFS=$'\t' read -r expected_state expected_logical expected_point expected_nonce expected_operation_id \
        <"${root}/restore-crash-control"
    case "${expected_state}:${expected_logical}:${expected_point}" in
        present:/var/lib/pgw:partial_stage|present:/var/lib/pgw:post_exchange|present:/var/lib/pgw:mid_cleanup|\
        absent:/etc/pgw/credential-inbox:partial_stage|absent:/etc/pgw/credential-inbox:post_exchange|absent:/etc/pgw/credential-inbox:mid_cleanup) ;;
        *) printf 'invalid restore crash control\n' >&2; exit 97 ;;
    esac
    [[ "${expected_nonce}" =~ ^[0-9a-f]{64}$ ]] \
        || { printf 'invalid restore crash nonce\n' >&2; exit 97; }
    [[ "${expected_operation_id}" =~ ^[0-9a-f]{64}$ ]] \
        || { printf 'invalid restore crash operation id\n' >&2; exit 97; }

    # Production atomic_restore_path invokes exactly:
    # python3 -I HELPER STATE SOURCE TARGET METADATA LOGICAL EXPECTED_UID.
    # Delegate verify/metadata/operation-id and other logical roots unchanged;
    # intercept only the authenticated restore operation named by the control.
    (($# == 8)) || return 1
    [[ "$1" == -I ]] || return 1
    helper="$2"; state_arg="$3"; source_arg="$4"; target_arg="$5"
    metadata_arg="$6"; logical_arg="$7"; uid_arg="$8"
    [[ "${state_arg}" == "${expected_state}" && "${logical_arg}" == "${expected_logical}" ]] \
        || return 1
    [[ "${helper}" == */deploy/restore_snapshot.py && -f "${helper}" && ! -L "${helper}" ]] \
        || { printf 'invalid production restore helper argv\n' >&2; exit 98; }
    [[ "${metadata_arg}" == "${root}"/system/run/pgw/snapshot-restore.install.*/metadata.json ]] \
        || { printf 'invalid production restore metadata argv\n' >&2; exit 98; }
    snapshot_root="${metadata_arg%/metadata.json}"
    [[ "${target_arg}" == "${root}/system${expected_logical}" && "${uid_arg}" == "${EUID}" ]] \
        || { printf 'invalid production restore target argv\n' >&2; exit 98; }
    if [[ "${expected_state}" == present ]]; then
        [[ "${source_arg}" == "${snapshot_root}/files${expected_logical}" ]] \
            || { printf 'invalid production restore source argv\n' >&2; exit 98; }
    else
        [[ "${source_arg}" == /dev/null ]] \
            || { printf 'invalid absent restore source argv\n' >&2; exit 98; }
    fi
    PGW_RESTORE_CRASH_OPERATION_ID="${expected_operation_id}" \
        exec /usr/bin/python3 -I "${root}/restore-crash-driver.py" "${helper}" "${@:3}"
}

case "$(basename -- "$0")" in
    systemctl) fake_systemctl "$@" ;;
    nft) fake_nft "$@" ;;
    sysctl) fake_sysctl "$@" ;;
    sqlite3) printf 'ok\n' ;;
    python3)
        dispatch_restore_crash "$@" || true
        last_arg="${!#}"
        if [[ "${PGW_CRASH_LEGACY_SEALED:-0}" == 1 && "${2:-}" == */deploy/snapshot_payload.py && \
              "${3:-}" == materialize && "${last_arg}" == "${root}/system/run/pgw/legacy-sealed.install."* ]]; then
            if [[ "$(uname -s)" == MINGW* ]]; then
                MSYS2_ARG_CONV_EXCL='/etc;/var;/run;/usr;/dev' python "$@"
            else
                /usr/bin/python3 "$@"
            fi
            rc=$?
            ((rc == 0)) || exit "${rc}"
            # This fake is a direct child of the installer harness. SIGKILL
            # its parent so the harness EXIT trap cannot scrub the stage.
            kill -KILL "${PPID}"
            kill -KILL "$$"
        fi
        if [[ "$(uname -s)" == MINGW* ]]; then
            MSYS2_ARG_CONV_EXCL='/etc;/var;/run;/usr;/dev' exec python "$@"
        fi
        exec /usr/bin/python3 "$@"
        ;;
    readlink) fake_readlink "$@" ;;
    openssl) fake_openssl "$@" ;;
    curl) fake_curl "$@" ;;
    stat) fake_stat "$@" ;;
    lifecycle)
        case "${1:-}" in
            mutate) mutate_fixture "${4}" ;;
            install-base)
                printf 'table inet pgw_base { chain forward { type filter hook forward priority filter; policy drop; } }\n' \
                    >"${root}/runtime/ruleset.nft"
                printf '0\n' >"${root}/runtime/ip-forward"
                ;;
            verify-base)
                grep -q 'table inet pgw_base' "${root}/runtime/ruleset.nft"
                ;;
            *) exit 2 ;;
        esac
        ;;
    install) fake_install "$@" ;;
    chown|systemd-sysusers|systemd-tmpfiles) exit 0 ;;
    *) printf 'unsupported lifecycle fake command\n' >&2; exit 2 ;;
esac
