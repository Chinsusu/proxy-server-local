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

render_nft_boot_ruleset() {
    /usr/bin/python3 -I - "${root}" <<'PY'
import os
import stat
import sys

MAX_MAIN = 65536
MAX_BASE = 1048576
CANONICAL_BASE = b"table inet pgw_base { chain forward { type filter hook forward priority filter; policy drop; } }\n"


def safe_directory(parent, name, expected_uid):
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    info = os.fstat(descriptor)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) & 0o022):
        os.close(descriptor)
        raise ValueError("unsafe directory")
    return descriptor


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def safe_file(parent, name, expected_uid, limit):
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=parent,
    )
    try:
        before = os.fstat(descriptor)
        bound_before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != expected_uid
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022
                or (bound_before.st_dev, bound_before.st_ino) != (before.st_dev, before.st_ino)
                or before.st_size > limit):
            raise ValueError("unsafe file")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        bound_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (len(payload) > limit or identity(after) != identity(before)
                or (bound_after.st_dev, bound_after.st_ino) != (after.st_dev, after.st_ino)):
            raise ValueError("file changed")
        return payload
    finally:
        os.close(descriptor)


fixture = sys.argv[1]
descriptors = []
try:
    if not os.path.isabs(fixture) or os.path.normpath(fixture) != fixture:
        raise ValueError("unsafe fixture")
    expected = os.geteuid()
    root_fd = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors.append(root_fd)
    root_info = os.fstat(root_fd)
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != expected
            or stat.S_IMODE(root_info.st_mode) & 0o022):
        raise ValueError("unsafe fixture")
    system_fd = safe_directory(root_fd, "system", expected)
    descriptors.append(system_fd)
    etc_fd = safe_directory(system_fd, "etc", expected)
    descriptors.append(etc_fd)
    nft_dir_fd = safe_directory(etc_fd, "nftables.d", expected)
    descriptors.append(nft_dir_fd)

    main = safe_file(etc_fd, "nftables.conf", expected, MAX_MAIN)
    base = safe_file(nft_dir_fd, "pgw-base.nft", expected, MAX_BASE)

    executable = []
    if any(byte not in (9, 10) and not 32 <= byte <= 126 for byte in main):
        raise ValueError("invalid main nftables bytes")
    for line in main.split(b"\n"):
        stripped = line.strip(b" \t")
        if not stripped or stripped.startswith(b"#"):
            continue
        executable.append(stripped)
    if executable != [b"flush ruleset", b'include "/etc/nftables.d/pgw-base.nft"']:
        raise ValueError("invalid main nftables config")

    if base != CANONICAL_BASE:
        raise ValueError("invalid persisted base")
    sys.stdout.buffer.write(base)
except (OSError, UnicodeError, ValueError):
    raise SystemExit(2)
finally:
    for descriptor in reversed(descriptors):
        os.close(descriptor)
PY
}

publish_nft_boot_ruleset() {
    local temporary
    temporary="$(/usr/bin/mktemp "${root}/runtime/.ruleset.nft.new.XXXXXXXX")" || return 2
    if ! render_nft_boot_ruleset >"${temporary}"; then
        rm -f -- "${temporary}"
        return 2
    fi
    /usr/bin/chmod 0644 "${temporary}" || { rm -f -- "${temporary}"; return 2; }
    /usr/bin/mv -f -- "${temporary}" "${root}/runtime/ruleset.nft" || {
        rm -f -- "${temporary}"
        return 2
    }
}

publish_fake_base() {
    local candidate base_stage runtime_stage base_target runtime_target base_backup="" runtime_backup=""
    local target uid mode links rc=0 rollback_rc=0 base_had=0 runtime_had=0 base_published=0 runtime_published=0
    case "${PGW_FAKE_NFT_INSTALL_FAIL_AT:-}" in
        ''|after_base) ;;
        *) return 2 ;;
    esac
    base_target="${root}/system/etc/nftables.d/pgw-base.nft"
    runtime_target="${root}/runtime/ruleset.nft"
    candidate="$(/usr/bin/mktemp "${root}/runtime/.pgw-base.candidate.XXXXXXXX")" || return 2
    base_stage="$(/usr/bin/mktemp "${root}/system/etc/nftables.d/.pgw-base.nft.new.XXXXXXXX")" \
        || { /usr/bin/rm -f -- "${candidate}"; return 2; }
    runtime_stage="$(/usr/bin/mktemp "${root}/runtime/.ruleset.nft.new.XXXXXXXX")" \
        || { /usr/bin/rm -f -- "${candidate}" "${base_stage}"; return 2; }
    printf 'table inet pgw_base { chain forward { type filter hook forward priority filter; policy drop; } }\n' \
        >"${candidate}"
    if ! /usr/bin/install -m 0644 -- "${candidate}" "${base_stage}" ||
       ! /usr/bin/install -m 0644 -- "${candidate}" "${runtime_stage}" ||
       [[ "$(/usr/bin/stat -c '%u:%a:%F:%h' -- "${base_stage}")" != "${EUID}:644:regular file:1" ]] ||
       [[ "$(/usr/bin/stat -c '%u:%a:%F:%h' -- "${runtime_stage}")" != "${EUID}:644:regular file:1" ]] ||
       ! /usr/bin/cmp -s -- "${base_stage}" "${runtime_stage}"; then
        /usr/bin/rm -f -- "${candidate}" "${base_stage}" "${runtime_stage}"
        return 2
    fi
    /usr/bin/rm -f -- "${candidate}"

    for target in "${base_target}" "${runtime_target}"; do
        if [[ -e "${target}" || -L "${target}" ]]; then
            [[ -f "${target}" && ! -L "${target}" ]] || { rc=2; break; }
            uid="$(/usr/bin/stat -c '%u' -- "${target}")"
            mode="$(/usr/bin/stat -c '%a' -- "${target}")"
            links="$(/usr/bin/stat -c '%h' -- "${target}")"
            [[ "${uid}" == "${EUID}" && "${links}" == 1 && $((8#${mode} & 8#022)) == 0 ]] \
                || { rc=2; break; }
        fi
    done

    if ((rc == 0)) && [[ -e "${base_target}" ]]; then
        base_backup="$(/usr/bin/mktemp "${root}/system/etc/nftables.d/.pgw-base.nft.backup.XXXXXXXX")" || rc=2
        if ((rc == 0)); then
            /usr/bin/rm -f -- "${base_backup}"
            /usr/bin/mv -T -- "${base_target}" "${base_backup}" && base_had=1 || rc=2
        fi
    fi
    if ((rc == 0)) && [[ -e "${runtime_target}" ]]; then
        runtime_backup="$(/usr/bin/mktemp "${root}/runtime/.ruleset.nft.backup.XXXXXXXX")" || rc=2
        if ((rc == 0)); then
            /usr/bin/rm -f -- "${runtime_backup}"
            /usr/bin/mv -T -- "${runtime_target}" "${runtime_backup}" && runtime_had=1 || rc=2
        fi
    fi
    if ((rc == 0)); then
        /usr/bin/mv -T -- "${base_stage}" "${base_target}" && { base_stage=""; base_published=1; } || rc=2
    fi
    if ((rc == 0)) && [[ "${PGW_FAKE_NFT_INSTALL_FAIL_AT:-}" == after_base ]]; then
        rc=2
    fi
    if ((rc == 0)); then
        /usr/bin/mv -T -- "${runtime_stage}" "${runtime_target}" && { runtime_stage=""; runtime_published=1; } || rc=2
    fi
    if ((rc == 0)); then
        [[ -z "${base_backup}" ]] || /usr/bin/rm -f -- "${base_backup}"
        [[ -z "${runtime_backup}" ]] || /usr/bin/rm -f -- "${runtime_backup}"
        return 0
    fi

    if ((runtime_published)); then
        /usr/bin/rm -f -- "${runtime_target}" || rollback_rc=1
    fi
    if ((runtime_had)); then
        /usr/bin/mv -T -- "${runtime_backup}" "${runtime_target}" || rollback_rc=1
        runtime_backup=""
    fi
    if ((base_published)); then
        /usr/bin/rm -f -- "${base_target}" || rollback_rc=1
    fi
    if ((base_had)); then
        /usr/bin/mv -T -- "${base_backup}" "${base_target}" || rollback_rc=1
        base_backup=""
    fi
    [[ -z "${base_stage}" ]] || /usr/bin/rm -f -- "${base_stage}"
    [[ -z "${runtime_stage}" ]] || /usr/bin/rm -f -- "${runtime_stage}"
    [[ -z "${base_backup}" ]] || /usr/bin/rm -f -- "${base_backup}"
    [[ -z "${runtime_backup}" ]] || /usr/bin/rm -f -- "${runtime_backup}"
    ((rollback_rc == 0)) || return 98
    return 2
}

fake_systemctl() {
    local operation="${1:-}" runtime=0 quiet=0 unit value config config_uid config_mode config_links config_value
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
                if [[ "${unit}" == nftables.service ]]; then
                    if [[ "${operation}" == start && "$(field "${unit}" 3)" == active ]]; then
                        continue
                    fi
                    publish_nft_boot_ruleset || return 2
                elif [[ "${unit}" == systemd-sysctl.service ]]; then
                    config="${root}/system/etc/sysctl.d/99-pgw.conf"
                    [[ ! -L "${config}" ]] || return 2
                    if [[ -e "${config}" ]]; then
                        [[ -f "${config}" ]] || return 2
                        config_uid="$(/usr/bin/stat -c '%u' -- "${config}")"
                        config_mode="$(/usr/bin/stat -c '%a' -- "${config}")"
                        config_links="$(/usr/bin/stat -c '%h' -- "${config}")"
                        [[ "${config_uid}" == "${EUID}" && "${config_links}" == 1 &&
                           $((8#${config_mode} & 8#022)) == 0 ]] || return 2
                        config_value="$(/usr/bin/awk '
                            /^[[:space:]]*([#;]|$)/ { next }
                            {
                                line=$0
                                if (line ~ /^[[:space:]]*net[.]ipv4[.]ip_forward([[:space:]]|=)/) {
                                    if (line !~ /^[[:space:]]*net[.]ipv4[.]ip_forward[[:space:]]*=[[:space:]]*[01][[:space:]]*$/) exit 2
                                    sub(/^[^=]*=[[:space:]]*/, "", line)
                                    sub(/[[:space:]]*$/, "", line)
                                    value=line
                                    found=1
                                }
                            }
                            END { if (!found) exit 3; print value }
                        ' "${config}")" || return 2
                        printf '%s\n' "${config_value}" >"${root}/runtime/ip-forward"
                    fi
                fi
                update_field "${unit}" 3 active
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
        if [[ "$3" == "${root}/system/etc/nftables.conf" ]]; then
            render_nft_boot_ruleset >/dev/null || return 2
        else
            grep -q '^flush ruleset$' "$3" && grep -q 'table inet pgw_base' "$3" || return 2
        fi
    elif [[ "${1:-}" == -f ]]; then
        if [[ "$2" == "${root}/system/etc/nftables.conf" ]]; then
            publish_nft_boot_ruleset || return 2
        else
            grep -q '^flush ruleset$' "$2" && grep -q 'table inet pgw_base' "$2" || return 2
            sed '1{/^flush ruleset$/d;}' "$2" >"${root}/runtime/ruleset.nft"
        fi
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
        # -pubin means this fake is the stdin-fed consumer of a pipeline
        # (validate_tls_pair's `x509 -pubkey | pkey -pubin`). The real openssl
        # reads that stream; the fake must drain it too, or exiting first
        # races the upstream writer into SIGPIPE - under the installer's
        # pipefail the pipeline then returns 141 and errexit kills the
        # installer with no diagnostic. This was the intermittent
        # "fake openssl broken pipe" CI flake.
        [[ "$*" != *'-pubin'* ]] || cat >/dev/null
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

grant_restore_authority() {
    local target="${1:-}"
    /usr/bin/python3 -I - "${root}" "${target}" "${EUID}" <<'PY'
import os, stat, sys

fixture, target, expected_text = sys.argv[1:]
expected = int(expected_text)
required_target = os.path.join(fixture, "system/usr/local/share/pgw/web")
if (not os.path.isabs(fixture) or os.path.normpath(fixture) != fixture or
        target != required_target):
    raise SystemExit("unsafe fixture restore-authority target")

flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
descriptor = os.open(os.sep, flags)
try:
    for component in (part for part in fixture.split(os.sep) if part):
        child = os.open(component, flags, dir_fd=descriptor)
        info = os.fstat(child)
        if info.st_uid not in (0, expected) or info.st_mode & 0o022:
            os.close(child)
            raise SystemExit("unsafe fixture restore-authority ancestor")
        os.close(descriptor)
        descriptor = child
    for component in ("system", "usr", "local", "share", "pgw", "web"):
        child = os.open(component, flags, dir_fd=descriptor)
        info = os.fstat(child)
        if info.st_uid != expected or info.st_mode & 0o022:
            os.close(child)
            raise SystemExit("unsafe fixture restore-authority UI directory")
        os.close(descriptor)
        descriptor = child

    web = descriptor
    descriptor = -1
    entries = sorted(os.listdir(web))
    if entries not in (["static"], [".manifest.sha256", "static"]):
        raise SystemExit("unexpected fixture restore-authority UI layout")
    static_fd = os.open("static", flags, dir_fd=web)
    try:
        static_info = os.fstat(static_fd)
        if static_info.st_uid != expected or static_info.st_mode & 0o022:
            raise SystemExit("unsafe fixture restore-authority static directory")
        if sorted(os.listdir(static_fd)) != ["app.js", "layout.css", "login.js", "styles.css"]:
            raise SystemExit("unexpected fixture restore-authority static layout")

        def admit_file(parent, name):
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected or
                    info.st_mode & 0o022 or info.st_nlink != 1):
                raise SystemExit("unsafe fixture restore-authority UI file")

        for name in ("app.js", "layout.css", "login.js", "styles.css"):
            admit_file(static_fd, name)
        if ".manifest.sha256" in entries:
            admit_file(web, ".manifest.sha256")

        os.fchmod(static_fd, stat.S_IMODE(static_info.st_mode) | 0o300)
        os.fsync(static_fd)
        web_info = os.fstat(web)
        os.fchmod(web, stat.S_IMODE(web_info.st_mode) | 0o300)
        os.fsync(web)
    finally:
        os.close(static_fd)
        os.close(web)
finally:
    if descriptor >= 0:
        os.close(descriptor)
PY
}

grant_snapshot_validation_cleanup_authority() {
    local stage="${1:-}" expected_uid="${2:-}"
    /usr/bin/python3 -I - "${root}" "${stage}" "${expected_uid}" <<'PY'
import os
import re
import stat
import sys

fixture, stage_path, expected_text = sys.argv[1:]
expected = int(expected_text)
prefix = "snapshot-validation."
stage_name = os.path.basename(stage_path)
snapshot_name = stage_name[len(prefix):] if stage_name.startswith(prefix) else ""
if (not os.path.isabs(fixture) or os.path.normpath(fixture) != fixture
        or re.fullmatch(r"install[.][A-Za-z0-9]+", snapshot_name) is None
        or stage_path != os.path.join(fixture, "system/run/pgw", stage_name)):
    raise SystemExit("unsafe fixture snapshot-validation stage")

flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def open_safe(parent, name, owners, mode=None):
    descriptor = os.open(name, flags, dir_fd=parent)
    info = os.fstat(descriptor)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners
            or info.st_mode & 0o022
            or (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
        os.close(descriptor)
        raise ValueError("unsafe fixture snapshot-validation directory")
    return descriptor


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def grant_tree(parent, name):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if stat.S_ISDIR(before.st_mode):
        if before.st_uid != expected or before.st_mode & 0o022:
            raise ValueError("unsafe snapshot-validation child directory")
        child = os.open(name, flags, dir_fd=parent)
        try:
            opened = os.fstat(child)
            rebound = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                    or (rebound.st_dev, rebound.st_ino) != (opened.st_dev, opened.st_ino)):
                raise ValueError("snapshot-validation directory changed")
            os.fchmod(child, stat.S_IMODE(opened.st_mode) | 0o300)
            names = sorted(os.listdir(child))
            for member in names:
                if not member or member in (".", "..") or "/" in member or "\x00" in member:
                    raise ValueError("unsafe snapshot-validation member")
                grant_tree(child, member)
            rebound = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (sorted(os.listdir(child)) != names
                    or (rebound.st_dev, rebound.st_ino) != (opened.st_dev, opened.st_ino)
                    or (os.fstat(child).st_dev, os.fstat(child).st_ino) !=
                       (opened.st_dev, opened.st_ino)):
                raise ValueError("snapshot-validation directory rebound")
            os.fsync(child)
        finally:
            os.close(child)
        return
    if stat.S_ISREG(before.st_mode):
        if before.st_uid != expected or before.st_nlink != 1 or before.st_mode & 0o022:
            raise ValueError("unsafe snapshot-validation regular file")
    elif stat.S_ISLNK(before.st_mode):
        if before.st_uid != expected:
            raise ValueError("foreign snapshot-validation symlink")
    else:
        raise ValueError("special snapshot-validation node")
    after = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if identity(after) != identity(before):
        raise ValueError("snapshot-validation node changed")


descriptor = os.open(os.sep, flags)
try:
    for component in (part for part in fixture.split(os.sep) if part):
        child = open_safe(descriptor, component, (0, expected))
        os.close(descriptor)
        descriptor = child
    fixture_fd = descriptor
    descriptor = -1
    backups_fd = open_safe(fixture_fd, "backups", (expected,))
    try:
        snapshot_fd = open_safe(backups_fd, snapshot_name, (expected,), 0o700)
        os.close(snapshot_fd)
    finally:
        os.close(backups_fd)
    system_fd = open_safe(fixture_fd, "system", (expected,))
    try:
        run_fd = open_safe(system_fd, "run", (expected,))
        try:
            pgw_fd = open_safe(run_fd, "pgw", (expected,))
            try:
                stage_fd = open_safe(pgw_fd, stage_name, (expected,), 0o700)
                os.close(stage_fd)
                grant_tree(pgw_fd, stage_name)
                os.fsync(pgw_fd)
            finally:
                os.close(pgw_fd)
        finally:
            os.close(run_fd)
    finally:
        os.close(system_fd)
        os.close(fixture_fd)
finally:
    if descriptor >= 0:
        os.close(descriptor)
PY
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

    # Production per-path restore invokes exactly:
    # python3 -I HELPER STATE SOURCE TARGET METADATA LOGICAL EXPECTED_UID.
    # Present and absent roots must both bind to the authenticated metadata
    # generated inside the same private materialized restore stage.
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

dispatch_restore_authority() {
    local helper state_arg source_arg target_arg metadata_arg logical_arg uid_arg snapshot_root
    # Run only at the exact authenticated per-path restore call. Quiesce,
    # snapshot verification, materialization, and metadata authentication have
    # already succeeded; restore-crash interception runs before this adapter.
    (($# == 8)) || return 0
    [[ "$1" == -I && "$2" == */deploy/restore_snapshot.py &&
       ("$3" == present || "$3" == absent) && "$7" == /usr/local/share/pgw/web ]] \
        || return 0
    helper="$2"; state_arg="$3"; source_arg="$4"; target_arg="$5"
    metadata_arg="$6"; logical_arg="$7"; uid_arg="$8"
    [[ -f "${helper}" && ! -L "${helper}" ]] \
        || { printf 'invalid UI restore-authority helper argv\n' >&2; exit 98; }
    [[ "${metadata_arg}" == "${root}"/system/run/pgw/snapshot-restore.install.*/metadata.json ]] \
        || { printf 'invalid UI restore-authority metadata argv\n' >&2; exit 98; }
    snapshot_root="${metadata_arg%/metadata.json}"
    [[ "${target_arg}" == "${root}/system${logical_arg}" && "${uid_arg}" == "${EUID}" ]] \
        || { printf 'invalid UI restore-authority target argv\n' >&2; exit 98; }
    if [[ "${state_arg}" == present ]]; then
        [[ "${source_arg}" == "${snapshot_root}/files${logical_arg}" ]] \
            || { printf 'invalid UI restore-authority source argv\n' >&2; exit 98; }
    else
        [[ "${source_arg}" == /dev/null ]] \
            || { printf 'invalid UI restore-authority absent argv\n' >&2; exit 98; }
    fi
    # Production needs override authority only to unlink children of a sealed
    # directory. Missing targets and non-directories (including symlinks and
    # special nodes) are handled descriptor-relatively by the real helper.
    if [[ -d "${target_arg}" && ! -L "${target_arg}" ]]; then
        grant_restore_authority "${target_arg}"
    fi
}

dispatch_snapshot_validation_crash() {
    local point="" stage="" snapshot_name snapshot rc
    case "${PGW_FAIL_AT:-}" in
        crash_validation:materialized)
            (($# == 7)) || return 0
            [[ "$1" == -I && "$2" == */deploy/snapshot_payload.py && "$3" == materialize ]] \
                || return 0
            snapshot="$4"; stage="$7"; point=materialized
            ;;
        crash_validation:metadata)
            (($# == 4)) || return 0
            [[ "$1" == -I && "$2" == */deploy/restore_snapshot.py && "$3" == metadata ]] \
                || return 0
            stage="$4"; point=metadata
            ;;
        crash_validation:verified)
            (($# == 6)) || return 0
            [[ "$1" == -I && "$2" == */deploy/restore_snapshot.py && "$3" == verify &&
               "$5" == payload && "$6" == "${root}/system" ]] || return 0
            stage="$4"; point=verified
            ;;
        *) return 0 ;;
    esac
    [[ -f "$2" && ! -L "$2" &&
       "${stage}" == "${root}/system/run/pgw/snapshot-validation.install."* ]] \
        || { printf 'invalid snapshot-validation crash argv\n' >&2; exit 98; }
    snapshot_name="${stage##*/snapshot-validation.}"
    [[ "${snapshot_name}" =~ ^install[.][A-Za-z0-9]+$ ]] \
        || { printf 'invalid snapshot-validation crash stage name\n' >&2; exit 98; }
    [[ -n "${snapshot:-}" ]] || snapshot="${root}/backups/${snapshot_name}"
    [[ "${snapshot}" == "${root}/backups/${snapshot_name}" && -d "${snapshot}" && ! -L "${snapshot}" ]] \
        || { printf 'invalid snapshot-validation crash identity\n' >&2; exit 98; }
    /usr/bin/python3 "$@"
    rc=$?
    ((rc == 0)) || exit "${rc}"
    printf 'snapshot-validation-crash:%s\n' "${point}" >>"${root}/commands.log"
    kill -KILL "${PPID}"
    kill -KILL "$$"
}

dispatch_snapshot_validation_cleanup_authority() {
    (($# == 5)) || return 0
    [[ "$1" == -I && "$2" == */deploy/snapshot_payload.py && "$3" == remove-stage &&
       "$4" == "${root}/system/run/pgw/snapshot-validation."* ]] || return 0
    [[ -f "$2" && ! -L "$2" && "$5" == "${EUID}" ]] \
        || { printf 'invalid snapshot-validation cleanup argv\n' >&2; exit 98; }
    if [[ -d "$4" && ! -L "$4" ]]; then
        grant_snapshot_validation_cleanup_authority "$4" "$5"
    fi
}

case "$(basename -- "$0")" in
    systemctl) fake_systemctl "$@" ;;
    nft) fake_nft "$@" ;;
    sysctl) fake_sysctl "$@" ;;
    sqlite3) printf 'ok\n' ;;
    python3)
        dispatch_snapshot_validation_crash "$@"
        dispatch_restore_crash "$@" || true
        dispatch_restore_authority "$@"
        if [[ -f "${root}/fail-snapshot-validation-cleanup" &&
              ! -L "${root}/fail-snapshot-validation-cleanup" &&
              "$(stat -c '%u:%a:%F' "${root}/fail-snapshot-validation-cleanup")" == \
                  "${EUID}:600:regular file" &&
              $# == 5 && "$1" == -I && "$2" == */deploy/snapshot_payload.py &&
              "$3" == remove-stage &&
              "$4" == "${root}/system/run/pgw/snapshot-validation.install."* &&
              "$5" == "${EUID}" ]]; then
            exit 86
        fi
        dispatch_snapshot_validation_cleanup_authority "$@"
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
            # This fake runs as its own process forked from the
            # execute_install_phase subshell, so PPID is only that subshell,
            # not the harness. SIGKILL the harness's real PID (handed down via
            # PGW_HARNESS_PID) so its EXIT trap cannot run and scrub the
            # stage; killing only the subshell would let on_exit auto-recover
            # in-process, which defeats this boundary's separate-recover test.
            kill -KILL "${PGW_HARNESS_PID:?PGW_HARNESS_PID must be set for crash_legacy_sealed}"
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
            restore-authority) grant_restore_authority "${2:-}" ;;
            install-base)
                publish_fake_base
                printf '0\n' >"${root}/runtime/ip-forward"
                ;;
            verify-base)
                grep -q 'table inet pgw_base' "${root}/runtime/ruleset.nft"
                ;;
            wait-api-ready)
                [[ "$(field pgw-api.service 3)" == active ]] || exit 2
                awk -F '\t' '$1 ~ /^pgw-fwd@[0-9]+\.service$/ && $3 == "active" {found=1} END {exit found}' \
                    "${root}/runtime/services" || exit 2
                printf 'api-ready-before-forwarder\n' >>"${root}/commands.log"
                ;;
            *) exit 2 ;;
        esac
        ;;
    install) fake_install "$@" ;;
    chown|systemd-sysusers|systemd-tmpfiles) exit 0 ;;
    *) printf 'unsupported lifecycle fake command\n' >&2; exit 2 ;;
esac
