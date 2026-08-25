#!/bin/bash
# Production never inherits the caller's command search path. This assignment
# is the first body operation and precedes every external command.
readonly SAFE_PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH
set -Eeuo pipefail

installer_sourced=0
[[ "${BASH_SOURCE[0]}" != "$0" ]] && installer_sourced=1

readonly TEST_ENV_VARS=(
    PGW_INSTALL_TEST_MODE PGW_INSTALL_TEST_ROOT PGW_INSTALL_TEST_COMMAND
    PGW_INSTALL_SYSTEM_ROOT PGW_INSTALL_BACKUP_ROOT PGW_RESTORE_FAIL_AT
    PGW_FAIL_AT PGW_FAKE_ROOT PGW_INSTALL_INTERNAL_SOURCE PGW_INTERNAL_TEST_MARKER
    PGW_INTERNAL_PYTHON_BINARY
)
readonly PRODUCTION_OVERRIDE_VARS=(
    PGW_SOURCE_DIR PGW_GO_BINARY PGW_REVIEWED_CHECKOUT PGW_REVIEWED_COMMIT
    BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH
    PGW_UI_TLS_CERT_SOURCE PGW_UI_TLS_KEY_SOURCE PGW_UI_PROXY_TOKEN_SOURCE
    PGW_ADMIN_PASS_FILE
)

trusted_launch=0
developer_dry_run=0
if [[ "${PGW_TRUSTED_LAUNCH:-}" == pgw-release-launcher-v1 ]]; then
    launcher_parent="$(readlink -f -- "/proc/${PPID}/exe" 2>/dev/null || true)"
    if ((EUID == 0)) && [[ "${launcher_parent}" == /usr/local/sbin/pgw-release-launcher ]]; then
        trusted_launch=1
    else
        printf '[pgw-install] ERROR: forged or invalid trusted launcher context\n' >&2
        exit 126
    fi
fi

if ((installer_sourced)); then
    ((EUID != 0)) || { printf '[pgw-install] ERROR: installer library cannot be sourced as root\n' >&2; return 96; }
    [[ "${PGW_INSTALL_INTERNAL_SOURCE:-}" == pgw-nonroot-lifecycle-test-v1 ]] \
        || { printf '[pgw-install] ERROR: invalid internal non-root source context\n' >&2; return 96; }
    [[ -n "${PGW_INTERNAL_TEST_MARKER:-}" && -f "${PGW_INTERNAL_TEST_MARKER}" && ! -L "${PGW_INTERNAL_TEST_MARKER}" ]] \
        || { printf '[pgw-install] ERROR: missing internal non-root test marker\n' >&2; return 96; }
    [[ "$(<"${PGW_INTERNAL_TEST_MARKER}")" == pgw-installer-nonroot-test-v1 ]] \
        || { printf '[pgw-install] ERROR: invalid internal non-root test marker\n' >&2; return 96; }
    [[ "$(stat -c '%u' "${PGW_INTERNAL_TEST_MARKER}")" == "${EUID}" ]] \
        || { printf '[pgw-install] ERROR: internal test marker owner mismatch\n' >&2; return 96; }
    validated_test_root="$(readlink -f -- "${PGW_INSTALL_TEST_ROOT:?}")"
    [[ "${validated_test_root}" != / && -d "${validated_test_root}" && \
       "$(readlink -f -- "${PGW_INTERNAL_TEST_MARKER}")" == "${validated_test_root}/.pgw-installer-source-marker" && \
       "${PGW_INSTALL_SYSTEM_ROOT:?}" == "${validated_test_root}/system" && \
       "${PGW_INSTALL_BACKUP_ROOT:?}" == "${validated_test_root}/backups" ]] \
        || { printf '[pgw-install] ERROR: internal test roots are outside the marked fixture\n' >&2; return 96; }
else
    for test_env_name in "${TEST_ENV_VARS[@]}"; do
        if [[ -v "${test_env_name}" ]]; then
            printf '[pgw-install] ERROR: forbidden test environment: %s\n' "${test_env_name}" >&2
            exit 64
        fi
    done
    for override_name in "${PRODUCTION_OVERRIDE_VARS[@]}"; do
        if [[ -v "${override_name}" ]]; then
            printf '[pgw-install] ERROR: forbidden production override: %s\n' "${override_name}" >&2
            exit 64
        fi
    done
    if ((EUID == 0 && !trusted_launch)); then
        printf '[pgw-install] ERROR: production root execution requires pgw-release-launcher\n' >&2
        exit 126
    fi
    if ((!trusted_launch)); then
        developer_dry_run=1
    fi
fi

if ((installer_sourced)); then
    [[ "${PGW_INTERNAL_PYTHON_BINARY:-}" == "${validated_test_root}/fake-bin/python3" &&
       -x "${PGW_INTERNAL_PYTHON_BINARY}" && ! -L "${PGW_INTERNAL_PYTHON_BINARY}" ]] \
        || { printf '[pgw-install] ERROR: invalid internal Python fixture\n' >&2; return 96; }
    readonly PYTHON3="${PGW_INTERNAL_PYTHON_BINARY}"
else
    readonly PYTHON3=/usr/bin/python3
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
if ((installer_sourced || developer_dry_run)); then
    readonly SOURCE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
else
    readonly SOURCE_DIR=""
    [[ "${PGW_RELEASE_ID:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ && -n "${PGW_RELEASE_FD_MAP:-}" ]] \
        || { printf '[pgw-install] ERROR: invalid trusted release descriptor map\n' >&2; exit 126; }
fi
if ((installer_sourced)); then
    readonly SYSTEM_ROOT="${validated_test_root}/system"
    readonly BACKUP_ROOT="${validated_test_root}/backups"
else
    readonly SYSTEM_ROOT=""
    readonly BACKUP_ROOT="/var/backups/pgw"
fi
readonly UI_ROOT="${SYSTEM_ROOT}/usr/local/share/pgw/web"
readonly LIFECYCLE_LOCK="${SYSTEM_ROOT}/run/pgw-lifecycle.lock"
readonly RECOVERY_ROOT="${SYSTEM_ROOT}/var/lib/pgw-lifecycle"
readonly RECOVERY_JOURNAL="${RECOVERY_ROOT}/recovery.journal"
readonly SERVICES=(nftables.service systemd-sysctl.service pgw-api.service pgw-agent.service pgw-ui.service pgw-health.service)

lan_interface="${PGW_LAN_IFACE:-ens19}"
wan_interface="${PGW_WAN_IFACE:-eth0}"
management_ports="${PGW_MANAGEMENT_TCP_PORTS:-8080,8081}"
lan_address=""
dry_run=0
allow_legacy=0
legacy_state_pending=0
legacy_state_checksum=""
rollback_request=""
backup_dir=""
mutated=0
full_snapshot_recovery=0
state_only_recovery=0
recovery_attempt_failed=0
ui_stage=""
legacy_sealed_stage=""
snapshot_restore_stage=""

log() { printf '[pgw-install] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
host_path() { printf '%s%s\n' "${SYSTEM_ROOT}" "$1"; }
release_file() {
    local relative="$1" entry path fd
    [[ "${relative}" =~ ^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,255}$ && \
       "${relative}" != /* && "${relative}" != *'..'* && "${relative}" != *//* ]] \
        || die "invalid release path: ${relative}"
    if ((installer_sourced || developer_dry_run)); then
        printf '%s/%s\n' "${SOURCE_DIR}" "${relative}"
        return
    fi
    IFS=';' read -r -a release_entries <<<"${PGW_RELEASE_FD_MAP}"
    for entry in "${release_entries[@]}"; do
        path="${entry%%=*}"
        fd="${entry#*=}"
        if [[ "${path}" == "${relative}" && "${fd}" =~ ^[0-9]+$ && 10#${fd} -ge 3 ]]; then
            [[ -f "/proc/self/fd/${fd}" ]] \
                || die "trusted release descriptor is unavailable: ${relative}"
            printf '/proc/self/fd/%s\n' "${fd}"
            return
        fi
    done
    die "release manifest omitted: ${relative}"
}
ensure_directory() {
    local path="$1" mode="$2"
    if [[ -n "${SYSTEM_ROOT}" ]]; then
        mkdir -p "${path}"
        chmod "${mode}" "${path}" 2>/dev/null || true
    else
        install -d -m "${mode}" "${path}"
    fi
}
require_command() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
validate_fixed_python() {
    local resolved
    if ((installer_sourced)); then
        [[ -x "${PYTHON3}" && ! -L "${PYTHON3}" ]] || die "unsafe internal Python fixture"
        return
    fi
    [[ "${PYTHON3}" == /usr/bin/python3 && ! -L /usr && ! -L /usr/bin ]] \
        || die "fixed Python path or ancestor is unsafe"
    resolved="$(readlink -f -- "${PYTHON3}")"
    [[ "${resolved}" =~ ^/usr/bin/python3([.][0-9]+)*$ && -f "${resolved}" && ! -L "${resolved}" ]] \
        || die "fixed Python interpreter target is unsafe"
    [[ "$(stat -c '%U:%G:%a' /usr /usr/bin "${resolved}")" == $'root:root:755\nroot:root:755\nroot:root:755' ]] \
        || die "fixed Python interpreter ownership or mode is unsafe"
}
failure_point() { :; }
restore_failure_point() { :; }

prepare_lifecycle_roots() {
    local expected_uid=0
    ((installer_sourced)) && expected_uid="${EUID}"
    if ((installer_sourced)); then
        mkdir -p "${BACKUP_ROOT}" "${BACKUP_ROOT}/key-sequences" "${RECOVERY_ROOT}"
        chmod 0700 "${BACKUP_ROOT}" "${BACKUP_ROOT}/key-sequences" "${RECOVERY_ROOT}" 2>/dev/null || true
        return
    fi
    "${PYTHON3}" -I - "${BACKUP_ROOT}" "${BACKUP_ROOT}/key-sequences" "${RECOVERY_ROOT}" "${expected_uid}" <<'PY'
import os, stat, sys
expected=int(sys.argv[4])
for target in sys.argv[1:4]:
    if not os.path.isabs(target) or os.path.normpath(target)!=target: raise SystemExit("unsafe lifecycle root path")
    parts=[p for p in target.split(os.sep) if p]; fd=os.open(os.sep,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for index,part in enumerate(parts):
            try: nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part,0o700,dir_fd=fd); nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            st=os.fstat(nxt)
            if st.st_uid!=expected or st.st_mode&0o022 or not stat.S_ISDIR(st.st_mode): raise SystemExit("unsafe lifecycle ancestor")
            os.close(fd); fd=nxt
        os.chmod(target,0o700)
        os.fsync(fd)
    finally: os.close(fd)
PY
}

recovery_journal_auth() {
    local operation="$1" journal_path="$2" key expected_uid=0
    key="$(host_path /etc/pgw/snapshot.hmac)"
    ((installer_sourced)) && expected_uid="${EUID}"
    "${PYTHON3}" -I - "${operation}" "${journal_path}" "${key}" "${expected_uid}" <<'PY'
import hashlib,hmac,os,stat,sys
operation,path,key_path,expected_arg=sys.argv[1:]
expected=int(expected_arg); maximum=4096
if expected:
    # The sourced harness has already descriptor/prefix-validated its isolated
    # non-root fixture.  Normalize MSYS path spelling before local checks.
    path=os.path.abspath(path); key_path=os.path.abspath(key_path)
portable=not hasattr(os,"O_DIRECTORY")
def read_secure(path, expected_mode, limit):
    if portable:
        info=os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:
            raise SystemExit("unsafe journal auth file")
        with open(path,"rb") as handle: data=handle.read(limit+1)
        if len(data)>limit: raise SystemExit("recovery journal exceeds bound")
        return data,None,None,None
    if not os.path.isabs(path) or os.path.normpath(path)!=path: raise SystemExit("unsafe journal auth path")
    parts=[part for part in path.split(os.sep) if part]
    def identity(info):
        return (info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode),stat.S_IMODE(info.st_mode),
                info.st_uid,info.st_gid,info.st_size,info.st_nlink,info.st_mtime_ns,info.st_ctime_ns)
    parent=os.open(os.sep,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            info=os.fstat(child)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,expected) or info.st_mode&0o022:
                os.close(child); raise SystemExit("unsafe journal auth ancestor")
            os.close(parent); parent=child
        before=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
        descriptor=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        info=os.fstat(descriptor)
        if (identity(info)!=identity(before) or not stat.S_ISREG(info.st_mode) or info.st_uid!=expected
                or stat.S_IMODE(info.st_mode)!=expected_mode or info.st_size>limit):
            os.close(descriptor); raise SystemExit("unsafe journal auth file")
        try:
            data=b""
            while True:
                chunk=os.read(descriptor,min(65536,limit+1-len(data)))
                if not chunk: break
                data+=chunk
                if len(data)>limit: raise SystemExit("recovery journal exceeds bound")
            finished=os.fstat(descriptor)
            rebound=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
            if (finished.st_size!=len(data) or identity(finished)!=identity(info)
                    or identity(rebound)!=identity(info)):
                raise SystemExit("recovery journal changed while reading")
        finally: os.close(descriptor)
        return data,parent,parts[-1],identity(info)
    except BaseException:
        os.close(parent)
        raise
key, key_parent, _, _=read_secure(key_path,0o600,4096)
if key_parent is not None: os.close(key_parent)
if len(key)<32: raise SystemExit("invalid snapshot HMAC key")
data,parent,name,opened_identity=read_secure(path,0o600,maximum)
try:
    if operation=="create":
        if b"\nauth=" in data or data.startswith(b"auth=") or not data.endswith(b"\n"):
            raise SystemExit("invalid unsealed recovery journal")
        digest=hmac.new(key,data,hashlib.sha256).hexdigest().encode("ascii")
        if portable:
            with open(path,"ab") as handle:
                handle.write(b"auth="+digest+b"\n"); handle.flush(); os.fsync(handle.fileno())
        else:
            descriptor=os.open(name,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW,dir_fd=parent)
            try:
                current=os.fstat(descriptor)
                current_identity=(current.st_dev,current.st_ino,stat.S_IFMT(current.st_mode),stat.S_IMODE(current.st_mode),
                                  current.st_uid,current.st_gid,current.st_size,current.st_nlink,current.st_mtime_ns,current.st_ctime_ns)
                if current_identity!=opened_identity: raise SystemExit("recovery journal changed before sealing")
                os.write(descriptor,b"auth="+digest+b"\n"); os.fsync(descriptor)
            finally: os.close(descriptor)
    elif operation=="verify":
        lines=data.splitlines(keepends=True)
        if not lines or not lines[-1].startswith(b"auth=") or not lines[-1].endswith(b"\n"):
            raise SystemExit("unauthenticated recovery journal")
        supplied=lines[-1][5:-1]
        if len(supplied)!=64 or any(byte not in b"0123456789abcdef" for byte in supplied):
            raise SystemExit("invalid recovery journal authentication")
        body=b"".join(lines[:-1])
        expected_mac=hmac.new(key,body,hashlib.sha256).hexdigest().encode("ascii")
        if not hmac.compare_digest(supplied,expected_mac):
            raise SystemExit("recovery journal authentication failed")
    else: raise SystemExit("invalid recovery journal auth operation")
finally:
    if parent is not None: os.close(parent)
PY
}

write_recovery_journal() {
    local phase="$1" temporary state_hash=""
    [[ -n "${backup_dir}" && "${backup_dir}" == "${BACKUP_ROOT}"/install.* ]] || die "unsafe journal snapshot path"
    temporary="$(mktemp "${RECOVERY_ROOT}/.recovery.XXXXXXXX")"
    if [[ "${phase}" == capturing ]]; then
        state_hash="$({ sha256sum "${backup_dir}/services" "${backup_dir}/forwarders" \
            "${backup_dir}/runtime-ruleset.nft" "${backup_dir}/ip-forward"; } | sha256sum | awk '{print $1}')"
        [[ "${state_hash}" =~ ^[0-9a-f]{64}$ ]] || die "invalid capture state digest"
    fi
    printf 'version=1\nphase=%s\nsnapshot=%s\n' "${phase}" "${backup_dir}" >"${temporary}"
    [[ -z "${state_hash}" ]] || printf 'state_hash=%s\n' "${state_hash}" >>"${temporary}"
    chmod 0600 "${temporary}"
    recovery_journal_auth create "${temporary}"
    sync -f "${temporary}"
    mv -Tf -- "${temporary}" "${RECOVERY_JOURNAL}"
    sync -f "${RECOVERY_ROOT}"
}

write_restore_progress() {
    local state="$1" path="$2" restore_phase="$3" operation_id temporary
    [[ "${state}" == present || "${state}" == absent ]] || die "invalid restore journal state"
    [[ "${restore_phase}" == prepared || "${restore_phase}" == applied ]] || die "invalid restore journal phase"
    grep -Fxq "${state}"$'\t'"${path}" "${backup_dir}/manifest" || die "restore journal path is outside authenticated manifest"
    operation_id="$(restore_operation_id "${state}" "${path}")"
    [[ "${operation_id}" =~ ^[0-9a-f]{64}$ ]] || die "invalid restore operation identifier"
    temporary="$(mktemp "${RECOVERY_ROOT}/.recovery.XXXXXXXX")"
    printf 'version=1\nphase=restoring\nsnapshot=%s\nrestore_state=%s\nrestore_path=%s\nrestore_phase=%s\noperation_id=%s\n' \
        "${backup_dir}" "${state}" "${path}" "${restore_phase}" "${operation_id}" >"${temporary}"
    chmod 0600 "${temporary}"
    recovery_journal_auth create "${temporary}"
    ((installer_sourced)) || sync -f "${temporary}"
    mv -Tf -- "${temporary}" "${RECOVERY_JOURNAL}"
    ((installer_sourced)) || sync -f "${RECOVERY_ROOT}"
}

restore_operation_id() {
    local state="$1" path="$2"
    # The ciphertext payload manifest is HMAC-covered before any restore stage
    # exists. A stage metadata file is derived anew in private /run and must
    # never become the recovery journal's authority.
    { cat "${backup_dir}/payload.manifest.json"; printf '\0%s\0%s' "${path}" "${state}"; } | sha256sum | awk '{print $1}'
}

clear_recovery_journal() {
    rm -f -- "${RECOVERY_JOURNAL}"
    sync -f "${RECOVERY_ROOT}"
}

recover_interrupted_lifecycle() {
    local phase snapshot key value expected_id restore_rc
    local -A journal=()
    [[ -e "${RECOVERY_JOURNAL}" ]] || return 0
    # Any durable recovery marker means a prior privileged lifecycle may have
    # crossed its mutation boundary.  Until its authenticated mode is parsed,
    # an error must fail closed rather than leave the prior runtime running.
    mutated=1
    full_snapshot_recovery=0
    state_only_recovery=0
    [[ -f "${RECOVERY_JOURNAL}" && ! -L "${RECOVERY_JOURNAL}" && \
       "$(stat -c '%a:%u' "${RECOVERY_JOURNAL}")" == "600:$((installer_sourced ? EUID : 0))" ]] \
        || die "CRITICAL: unsafe lifecycle recovery journal"
    recovery_journal_auth verify "${RECOVERY_JOURNAL}" \
        || die "CRITICAL: unauthenticated lifecycle recovery journal"
    while IFS='=' read -r key value; do
        case "${key}" in
            version|phase|snapshot|state_hash|restore_state|restore_path|restore_phase|operation_id|auth) ;;
            *) die "CRITICAL: invalid lifecycle recovery journal key" ;;
        esac
        [[ ! -v "journal[${key}]" ]] || die "CRITICAL: duplicate lifecycle recovery journal key"
        journal["${key}"]="${value}"
    done <"${RECOVERY_JOURNAL}"
    [[ "${journal[version]:-}" == 1 && -n "${journal[phase]:-}" && \
       "${journal[snapshot]:-}" == "${BACKUP_ROOT}"/install.* ]] || die "CRITICAL: invalid lifecycle recovery journal"
    phase="${journal[phase]}"; snapshot="${journal[snapshot]}"
    backup_dir="${snapshot}"
    case "${phase}" in
        ready|after_*)
            [[ "${#journal[@]}" == 4 ]] || die "CRITICAL: unexpected lifecycle journal fields"
            full_snapshot_recovery=1
            state_only_recovery=0
            mutated=1
            validate_rollback_snapshot "${snapshot}"
            set +e
            ( set -Eeuo pipefail; restore_snapshot preserve )
            restore_rc=$?
            set -e
            if ((restore_rc != 0)); then
                recovery_attempt_failed=1
                die "CRITICAL: interrupted lifecycle restore failed; services remain quiesced"
            fi
            # Keep the authenticated journal until every exact /run cleanup
            # succeeds. A malformed report/stage leaves durable recovery
            # evidence and forwarding closed for the next startup.
            if ! cleanup_legacy_import_runtime ||
               ! remove_legacy_sealed_stage_for_snapshot "${snapshot}" ||
               ! restore_saved_forwarding_final ||
               ! clear_recovery_journal; then
                recovery_attempt_failed=1
                force_forwarding_off || true
                die "CRITICAL: interrupted legacy cleanup failed; services remain quiesced"
            fi
            mutated=0
            full_snapshot_recovery=0
            log "recovered interrupted lifecycle from authenticated snapshot"
            ;;
        restoring)
            [[ "${#journal[@]}" == 8 && ("${journal[restore_state]:-}" == present || "${journal[restore_state]:-}" == absent) && \
               ("${journal[restore_phase]:-}" == prepared || "${journal[restore_phase]:-}" == applied) ]] \
                || die "CRITICAL: invalid restore progress journal"
            full_snapshot_recovery=1
            state_only_recovery=0
            mutated=1
            validate_rollback_snapshot "${snapshot}"
            grep -Fxq "${journal[restore_state]}"$'\t'"${journal[restore_path]:-}" "${backup_dir}/manifest" \
                || die "CRITICAL: restore progress is outside authenticated manifest"
            expected_id="$(restore_operation_id "${journal[restore_state]}" "${journal[restore_path]}")"
            [[ "${journal[operation_id]:-}" == "${expected_id}" ]] || die "CRITICAL: restore progress authentication mismatch"
            set +e
            ( set -Eeuo pipefail; restore_snapshot preserve )
            restore_rc=$?
            set -e
            if ((restore_rc != 0)); then
                recovery_attempt_failed=1
                die "CRITICAL: interrupted per-path restore failed; services remain quiesced"
            fi
            if ! cleanup_legacy_import_runtime ||
               ! remove_legacy_sealed_stage_for_snapshot "${snapshot}" ||
               ! restore_saved_forwarding_final ||
               ! clear_recovery_journal; then
                recovery_attempt_failed=1
                force_forwarding_off || true
                die "CRITICAL: interrupted legacy cleanup failed; services remain quiesced"
            fi
            mutated=0
            full_snapshot_recovery=0
            log "recovered interrupted deterministic restore operation"
            ;;
        capturing)
            [[ "${#journal[@]}" == 5 && "${journal[state_hash]:-}" =~ ^[0-9a-f]{64}$ ]] \
                || die "CRITICAL: unexpected capture journal fields"
            expected_id="$({ sha256sum "${snapshot}/services" "${snapshot}/forwarders" \
                "${snapshot}/runtime-ruleset.nft" "${snapshot}/ip-forward"; } | sha256sum | awk '{print $1}')"
            [[ "${journal[state_hash]}" == "${expected_id}" ]] \
                || die "CRITICAL: capture state evidence authentication mismatch"
            mutated=1
            if [[ -e "${snapshot}/snapshot.sha256" || -e "${snapshot}/snapshot.hmac" ]]; then
                [[ -f "${snapshot}/snapshot.sha256" && -f "${snapshot}/snapshot.hmac" ]] \
                    || die "CRITICAL: capture seal is incomplete; runtime remains fail-closed"
                full_snapshot_recovery=1
                state_only_recovery=0
                validate_rollback_snapshot "${snapshot}"
                set +e
                ( set -Eeuo pipefail; restore_snapshot )
                restore_rc=$?
                set -e
                if ((restore_rc != 0)); then
                    recovery_attempt_failed=1
                    die "CRITICAL: sealed capture restore failed; services remain quiesced"
                fi
                log "recovered sealed capture before ready publication"
            else
                full_snapshot_recovery=0
                state_only_recovery=1
                restore_capture_state_only \
                    || die "CRITICAL: interrupted capture state recovery failed; runtime remains fail-closed"
                log "recovered interrupted pre-ready capture from runtime-state evidence only"
            fi
            mutated=0
            full_snapshot_recovery=0
            state_only_recovery=0
            ;;
        *) die "CRITICAL: unknown lifecycle recovery phase" ;;
    esac
}

snapshot_auth() {
    local operation="$1" snapshot="$2" key
    key="$(host_path /etc/pgw/snapshot.hmac)"
    if ((installer_sourced)); then
        "${PYTHON3}" -I - "${operation}" "${snapshot}" "${key}" <<'PY'
import hashlib,hmac,os,sys
operation,root,key_path=sys.argv[1:]
key=open(key_path,"rb").read()
if len(key)<32: raise SystemExit("invalid test HMAC key")
if operation=="keycheck": raise SystemExit(0)
payload=open(os.path.join(root,"snapshot.sha256"),"rb").read()
digest=hmac.new(key,payload,hashlib.sha256).hexdigest()+"\n"; auth=os.path.join(root,"snapshot.hmac")
if operation=="create": open(auth,"w",encoding="ascii").write(digest)
elif operation=="verify":
    if not hmac.compare_digest(open(auth,encoding="ascii").read(),digest): raise SystemExit("snapshot authentication failed")
else: raise SystemExit("invalid operation")
PY
        return
    fi
    "${PYTHON3}" -I - "${operation}" "${snapshot}" "${key}" <<'PY'
import hashlib,hmac,os,stat,sys,tempfile
operation,root,key_path=sys.argv[1:]
expected=0 if not os.environ.get("PGW_INSTALL_INTERNAL_SOURCE") else os.geteuid()
def secure_open(path,mode,max_size):
    if not os.path.isabs(path) or os.path.normpath(path)!=path: raise SystemExit("unsafe auth path")
    parts=[p for p in path.split(os.sep) if p]; parent=os.open(os.sep,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent); st=os.fstat(nxt)
            if st.st_uid!=expected or st.st_mode&0o022 or not stat.S_ISDIR(st.st_mode): raise SystemExit("unsafe auth ancestor")
            os.close(parent); parent=nxt
        fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent); st=os.fstat(fd)
        if st.st_uid!=expected or stat.S_IMODE(st.st_mode)!=mode or not stat.S_ISREG(st.st_mode) or st.st_size>max_size:
            os.close(fd); raise SystemExit("unsafe auth file")
        return fd
    finally: os.close(parent)
key_fd=secure_open(key_path,0o600,4096)
try:
    key=os.read(key_fd,4097)
finally: os.close(key_fd)
if len(key)<32 or len(key)>4096: raise SystemExit("invalid snapshot HMAC key")
if operation=="keycheck": raise SystemExit(0)
payload_path=os.path.join(root,"snapshot.sha256")
payload_fd=secure_open(payload_path,0o600,1024*1024)
try:
    payload=b""
    while True:
        chunk=os.read(payload_fd,65536)
        if not chunk: break
        payload+=chunk
finally: os.close(payload_fd)
digest=hmac.new(key,payload,hashlib.sha256).hexdigest()+"\n"
auth_path=os.path.join(root,"snapshot.hmac")
if operation=="create":
    temporary=os.path.join(root,".snapshot.hmac.tmp")
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try: os.write(fd,digest.encode()); os.fsync(fd)
    finally: os.close(fd)
    os.replace(temporary,auth_path)
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(directory)
    finally: os.close(directory)
elif operation=="verify":
    auth_fd=secure_open(auth_path,0o600,256)
    try: actual=os.read(auth_fd,257).decode()
    finally: os.close(auth_fd)
    if not hmac.compare_digest(actual,digest): raise SystemExit("snapshot authentication failed")
else: raise SystemExit("invalid snapshot auth operation")
PY
}

fsync_snapshot_tree() {
    if ((installer_sourced)); then
        local fixture_path
        for fixture_path in services forwarders runtime-ruleset.nft ip-forward source-units.sha256 manifest payload.manifest.json snapshot.sha256 snapshot.hmac; do
            [[ ! -f "${backup_dir}/${fixture_path}" ]] || sync -f "${backup_dir}/${fixture_path}"
        done
        sync -f "${backup_dir}"
        return
    fi
    "${PYTHON3}" -I - "${backup_dir}" "${BACKUP_ROOT}" <<'PY'
import os,stat,sys
root,backup_root=sys.argv[1:]
for base,dirs,files in os.walk(root,topdown=False,followlinks=False):
    for name in files:
        path=os.path.join(base,name); st=os.lstat(path)
        if not stat.S_ISREG(st.st_mode): continue
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
fd=os.open(backup_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try: os.fsync(fd)
finally: os.close(fd)
PY
}
valid_forwarder_unit() {
    local unit="$1" port
    [[ "${unit}" =~ ^pgw-fwd@([0-9]+)\.service$ ]] || return 1
    port="${BASH_REMATCH[1]}"
    ((10#${port} >= 15001 && 10#${port} <= 15999))
}

enumerate_forwarder_units() {
    {
        systemctl list-units --all --type=service --no-legend 'pgw-fwd@*.service' 2>/dev/null | awk '{print $1}'
        systemctl list-unit-files --no-legend 'pgw-fwd@*.service' 2>/dev/null | awk '{print $1}'
    } | while IFS= read -r unit; do
        valid_forwarder_unit "${unit}" && printf '%s\n' "${unit}"
    done | sort -u
}

wait_unit_stopped() {
    local unit="$1" deadline=$((SECONDS + 35))
    systemctl --no-block stop "${unit}"
    while systemctl is-active --quiet "${unit}"; do
        ((SECONDS < deadline)) || die "timed out draining ${unit}"
        sleep 1
    done
}

quiesce_runtime() {
    local unit
    if systemctl is-active --quiet pgw-agent.service; then
        wait_unit_stopped pgw-agent.service
    fi
    while IFS= read -r unit; do
        [[ -n "${unit}" ]] && wait_unit_stopped "${unit}"
    done < <(enumerate_forwarder_units)
    for unit in pgw-ui.service pgw-health.service pgw-api.service; do
        if systemctl is-active --quiet "${unit}"; then
            wait_unit_stopped "${unit}"
        fi
    done
    while IFS= read -r unit; do
        [[ -z "${unit}" ]] || ! systemctl is-active --quiet "${unit}" || die "forwarder remained active: ${unit}"
    done < <(enumerate_forwarder_units)
}
force_forwarding_off() {
    sysctl -q -w net.ipv4.ip_forward=0
    [[ "$(sysctl -n net.ipv4.ip_forward)" == 0 ]] || die "failed to force IPv4 forwarding off"
}
validate_tls_pair() {
    local certificate="$1" private_key="$2" cert_fp key_fp
    openssl x509 -noout -in "${certificate}" >/dev/null 2>&1 || die "invalid UI TLS certificate"
    openssl pkey -noout -in "${private_key}" >/dev/null 2>&1 || die "invalid UI TLS private key"
    cert_fp="$(openssl x509 -in "${certificate}" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
    key_fp="$(openssl pkey -in "${private_key}" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
    [[ -n "${cert_fp}" && "${cert_fp}" == "${key_fp}" ]] || die "UI TLS certificate/private key mismatch"
}

usage() {
    cat <<'EOF'
Usage: install-pgw.sh [--dry-run] [--migrate-legacy] [--lan IFACE] [--wan IFACE]
       install-pgw.sh --rollback /var/backups/pgw/install.XXXXXXXX

Fresh installs are fail-close. Existing legacy pgw units/sudoers are rejected
unless --migrate-legacy is explicit and all migration preflight checks pass.
EOF
}

parse_arguments() {
    while (($#)); do
        case "$1" in
            --dry-run) dry_run=1; shift ;;
            --rollback)
                (($# >= 2)) || die "--rollback requires a snapshot path"
                rollback_request="$2"
                shift 2
                ;;
            --migrate-legacy) allow_legacy=1; shift ;;
            --lan|--wan)
                (($# >= 2)) || die "$1 requires a value"
                [[ "$1" == --lan ]] && lan_interface="$2" || wan_interface="$2"
                shift 2
                ;;
            --help|-h) usage; exit 0 ;;
            *) die "unknown argument: $1" ;;
        esac
    done
}

validate_source() {
    local required source unit
    for required in \
        deploy/install-pgw-base.sh deploy/pgw-verify-base.sh deploy/pgw-verify-ui-bind.sh deploy/restore_snapshot.py deploy/snapshot_payload.py deploy/nftables.conf \
        deploy/sysusers.d/pgw.conf deploy/tmpfiles.d/pgw.conf \
        deploy/polkit-1/rules.d/50-pgw-agent-forwarder.rules \
        deploy/systemd/pgw-api.service deploy/systemd/pgw-agent.service \
        deploy/systemd/pgw-fwd@.service deploy/systemd/pgw-ui.service \
        deploy/systemd/pgw-health.service \
        deploy/ui-assets.sha256 web/static/app.js web/static/styles.css \
        web/static/login.js web/static/layout.css \
        deploy/systemd/nftables.service.d/pgw.conf \
        deploy/systemd/systemd-sysctl.service.d/pgw.conf; do
        source="$(release_file "${required}")"
        [[ -f "${source}" ]] || die "missing deployment source: ${required}"
    done
    [[ "${lan_interface}" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || die "invalid LAN interface"
    [[ "${wan_interface}" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || die "invalid WAN interface"
    [[ "${lan_interface}" != "${wan_interface}" ]] || die "LAN and WAN interfaces must differ"
    [[ "${management_ports}" =~ ^[0-9]+(,[0-9]+)*$ ]] || die "invalid management ports"
    [[ ",${management_ports}," != *",9090,"* ]] || die "Agent port 9090 must remain loopback-only"
    for unit in pgw-api.service pgw-agent.service pgw-fwd@.service pgw-ui.service pgw-health.service; do
        ! grep -qsE 'NOPASSWD:.*systemctl|User=pgw$|Group=pgw$' "$(release_file "deploy/systemd/${unit}")" \
            || die "deployment source contains a legacy broad privilege contract"
    done
    ! grep -qs 'pgw_dynamic' "$(release_file deploy/nftables.conf)" \
        || die "boot nftables config must never persist pgw_dynamic"
    verify_ui_source_manifest || die "UI source asset manifest validation failed"
}

verify_ui_source_manifest() {
    local manifest expected relative actual seen=0
    manifest="$(release_file deploy/ui-assets.sha256)"
    while read -r expected relative; do
        [[ "${expected}" =~ ^[0-9a-f]{64}$ && "${relative}" =~ ^web/static/(app\.js|styles\.css|login\.js|layout\.css)$ ]] || return 1
        actual="$(sha256sum "$(release_file "${relative}")" | awk '{print $1}')"
        [[ "${actual}" == "${expected}" ]] || return 1
        ((seen += 1))
    done <"${manifest}"
    [[ "${seen}" == 4 ]]
}

preflight_legacy_state() {
    local state api_binary report
    state="$(host_path /var/lib/pgw/state.json)"
    [[ -f "${state}" && ! -L "${state}" ]] || die "legacy state path is unsafe"
    ((allow_legacy)) || die "legacy state.json detected; rerun with --migrate-legacy after reviewing the migration backup"
    api_binary="$(release_file artifacts/pgw-api)"
    [[ -x "${api_binary}" && ! -L "${api_binary}" ]] || die "staged pgw-api migration binary is unavailable"
    # This runs against an ephemeral SQLite store and cannot create a host
    # database or read the master key before rollback capture.
    report="$("${api_binary}" import-legacy-state --file "${state}" --dry-run)" \
        || die "legacy state dry-run validation failed"
    legacy_state_checksum="$("${PYTHON3}" -I - "${report}" <<'PY'
import json,re,sys
try:
    value=json.loads(sys.argv[1])
except (ValueError, TypeError):
    raise SystemExit(1)
checksum=value.get("checksum") if isinstance(value,dict) and value.get("dry_run") is True else ""
if not isinstance(checksum,str) or not re.fullmatch(r"[0-9a-f]{64}",checksum): raise SystemExit(1)
print(checksum)
PY
)" || die "legacy state dry-run report is invalid"
    legacy_state_pending=1
    log "legacy state dry-run passed; import is deferred until the rollback snapshot is sealed"
}

detect_legacy() {
    local legacy=0 unit
    [[ ! -e "$(host_path /etc/sudoers.d/pgw)" ]] || legacy=1
    [[ ! -e "$(host_path /etc/systemd/system/pgw-webhook.service)" ]] || legacy=1
    for unit in pgw-api pgw-agent pgw-ui pgw-health; do
        if [[ -f "$(host_path "/etc/systemd/system/${unit}.service")" ]] && grep -Eq '^(User|Group)=pgw$' "$(host_path "/etc/systemd/system/${unit}.service")"; then
            legacy=1
        fi
    done
    if ((legacy && !allow_legacy)); then
        die "legacy production layout detected; rerun with --migrate-legacy after reviewing the migration backup"
    fi
    if [[ -e "$(host_path /var/lib/pgw/state.json)" ]]; then
        preflight_legacy_state
    fi
}

validate_host() {
    [[ "${EUID}" -eq 0 ]] || die "installation requires root"
    local command_name
    for command_name in install systemctl systemd-sysusers systemd-tmpfiles nft ip sysctl sha256sum cmp awk grep find stat openssl flock tac readlink cp mktemp getent tr curl mv sed sync sort sleep; do
        require_command "${command_name}"
    done
    validate_fixed_python
    ip link show dev "${lan_interface}" >/dev/null 2>&1 || die "missing LAN interface: ${lan_interface}"
    ip link show dev "${wan_interface}" >/dev/null 2>&1 || die "missing WAN interface: ${wan_interface}"
    mapfile -t lan_addresses < <(ip -4 -o addr show dev "${lan_interface}" scope global | awk '{sub(/\/.*/,"",$4); print $4}')
    [[ "${#lan_addresses[@]}" == 1 ]] || die "LAN interface must have exactly one global IPv4 management address"
    lan_address="${lan_addresses[0]}"
    "${PYTHON3}" -I - "${lan_address}" <<'PY' || die "invalid LAN management IPv4 address"
import ipaddress, sys
value=ipaddress.ip_address(sys.argv[1])
if value.version != 4 or value.is_unspecified or value.is_loopback or value.is_multicast: raise SystemExit(1)
PY
    detect_legacy
    if [[ -f /etc/systemd/system/pgw-agent.service ]] && grep -q '^User=pgw-agent$' /etc/systemd/system/pgw-agent.service; then
        local account group_name secret_path mode owner
        for account in pgw-api pgw-agent pgw-fwd pgw-ui pgw-health; do id "${account}" >/dev/null 2>&1 || die "missing service account: ${account}"; done
        for group_name in pgw-control pgw-config pgw-fwd; do getent group "${group_name}" >/dev/null || die "missing purpose group: ${group_name}"; done
        id -nG pgw-agent | tr ' ' '\n' | grep -qx pgw-fwd || die "pgw-agent is not a pgw-fwd group member"
        id -nG pgw-agent | tr ' ' '\n' | grep -qx pgw-control || die "pgw-agent is not a pgw-control group member"
        for secret_path in jwt_secret agent.token secrets.key admin_pass_hash; do
            [[ -f "/etc/pgw/${secret_path}" && ! -L "/etc/pgw/${secret_path}" ]] || die "missing or unsafe credential source: ${secret_path}"
            mode="$(stat -c '%a' "/etc/pgw/${secret_path}")"
            owner="$(stat -c '%U:%G' "/etc/pgw/${secret_path}")"
            [[ "${mode}" == 600 && "${owner}" == root:root ]] || die "unsafe credential owner/mode: ${secret_path}"
        done
        [[ "$(stat -c '%s' /etc/pgw/jwt_secret)" -ge 32 ]] || die "JWT credential is too short"
        [[ "$(stat -c '%s' /etc/pgw/agent.token)" -gt 0 ]] || die "Agent credential is empty"
        case "$(stat -c '%s' /etc/pgw/secrets.key)" in 32|64|65) ;; *) die "AES key credential has invalid length" ;; esac
        grep -q '^\$argon2id\$v=19\$' /etc/pgw/admin_pass_hash || die "admin PHC credential is invalid"
        if [[ -L /etc/pgw/credentials-current ]]; then
            validate_tls_pair /etc/pgw/credentials-current/ui.crt /etc/pgw/credentials-current/ui.key
            [[ "$(stat -c '%s' /etc/pgw/credentials-current/ui_proxy_token)" -ge 32 ]] \
                || die "UI proxy identity credential is too short"
        elif [[ -f /etc/pgw/ui.crt && -f /etc/pgw/ui.key && -f /etc/pgw/ui_proxy_token ]]; then
            validate_tls_pair /etc/pgw/ui.crt /etc/pgw/ui.key
            [[ "$(stat -c '%s' /etc/pgw/ui_proxy_token)" -ge 32 ]] \
                || die "legacy UI proxy identity credential is too short"
        else
            die "missing atomic UI credential generation"
        fi
    fi
    if [[ -f /var/lib/pgw/pgw.db ]]; then
        require_command sqlite3
        [[ "$(sqlite3 /var/lib/pgw/pgw.db 'PRAGMA integrity_check;')" == ok ]] || die "SQLite integrity preflight failed"
    fi
    snapshot_auth keycheck "${BACKUP_ROOT}"
}

record_backup_path() {
    local logical="$1" path
    path="$(host_path "${logical}")"
    if [[ -e "${path}" || -L "${path}" ]]; then
        printf 'present\t%s\n' "${logical}" >>"${backup_dir}/manifest"
    else
        printf 'absent\t%s\n' "${logical}" >>"${backup_dir}/manifest"
    fi
}

capture_snapshot_payload() {
    local source_root="${SYSTEM_ROOT:-/}" key key_id helper release_id ledger_name ledger expected_owner=0
    key="$(host_path /etc/pgw/snapshot-encryption.key)"
    key_id="$(host_path /etc/pgw/snapshot-encryption.key.id)"
    helper="$(release_file artifacts/pgw-snapshot-crypt)"
    release_id="${PGW_RELEASE_ID:-$(basename -- "${backup_dir}")}"
    if ((installer_sourced)); then
        [[ -f "${key}" && ! -L "${key}" && -f "${key_id}" && ! -L "${key_id}" ]] \
            || die "missing or unsafe independently provisioned snapshot encryption key"
    else
        [[ -f "${key}" && ! -L "${key}" && "$(stat -c '%u:%a:%F' "${key}")" == "${expected_owner}:600:regular file" && \
           -f "${key_id}" && ! -L "${key_id}" && "$(stat -c '%u:%a:%F' "${key_id}")" == "${expected_owner}:600:regular file" ]] \
            || die "missing or unsafe independently provisioned snapshot encryption key"
    fi
    [[ -x "${helper}" && ! -L "${helper}" ]] || die "snapshot encryption helper is unavailable"
    [[ "$(<"${key_id}")" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] \
        || die "snapshot encryption key ID is invalid"
    ledger_name="$(printf '%s' "$(<"${key_id}")" | sha256sum | awk '{print $1}')"
    [[ "${ledger_name}" =~ ^[0-9a-f]{64}$ ]] || die "could not derive snapshot key sequence ledger"
    ledger="${BACKUP_ROOT}/key-sequences/key-sequence-${ledger_name}.json"
    "${PYTHON3}" -I "$(release_file deploy/snapshot_payload.py)" capture \
        "${backup_dir}" "${source_root}" "${key}" "$(<"${key_id}")" "${helper}" "$(basename -- "${backup_dir}")" "${release_id}" "${ledger}"
}

verify_snapshot_payload() {
    local key helper
    key="$(host_path /etc/pgw/snapshot-encryption.key)"
    helper="$(release_file artifacts/pgw-snapshot-crypt)"
    "${PYTHON3}" -I "$(release_file deploy/snapshot_payload.py)" verify "${backup_dir}" "${key}" "${helper}"
}

write_snapshot_metadata() {
    local checksum_temporary
    # Bounded object-set, receipt, and authenticated-ciphertext verification is
    # the publication gate. Only the verified payload manifest is then covered
    # by the checksum/HMAC seal and ready recovery journal.
    verify_snapshot_payload || die "rollback ciphertext payload self-check failed"
    checksum_temporary="${backup_dir}/.snapshot.sha256.tmp"
    sha256sum "${backup_dir}/manifest" "${backup_dir}/services" "${backup_dir}/forwarders" \
        "${backup_dir}/runtime-ruleset.nft" "${backup_dir}/ip-forward" \
        "${backup_dir}/payload.manifest.json" "${backup_dir}/source-units.sha256" >"${checksum_temporary}"
    chmod 0600 "${backup_dir}"/{manifest,services,forwarders,runtime-ruleset.nft,ip-forward,source-units.sha256,payload.manifest.json} \
        "${checksum_temporary}"
    sync -f "${checksum_temporary}"
    mv -Tf -- "${checksum_temporary}" "${backup_dir}/snapshot.sha256"
    sync -f "${backup_dir}"
    snapshot_auth create "${backup_dir}"
    fsync_snapshot_tree
}

verify_snapshot() {
    local mode="$1"
    snapshot_auth verify "${backup_dir}" || return 1
    (cd -- "${backup_dir}" && sha256sum -c snapshot.sha256 >/dev/null) || return 1
    verify_snapshot_payload
}

remove_snapshot_stage() {
    local stage="$1" expected_uid=0
    ((installer_sourced)) && expected_uid="${EUID}"
    "${PYTHON3}" -I "$(release_file deploy/snapshot_payload.py)" remove-stage "${stage}" "${expected_uid}"
}

# A legacy migration materializes plaintext only in this deterministic private
# /run stage. The authenticated recovery journal binds the snapshot identity;
# derive the one permissible cleanup target from that identity rather than
# scanning /run or accepting a caller-provided path.
remove_legacy_sealed_stage_for_snapshot() {
    local snapshot="$1" snapshot_name stage
    [[ "${snapshot}" == "${BACKUP_ROOT}"/install.* && -d "${snapshot}" && ! -L "${snapshot}" ]] \
        || return 1
    snapshot_name="$(basename -- "${snapshot}")"
    [[ "${snapshot_name}" =~ ^install[.][A-Za-z0-9]+$ ]] || return 1
    stage="$(host_path "/run/pgw/legacy-sealed.${snapshot_name}")"
    [[ "${stage}" == "$(host_path /run/pgw)/legacy-sealed.${snapshot_name}" ]] \
        || return 1
    [[ -e "${stage}" || -L "${stage}" ]] || return 0
    remove_snapshot_stage "${stage}"
}

atomic_restore_path() {
    local state="$1" source="$2" target="$3" metadata="$4" logical="$5" expected_uid=0
    [[ -n "${snapshot_restore_stage}" &&
       "${snapshot_restore_stage}" == "$(host_path /run/pgw)/snapshot-restore.install."* &&
       "${metadata}" == "${snapshot_restore_stage}/metadata.json" &&
       -f "${metadata}" && ! -L "${metadata}" ]] || return 1
    ((installer_sourced)) && expected_uid="${EUID}"
    "${PYTHON3}" -I "$(release_file deploy/restore_snapshot.py)" \
        "${state}" "${source}" "${target}" "${metadata}" "${logical}" "${expected_uid}"
}

capture_state() {
    full_snapshot_recovery=0
    state_only_recovery=0
    backup_dir="$(mktemp -d "${BACKUP_ROOT}/install.XXXXXXXX")"
    chmod 0700 "${backup_dir}"
    : >"${backup_dir}/source-units.sha256"
    local release_path release_source release_digest
    for release_path in \
        deploy/systemd/pgw-api.service deploy/systemd/pgw-agent.service \
        deploy/systemd/pgw-ui.service deploy/systemd/pgw-health.service \
        deploy/systemd/pgw-fwd@.service deploy/systemd/nftables.service.d/pgw.conf \
        deploy/systemd/systemd-sysctl.service.d/pgw.conf; do
        release_source="$(release_file "${release_path}")"
        release_digest="$(sha256sum "${release_source}" | awk '{print $1}')"
        printf '%s  %s\n' "${release_digest}" "${release_path}" >>"${backup_dir}/source-units.sha256"
    done
    : >"${backup_dir}/manifest"
    local path service unit
    : >"${backup_dir}/services"
    for service in "${SERVICES[@]}"; do
        printf '%s\t%s\t%s\n' "${service}" \
            "$(systemctl is-enabled "${service}" 2>/dev/null || true)" \
            "$(systemctl is-active "${service}" 2>/dev/null || true)" >>"${backup_dir}/services"
    done
    : >"${backup_dir}/forwarders"
    while IFS= read -r unit; do
        [[ -n "${unit}" ]] || continue
        printf '%s\t%s\t%s\n' "${unit}" \
            "$(systemctl is-enabled "${unit}" 2>/dev/null || true)" \
            "$(systemctl is-active "${unit}" 2>/dev/null || true)" >>"${backup_dir}/forwarders"
    done < <(enumerate_forwarder_units)
    sysctl -n net.ipv4.ip_forward >"${backup_dir}/ip-forward"
    [[ "$(tr -d '[:space:]' <"${backup_dir}/ip-forward")" =~ ^[01]$ ]] || die "invalid live IPv4 forwarding state"
    nft -s list ruleset >"${backup_dir}/runtime-ruleset.nft"
    chmod 0600 "${backup_dir}"/{services,forwarders,runtime-ruleset.nft,ip-forward,source-units.sha256,manifest}
    # The capturing journal is published only after all state-only recovery
    # inputs are durable, and before forwarding or services are changed.
    fsync_snapshot_tree
    write_recovery_journal capturing
    state_only_recovery=1
    mutated=1
    force_forwarding_off
    quiesce_runtime
    if [[ -f "$(host_path /var/lib/pgw/pgw.db)" ]]; then
        [[ "$(sqlite3 "$(host_path /var/lib/pgw/pgw.db)" 'PRAGMA integrity_check;')" == ok ]] || die "SQLite integrity failed after stopping writers"
    fi
    for path in \
        /usr/local/bin/pgw-api /usr/local/bin/pgw-agent /usr/local/bin/pgw-fwd \
        /usr/local/bin/pgw-ui /usr/local/bin/pgw-health /usr/local/bin/pgw-snapshot-crypt \
        /usr/local/sbin/pgw-install-base /usr/local/sbin/pgw-verify-base /usr/local/sbin/pgw-verify-ui-bind \
        /usr/local/share/pgw/web \
        /etc/pgw/pgw.env /etc/pgw/jwt_secret /etc/pgw/agent.token /etc/pgw/secrets.key \
        /etc/pgw/admin_pass_hash /etc/pgw/credential-generations /etc/pgw/credentials-current \
        /etc/pgw/credential-inbox /etc/pgw/ui.crt /etc/pgw/ui.key /etc/pgw/ui_proxy_token \
        /var/lib/pgw /run/pgw/forwarders /run/pgw/agent-rollback \
        /etc/nftables.conf /etc/nftables.d/pgw-base.nft \
        /etc/sysctl.d/99-pgw.conf /etc/sysusers.d/pgw.conf /etc/tmpfiles.d/pgw.conf \
        /etc/polkit-1/rules.d/50-pgw-agent-forwarder.rules /etc/sudoers.d/pgw \
        /etc/systemd/system/pgw-api.service /etc/systemd/system/pgw-agent.service \
        /etc/systemd/system/pgw-fwd@.service /etc/systemd/system/pgw-ui.service \
        /etc/systemd/system/pgw-health.service /etc/systemd/system/pgw-webhook.service \
        /etc/systemd/system/nftables.service.d/pgw.conf \
        /etc/systemd/system/systemd-sysctl.service.d/pgw.conf; do
        record_backup_path "${path}"
    done
    capture_snapshot_payload
    write_snapshot_metadata
    # The authenticated seal exists and bounded payload verification passed.
    # Any subsequent failure must perform full recovery; it may never fall back
    # to the pre-ready state-only path.
    full_snapshot_recovery=1
    state_only_recovery=0
    verify_snapshot payload || die "rollback snapshot integrity self-check failed"
    write_recovery_journal ready
    log "rollback snapshot: ${backup_dir}"
}

restore_capture_state_only() {
    [[ -n "${backup_dir}" && -f "${backup_dir}/services" && \
       -f "${backup_dir}/forwarders" && -f "${backup_dir}/runtime-ruleset.nft" && \
       -f "${backup_dir}/ip-forward" ]] || return 1
    log "recovering pre-ready capture from service/runtime state only"
    force_forwarding_off
    quiesce_runtime
    restore_saved_runtime_state || { force_forwarding_off; return 1; }
    restore_saved_forwarding_final || { force_forwarding_off; return 1; }
    clear_recovery_journal || { force_forwarding_off; return 1; }
}

restore_snapshot() {
    [[ -n "${backup_dir}" && -f "${backup_dir}/manifest" && \
       -f "${backup_dir}/payload.manifest.json" && -f "${backup_dir}/snapshot.sha256" && -f "${backup_dir}/snapshot.hmac" ]] || return 1
    local journal_disposition="${1:-clear}" restore_stage key helper expected_uid=0
    [[ "${journal_disposition}" == clear || "${journal_disposition}" == preserve ]] || return 1
    log "restoring exact pre-install file and service state"
    force_forwarding_off
    restore_failure_point quiesce
    quiesce_runtime
    verify_snapshot payload || return 1
    key="$(host_path /etc/pgw/snapshot-encryption.key)"
    helper="$(release_file artifacts/pgw-snapshot-crypt)"
    restore_stage="$(host_path "/run/pgw/snapshot-restore.$(basename -- "${backup_dir}")")"
    snapshot_restore_stage="${restore_stage}"
    ((installer_sourced)) && expected_uid="${EUID}"
    if [[ -e "${restore_stage}" || -L "${restore_stage}" ]]; then
        remove_snapshot_stage "${restore_stage}" || return 1
    fi
    "${PYTHON3}" -I "$(release_file deploy/snapshot_payload.py)" materialize \
        "${backup_dir}" "${key}" "${helper}" "${restore_stage}" || return 1
    "${PYTHON3}" -I "$(release_file deploy/restore_snapshot.py)" metadata "${restore_stage}" || return 1
    restore_failure_point copy
    while IFS=$'\t' read -r state path; do
        local target
        write_restore_progress "${state}" "${path}" prepared
        target="$(host_path "${path}")"
        if [[ "${state}" == present ]]; then
            "${PYTHON3}" -I "$(release_file deploy/restore_snapshot.py)" \
                present "${restore_stage}/files/${path#/}" "${target}" "${restore_stage}/metadata.json" "${path}" "${expected_uid}" || return 1
        else
            atomic_restore_path absent /dev/null "${target}" "${restore_stage}/metadata.json" "${path}" || return 1
        fi
        write_restore_progress "${state}" "${path}" applied
    done < <(tac "${backup_dir}/manifest")
    "${PYTHON3}" -I "$(release_file deploy/restore_snapshot.py)" verify \
        "${restore_stage}" restored "${SYSTEM_ROOT:-/}" || return 1
    [[ "${restore_stage}" == "$(host_path /run/pgw)/snapshot-restore.install."* ]] || return 1
    remove_snapshot_stage "${restore_stage}" || return 1
    snapshot_restore_stage=""
    if ! restore_saved_runtime_state; then
        force_forwarding_off
        return 1
    fi
    # Interrupted recovery keeps forwarding disabled until every exact
    # plaintext-stage cleanup succeeds. The authenticated journal remains the
    # durable retry identity throughout that fail-closed interval.
    if [[ "${journal_disposition}" == clear ]] && ! restore_saved_forwarding_final; then
        force_forwarding_off
        return 1
    fi
    if [[ "${journal_disposition}" == clear ]] && ! clear_recovery_journal; then
        force_forwarding_off
        return 1
    fi
}

validate_rollback_snapshot() {
    local requested="$1" resolved state path
    if ((!installer_sourced)); then
        "${PYTHON3}" -I - "${requested}" "${BACKUP_ROOT}" <<'PY' || die "unsafe rollback snapshot path"
import os,stat,sys
requested,root=sys.argv[1:]
if not os.path.isabs(requested) or os.path.normpath(requested)!=requested or os.path.dirname(requested)!=root or not os.path.basename(requested).startswith("install."):
    raise SystemExit(1)
parts=[p for p in requested.split(os.sep) if p]; fd=os.open(os.sep,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    for part in parts:
        nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd); st=os.fstat(nxt)
        if st.st_uid!=0 or st.st_mode&0o022 or not stat.S_ISDIR(st.st_mode): raise SystemExit(2)
        os.close(fd); fd=nxt
    if stat.S_IMODE(os.fstat(fd).st_mode)!=0o700: raise SystemExit(3)
finally: os.close(fd)
PY
    fi
    resolved="$(readlink -f -- "${requested}")"
    [[ "${resolved}" == "${BACKUP_ROOT}"/install.* && -f "${resolved}/manifest" && \
       -f "${resolved}/services" && -f "${resolved}/forwarders" && -f "${resolved}/snapshot.sha256" ]] \
        || die "invalid PGW rollback snapshot"
    while IFS=$'\t' read -r state path; do
        [[ "${state}" == present || "${state}" == absent ]] || die "invalid snapshot manifest state"
        case "${path}" in
            /usr/local/bin/pgw-api|/usr/local/bin/pgw-agent|/usr/local/bin/pgw-fwd|\
            /usr/local/bin/pgw-ui|/usr/local/bin/pgw-health|/usr/local/bin/pgw-snapshot-crypt|\
            /usr/local/sbin/pgw-install-base|/usr/local/sbin/pgw-verify-base|/usr/local/sbin/pgw-verify-ui-bind|\
            /usr/local/share/pgw/web|/etc/pgw/pgw.env|/etc/pgw/jwt_secret|\
            /etc/pgw/agent.token|/etc/pgw/secrets.key|/etc/pgw/admin_pass_hash|\
            /etc/pgw/credential-generations|/etc/pgw/credentials-current|/etc/pgw/credential-inbox|\
            /etc/pgw/ui.crt|/etc/pgw/ui.key|/etc/pgw/ui_proxy_token|/var/lib/pgw|\
            /run/pgw/forwarders|/run/pgw/agent-rollback|\
            /etc/nftables.conf|/etc/nftables.d/pgw-base.nft|/etc/sysctl.d/99-pgw.conf|\
            /etc/sysusers.d/pgw.conf|/etc/tmpfiles.d/pgw.conf|\
            /etc/polkit-1/rules.d/50-pgw-agent-forwarder.rules|/etc/sudoers.d/pgw|\
            /etc/systemd/system/pgw-api.service|/etc/systemd/system/pgw-agent.service|\
            /etc/systemd/system/pgw-fwd@.service|/etc/systemd/system/pgw-ui.service|\
            /etc/systemd/system/pgw-health.service|/etc/systemd/system/pgw-webhook.service|\
            /etc/systemd/system/nftables.service.d/pgw.conf|\
            /etc/systemd/system/systemd-sysctl.service.d/pgw.conf) ;;
            *) die "snapshot contains out-of-scope path: ${path}" ;;
        esac
    done <"${resolved}/manifest"
    backup_dir="${resolved}"
    verify_snapshot payload || die "rollback snapshot integrity validation failed"
}

set_unit_enablement() {
    local unit="$1" saved="$2" actual
    case "${saved}" in
        masked)
            systemctl unmask "${unit}" >/dev/null
            systemctl unmask --runtime "${unit}" >/dev/null
            systemctl disable "${unit}" >/dev/null
            systemctl disable --runtime "${unit}" >/dev/null
            systemctl mask "${unit}" >/dev/null
            ;;
        masked-runtime)
            systemctl unmask "${unit}" >/dev/null
            systemctl unmask --runtime "${unit}" >/dev/null
            systemctl disable "${unit}" >/dev/null
            systemctl disable --runtime "${unit}" >/dev/null
            systemctl mask --runtime "${unit}" >/dev/null
            ;;
        enabled)
            systemctl unmask "${unit}" >/dev/null
            systemctl unmask --runtime "${unit}" >/dev/null
            systemctl disable "${unit}" >/dev/null
            systemctl disable --runtime "${unit}" >/dev/null
            systemctl enable "${unit}" >/dev/null
            ;;
        enabled-runtime)
            systemctl unmask "${unit}" >/dev/null
            systemctl unmask --runtime "${unit}" >/dev/null
            systemctl disable "${unit}" >/dev/null
            systemctl disable --runtime "${unit}" >/dev/null
            systemctl enable --runtime "${unit}" >/dev/null
            ;;
        disabled|static|indirect|generated)
            systemctl unmask "${unit}" >/dev/null
            systemctl unmask --runtime "${unit}" >/dev/null
            systemctl disable "${unit}" >/dev/null
            systemctl disable --runtime "${unit}" >/dev/null
            ;;
        not-found|'')
            actual="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
            [[ "${actual}" == not-found || -z "${actual}" ]] || die "expected absent unit after restore: ${unit}"
            return 0
            ;;
        *) die "unsupported saved enablement state for ${unit}: ${saved}" ;;
    esac
    actual="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
    [[ "${actual}" == "${saved}" ]] || die "enablement restore mismatch for ${unit}: wanted ${saved}, got ${actual}"
}

set_unit_activity() {
    local unit="$1" saved="$2" load_state
    load_state="$(systemctl show --property LoadState --value "${unit}" 2>/dev/null || true)"
    if [[ "${load_state}" == not-found && "${saved}" != active ]]; then
        ! systemctl is-active --quiet "${unit}" || die "absent unit unexpectedly active: ${unit}"
        return 0
    fi
    case "${saved}" in
        active) systemctl start "${unit}" ;;
        inactive|failed|deactivating|activating|'')
            systemctl stop "${unit}"
            ;;
        *) die "unsupported saved activity state for ${unit}: ${saved}" ;;
    esac
    if [[ "${saved}" == active ]]; then
        systemctl is-active --quiet "${unit}" || die "service activity restore failed: ${unit}"
    else
        ! systemctl is-active --quiet "${unit}" || die "service unexpectedly active after restore: ${unit}"
    fi
}

saved_service_field() {
    local wanted="$1" field="$2"
    awk -F '\t' -v unit="${wanted}" -v column="${field}" '$1==unit {print $column; exit}' "${backup_dir}/services"
}

restore_nft_runtime() {
    local nft_active current_ruleset restore_input
    [[ -f "${backup_dir}/runtime-ruleset.nft" && -f "${backup_dir}/ip-forward" ]] || die "runtime rollback evidence is missing"
    nft_active="$(saved_service_field nftables.service 3)"
    force_forwarding_off
    set_unit_activity nftables.service "${nft_active}"
    restore_input="$(mktemp "${backup_dir}/.ruleset-restore.XXXXXXXX")"
    { printf 'flush ruleset\n'; cat "${backup_dir}/runtime-ruleset.nft"; } >"${restore_input}"
    restore_failure_point runtime_apply
    nft -c -f "${restore_input}"
    nft -f "${restore_input}"
    rm -f -- "${restore_input}"
    current_ruleset="$(mktemp "${backup_dir}/.ruleset-current.XXXXXXXX")"
    nft -s list ruleset >"${current_ruleset}"
    cmp -s "${backup_dir}/runtime-ruleset.nft" "${current_ruleset}" || {
        rm -f -- "${current_ruleset}"
        die "nft runtime semantic restore mismatch"
    }
    rm -f -- "${current_ruleset}"
    verify_base_semantics
    force_forwarding_off
}

verify_saved_ruleset() {
    local current_ruleset
    current_ruleset="$(mktemp "${backup_dir}/.ruleset-verify.XXXXXXXX")"
    nft -s list ruleset >"${current_ruleset}"
    if ! cmp -s "${backup_dir}/runtime-ruleset.nft" "${current_ruleset}"; then
        rm -f -- "${current_ruleset}"
        return 1
    fi
    rm -f -- "${current_ruleset}"
    verify_base_semantics
}

verify_base_semantics() {
    if ((installer_sourced)); then
        "${PGW_INSTALL_TEST_COMMAND}" verify-base "${validated_test_root}" "${backup_dir}"
    else
        PGW_LAN_IFACE="${lan_interface}" PGW_WAN_IFACE="${wan_interface}" \
            PGW_MANAGEMENT_TCP_PORTS="${management_ports}" \
            "$(release_file artifacts/pgw-agent)" verify-base
    fi
}

restore_saved_forwarding_final() {
    local saved_forward sysctl_active
    force_forwarding_off
    verify_saved_ruleset || return 1
    sysctl_active="$(saved_service_field systemd-sysctl.service 3)"
    set_unit_activity systemd-sysctl.service "${sysctl_active}"
    saved_forward="$(tr -d '[:space:]' <"${backup_dir}/ip-forward")"
    [[ "${saved_forward}" == 0 || "${saved_forward}" == 1 ]] || return 1
    sysctl -q -w "net.ipv4.ip_forward=${saved_forward}" || return 1
    [[ "$(sysctl -n net.ipv4.ip_forward)" == "${saved_forward}" ]] || return 1
}

verify_process_binary() {
    local unit="$1" binary="$2" pid actual expected proc_exe
    systemctl is-active --quiet "${unit}" || return 0
    pid="$(systemctl show --property MainPID --value "${unit}")"
    [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || die "missing MainPID for ${unit}"
    proc_exe="$(host_path "/proc/${pid}/exe")"
    binary="$(host_path "${binary}")"
    actual="$(readlink -f "${proc_exe}")"
    expected="$(readlink -f "${binary}")"
    [[ "${actual}" == "${expected}" ]] || die "running binary identity mismatch for ${unit}: ${actual}"
    [[ "$(sha256sum "${proc_exe}" | awk '{print $1}')" == "$(sha256sum "${binary}" | awk '{print $1}')" ]] \
        || die "running binary checksum mismatch for ${unit}"
}

restore_saved_runtime_state() {
    local service enabled active unit
    restore_failure_point daemon_reload
    systemctl daemon-reload
    while IFS=$'\t' read -r service enabled active; do
        set_unit_enablement "${service}" "${enabled}"
    done <"${backup_dir}/services"
    while IFS=$'\t' read -r unit enabled active; do
        valid_forwarder_unit "${unit}" || die "invalid forwarder unit in snapshot: ${unit}"
        set_unit_enablement "${unit}" "${enabled}"
    done <"${backup_dir}/forwarders"

    if [[ -f "${backup_dir}/runtime-ruleset.nft" && -f "${backup_dir}/ip-forward" ]]; then
        restore_nft_runtime
    else
        set_unit_activity nftables.service "$(saved_service_field nftables.service 3)"
        force_forwarding_off
    fi

    for service in pgw-api.service; do
        set_unit_activity "${service}" "$(saved_service_field "${service}" 3)"
    done
    while IFS=$'\t' read -r unit enabled active; do
        set_unit_activity "${unit}" "${active}"
        [[ "${active}" != active ]] || verify_process_binary "${unit}" /usr/local/bin/pgw-fwd
    done <"${backup_dir}/forwarders"
    for service in pgw-agent.service pgw-ui.service pgw-health.service; do
        set_unit_activity "${service}" "$(saved_service_field "${service}" 3)"
    done
    verify_process_binary pgw-api.service /usr/local/bin/pgw-api
    verify_process_binary pgw-agent.service /usr/local/bin/pgw-agent
    verify_process_binary pgw-ui.service /usr/local/bin/pgw-ui
    verify_process_binary pgw-health.service /usr/local/bin/pgw-health
    verify_saved_ruleset
    force_forwarding_off
}

on_exit() {
    local rc=$? restore_rc=0
    trap - EXIT
    set +e
    if [[ -n "${ui_stage}" && "$(dirname -- "${ui_stage}")" == "$(dirname -- "${UI_ROOT}")" ]]; then
        rm -rf -- "${ui_stage}" || true
    fi
    cleanup_legacy_import_runtime || true
    if [[ -n "${snapshot_restore_stage}" && "${snapshot_restore_stage}" == "$(host_path /run/pgw)/snapshot-restore.install."* ]]; then
        remove_snapshot_stage "${snapshot_restore_stage}" || true
    fi
    if [[ -n "${legacy_sealed_stage}" && "${legacy_sealed_stage}" == "$(host_path /run/pgw)/legacy-sealed.install."* ]]; then
        remove_snapshot_stage "${legacy_sealed_stage}" || true
    fi
    if ((rc != 0 && mutated)); then
        force_forwarding_off || true
        quiesce_runtime || true
        if ((recovery_attempt_failed)); then
            restore_rc=1
        elif ((full_snapshot_recovery)); then
            ( set -Eeuo pipefail; restore_snapshot )
            restore_rc=$?
        elif ((state_only_recovery)); then
            ( set -Eeuo pipefail; restore_capture_state_only )
            restore_rc=$?
        else
            restore_rc=1
        fi
        if ((restore_rc != 0)); then
            log "CRITICAL: automatic rollback was partial or failed; snapshot retained at ${backup_dir}"
            rc=125
        fi
    fi
    exit "${rc}"
}

install_accounts_and_paths() {
    local sysusers_config tmpfiles_config
    sysusers_config="$(host_path /etc/sysusers.d/pgw.conf)"
    tmpfiles_config="$(host_path /etc/tmpfiles.d/pgw.conf)"
    atomic_install_file "$(release_file deploy/sysusers.d/pgw.conf)" "${sysusers_config}" root root 0644
    systemd-sysusers "${sysusers_config}"
    atomic_install_file "$(release_file deploy/tmpfiles.d/pgw.conf)" "${tmpfiles_config}" root root 0644
    systemd-tmpfiles --create "${tmpfiles_config}"
}

atomic_install_file() {
    local source="$1" target="$2" owner="$3" group="$4" mode="$5" directory temporary
    directory="$(dirname -- "${target}")"
    install -d -m 0755 "${directory}"
    temporary="$(mktemp "${directory}/.$(basename -- "${target}").new.XXXXXXXX")"
    if ! install -o "${owner}" -g "${group}" -m "${mode}" "${source}" "${temporary}"; then
        rm -f -- "${temporary}"
        return 1
    fi
    if ! sync -f "${temporary}" || ! mv -fT -- "${temporary}" "${target}"; then
        rm -f -- "${temporary}"
        return 1
    fi
    sync -f "${directory}"
}

atomic_publish_directory() {
    local stage="$1" target="$2"
    "${PYTHON3}" -I - "${stage}" "${target}" <<'PY'
import ctypes, os, shutil, sys
stage,target=sys.argv[1:]; parent=os.path.dirname(target)
if os.path.lexists(target):
    libc=ctypes.CDLL(None,use_errno=True)
    renameat2=getattr(libc,"renameat2",None)
    if renameat2 is None or renameat2(-100,stage.encode(),-100,target.encode(),2)!=0:
        raise OSError(ctypes.get_errno(),"atomic directory exchange unavailable")
    if os.path.islink(stage) or not os.path.isdir(stage): os.unlink(stage)
    else: shutil.rmtree(stage)
else:
    os.rename(stage,target)
descriptor=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
try: os.fsync(descriptor)
finally: os.close(descriptor)
PY
}

install_binaries() {
    local command_name
    for command_name in api agent fwd ui health snapshot-crypt; do
        atomic_install_file "$(release_file "artifacts/pgw-${command_name}")" \
            "$(host_path "/usr/local/bin/pgw-${command_name}")" root root 0755
    done
    atomic_install_file "$(release_file deploy/install-pgw-base.sh)" \
        "$(host_path /usr/local/sbin/pgw-install-base)" root root 0755
    atomic_install_file "$(release_file deploy/pgw-verify-base.sh)" \
        "$(host_path /usr/local/sbin/pgw-verify-base)" root root 0755
    atomic_install_file "$(release_file deploy/pgw-verify-ui-bind.sh)" \
        "$(host_path /usr/local/sbin/pgw-verify-ui-bind)" root root 0755
}

install_ui_assets() {
    local parent installed_manifest
    verify_ui_source_manifest || die "UI source asset checksum mismatch"
    parent="$(dirname -- "${UI_ROOT}")"
    install -d -o root -g root -m 0755 "${parent}"
    ui_stage="$(mktemp -d "${parent}/.web.new.XXXXXXXX")"
    # The unpublished stage root is still private (mktemp mode 0700), so its
    # service-owned child can remain owner-writable while the installer fills
    # it. Tighten the child before making the tree visible atomically.
    install -d -o pgw-ui -g pgw-ui -m 0750 "${ui_stage}/static"
    for asset in app.js styles.css login.js layout.css; do
        install -o pgw-ui -g pgw-ui -m 0440 "$(release_file "web/static/${asset}")" "${ui_stage}/static/${asset}"
    done
    installed_manifest="${ui_stage}/.manifest.sha256"
    sed 's#  web/#  #' "$(release_file deploy/ui-assets.sha256)" >"${installed_manifest}"
    chown pgw-ui:pgw-ui "${installed_manifest}"
    chmod 0440 "${installed_manifest}"
    (cd -- "${ui_stage}" && sha256sum -c .manifest.sha256 >/dev/null) || die "staged UI asset checksum mismatch"
    sync -f "${ui_stage}/static/app.js"
    chmod 0550 "${ui_stage}/static"
    chmod 0550 "${ui_stage}"
    chown pgw-ui:pgw-ui "${ui_stage}"
    atomic_publish_directory "${ui_stage}" "${UI_ROOT}"
    ui_stage=""
}

secure_copy_root_file() {
    local source="$1" target="$2" minimum="$3" maximum="$4" expected_uid=0
    ((installer_sourced)) && expected_uid="${EUID}"
    "${PYTHON3}" -I - "${source}" "${target}" "${minimum}" "${maximum}" "${expected_uid}" <<'PY'
import os, stat, sys
source,target,minimum,maximum,expected=sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),int(sys.argv[5])
def die(message): raise SystemExit(message)
if not os.path.isabs(source) or os.path.normpath(source)!=source: die("source must be clean and absolute")
components=[part for part in source.split(os.sep) if part]
parent=os.open(os.sep,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    for component in components[:-1]:
        nxt=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        st=os.fstat(nxt)
        if st.st_uid not in (0,expected) or st.st_mode&0o022 or not stat.S_ISDIR(st.st_mode): die("unsafe credential ancestor")
        os.close(parent); parent=nxt
    source_fd=os.open(components[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
    try:
        st=os.fstat(source_fd)
        if st.st_uid!=expected or stat.S_IMODE(st.st_mode) not in (0o400,0o600) or not stat.S_ISREG(st.st_mode):
            die("unsafe credential source owner, mode, or type")
        if st.st_size<minimum or st.st_size>maximum: die("credential source size is out of bounds")
        target_parent=os.path.dirname(target); target_name=os.path.basename(target)
        target_dir=os.open(target_parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            target_st=os.fstat(target_dir)
            if target_st.st_uid not in (0,expected) or target_st.st_mode&0o022: die("unsafe credential staging directory")
            target_fd=os.open(target_name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=target_dir)
            try:
                while True:
                    chunk=os.read(source_fd,65536)
                    if not chunk: break
                    view=memoryview(chunk)
                    while view:
                        written=os.write(target_fd,view); view=view[written:]
                os.fsync(target_fd)
            finally: os.close(target_fd)
            os.fsync(target_dir)
        finally: os.close(target_dir)
    finally: os.close(source_fd)
finally: os.close(parent)
PY
}

publish_ui_credential_generation() {
    local pgw_config_root inbox generations current legacy_cert legacy_key legacy_token
    local cert_source key_source token_source stage digest generation link_stage
    pgw_config_root="$(host_path /etc/pgw)"
    inbox="${pgw_config_root}/credential-inbox"
    generations="${pgw_config_root}/credential-generations"
    current="${pgw_config_root}/credentials-current"
    legacy_cert="${pgw_config_root}/ui.crt"
    legacy_key="${pgw_config_root}/ui.key"
    legacy_token="${pgw_config_root}/ui_proxy_token"
    install -d -o root -g root -m 0700 "${inbox}" "${generations}"
    if [[ -f "${inbox}/ui.crt" || -f "${inbox}/ui.key" || -f "${inbox}/ui_proxy_token" ]]; then
        [[ -f "${inbox}/ui.crt" && -f "${inbox}/ui.key" && -f "${inbox}/ui_proxy_token" ]] \
            || die "credential inbox rotation must contain ui.crt, ui.key, and ui_proxy_token"
        cert_source="${inbox}/ui.crt"; key_source="${inbox}/ui.key"; token_source="${inbox}/ui_proxy_token"
    elif [[ -L "${current}" && -f "${current}/ui.crt" && \
            -f "${current}/ui.key" && -f "${current}/ui_proxy_token" ]]; then
        validate_tls_pair "${current}/ui.crt" "${current}/ui.key"
        [[ "$(stat -c '%s' "${current}/ui_proxy_token")" -ge 32 ]] \
            || die "current UI proxy identity credential is too short"
        return
    elif [[ -f "${legacy_cert}" && -f "${legacy_key}" && -f "${legacy_token}" ]]; then
        cert_source="${legacy_cert}"; key_source="${legacy_key}"; token_source="${legacy_token}"
    else
        die "provision fixed root-owned credential inbox /etc/pgw/credential-inbox/{ui.crt,ui.key,ui_proxy_token}"
    fi

    stage="$(mktemp -d "${pgw_config_root}/.credential-generation.XXXXXXXX")"
    chmod 0700 "${stage}"
    secure_copy_root_file "${cert_source}" "${stage}/ui.crt" 1 1048576
    secure_copy_root_file "${key_source}" "${stage}/ui.key" 1 65536
    secure_copy_root_file "${token_source}" "${stage}/ui_proxy_token" 32 4096
    validate_tls_pair "${stage}/ui.crt" "${stage}/ui.key"
    digest="$(sha256sum "${stage}/ui.crt" "${stage}/ui.key" "${stage}/ui_proxy_token" | sha256sum | awk '{print $1}')"
    generation="${generations}/${digest}"
    if [[ -e "${generation}" ]]; then
        rm -rf -- "${stage}"
    else
        mv -T -- "${stage}" "${generation}"
        sync -f "${generation}/ui_proxy_token"
        sync -f "${generations}"
    fi
    link_stage="${pgw_config_root}/.credentials-current.${digest}"
    ln -s "credential-generations/${digest}" "${link_stage}"
    mv -Tf -- "${link_stage}" "${current}"
    sync -f "${pgw_config_root}"
    rm -f -- "${legacy_cert}" "${legacy_key}" "${legacy_token}"
    sync -f "${pgw_config_root}"
    # Inbox bytes are single-use. Remove them only after the complete staged
    # generation and atomic current pointer are durable.
    if [[ "${cert_source}" == "${inbox}/ui.crt" ]]; then
        rm -f -- "${inbox}/ui.crt" "${inbox}/ui.key" "${inbox}/ui_proxy_token"
        sync -f "${inbox}"
    fi
}

install_config_and_credentials() {
    local pgw_config_root env_stage password_file=/etc/pgw/credential-inbox/admin_password
    local jwt_secret agent_token secrets_key admin_pass_hash
    pgw_config_root="$(host_path /etc/pgw)"
    ((installer_sourced)) && password_file="$(host_path "${password_file}")"
    jwt_secret="${pgw_config_root}/jwt_secret"
    agent_token="${pgw_config_root}/agent.token"
    secrets_key="${pgw_config_root}/secrets.key"
    admin_pass_hash="${pgw_config_root}/admin_pass_hash"
    install -d -o root -g pgw-config -m 0750 "${pgw_config_root}"
    [[ -n "${lan_address}" ]] || die "LAN management address was not resolved"
    env_stage="$(mktemp "${pgw_config_root}/.pgw.env.XXXXXXXX")"
    cat >"${env_stage}" <<EOF
PGW_API_ADDR=127.0.0.1:8080
PGW_AGENT_ADDR=127.0.0.1:9090
PGW_AGENT_SOCKET=/run/pgw/control/api-agent.sock
PGW_IPV6_POLICY=deny
PGW_WAN_IFACE=${wan_interface}
PGW_LAN_IFACE=${lan_interface}
PGW_LAN_ADDRESS=${lan_address}
PGW_MANAGEMENT_TCP_PORTS=${management_ports}
PGW_UI_ADDR=${lan_address}:8081
PGW_UI_API=http://127.0.0.1:8080
PGW_HEALTH_INTERVAL=30s
PGW_FWD_BASE_PORT=15001
PGW_FWD_MAX_PORT=15999
EOF
    chown root:pgw-config "${env_stage}"
    chmod 0640 "${env_stage}"
    sync -f "${env_stage}"
    mv -Tf -- "${env_stage}" "${pgw_config_root}/pgw.env"
    sync -f "${pgw_config_root}"
    umask 077
    [[ -f "${jwt_secret}" ]] || openssl rand -base64 48 >"${jwt_secret}"
    [[ -f "${agent_token}" ]] || openssl rand -base64 48 >"${agent_token}"
    [[ -f "${secrets_key}" ]] || openssl rand 32 >"${secrets_key}"
    if [[ ! -f "${admin_pass_hash}" ]]; then
        [[ -f "${password_file}" ]] || die "fresh install requires fixed root-owned /etc/pgw/credential-inbox/admin_password"
        "$(host_path /usr/local/bin/pgw-api)" hash-admin-password --file "${password_file}" >"${admin_pass_hash}"
        rm -f -- "${password_file}"
    fi
    publish_ui_credential_generation
    grep -q '^\$argon2id\$v=19\$' "${admin_pass_hash}" || die "pgw-api emitted an invalid admin PHC"
    chown root:root "${jwt_secret}" "${agent_token}" "${secrets_key}" "${admin_pass_hash}"
    chmod 0600 "${jwt_secret}" "${agent_token}" "${secrets_key}" "${admin_pass_hash}"
    systemd-tmpfiles --create "$(host_path /etc/tmpfiles.d/pgw.conf)"
}

import_legacy_state() {
    ((legacy_state_pending)) || return 0
    local live_state sealed_state sealed_stage database key snapshot_key helper api_binary runtime_dir report_temp report_identity report runtime_uid
    live_state="$(host_path /var/lib/pgw/state.json)"
    sealed_stage="$(host_path "/run/pgw/legacy-sealed.$(basename -- "${backup_dir}")")"
    legacy_sealed_stage="${sealed_stage}"
    sealed_state="${sealed_stage}/files/var/lib/pgw/state.json"
    database="$(host_path /var/lib/pgw/pgw.db)"
    key="$(host_path /etc/pgw/secrets.key)"
    snapshot_key="$(host_path /etc/pgw/snapshot-encryption.key)"
    helper="$(release_file artifacts/pgw-snapshot-crypt)"
    api_binary="$(host_path /usr/local/bin/pgw-api)"
    [[ -n "${legacy_state_checksum}" && ! -e "${sealed_stage}" && ! -L "${sealed_stage}" && \
       -f "${key}" && ! -L "${key}" && -f "${snapshot_key}" && ! -L "${snapshot_key}" && -x "${api_binary}" && ! -L "${api_binary}" ]] \
        || die "legacy import inputs are missing or unsafe"
    cmp -s "$(release_file artifacts/pgw-api)" "${api_binary}" \
        || die "installed pgw-api does not match the staged release binary"
    "${PYTHON3}" -I "$(release_file deploy/snapshot_payload.py)" materialize \
        "${backup_dir}" "${snapshot_key}" "${helper}" "${sealed_stage}" || die "could not decrypt sealed legacy state"
    [[ -f "${sealed_state}" && ! -L "${sealed_state}" ]] || die "sealed legacy state is unavailable"
    # /run is a root-owned tmpfs.  Do not open any root-write target beneath
    # /var/lib/pgw: that hierarchy is writable by pgw-api.  The lower
    # privilege process receives only inherited descriptors, never paths.
    runtime_dir="$(host_path /run/pgw/legacy-import)"
    runtime_uid=0
    ((installer_sourced)) && runtime_uid="${EUID}"
    install -d -o root -g root -m 0700 "${runtime_dir}"
    ((installer_sourced)) && chown "${runtime_uid}:${runtime_uid}" "${runtime_dir}"
    [[ "$(stat -c '%u:%g:%a:%F' "${runtime_dir}")" == "${runtime_uid}:${runtime_uid}:700:directory" ]] \
        || die "unsafe legacy import runtime directory"
    report_temp="${runtime_dir}/report.json"
    # Python performs the root-only opens with O_EXCL|O_NOFOLLOW and drops to
    # pgw-api only after descriptor validation. No root shell redirection (or
    # later root pathname open) occurs below a pgw-api-writable ancestor.
    "${PYTHON3}" -I - "${runtime_dir}" "${sealed_state}" "${key}" "${database}" "${api_binary}" "${runtime_uid}" <<'PY' \
        || die "legacy state import failed; rollback snapshot is retained"
import os,pwd,stat,subprocess,sys
runtime,state,key,database,api,owner=sys.argv[1:]; owner=int(owner)
def regular(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode): raise SystemExit("unsafe import input")
    return fd
rfd=os.open(runtime,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    st=os.fstat(rfd)
    if st.st_uid != owner or stat.S_IMODE(st.st_mode) != 0o700: raise SystemExit("unsafe runtime")
    statefd=regular(state); keyfd=regular(key)
    reportfd=os.open("report.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=rfd)
    reportst=os.fstat(reportfd)
    if not stat.S_ISREG(reportst.st_mode) or reportst.st_uid != owner or stat.S_IMODE(reportst.st_mode) != 0o600: raise SystemExit("unsafe report")
    account=pwd.getpwnam("pgw-api")
    def drop_privileges():
        os.initgroups(account.pw_name,account.pw_gid); os.setgid(account.pw_gid); os.setuid(account.pw_uid)
    for fd in (statefd,keyfd,reportfd): os.set_inheritable(fd,True)
    result=subprocess.run([api,"import-legacy-state","--state-fd",str(statefd),"--database",database,"--key-fd",str(keyfd),"--report-fd",str(reportfd)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,pass_fds=(statefd,keyfd,reportfd),preexec_fn=drop_privileges,check=False)
    if result.returncode != 0: raise SystemExit("import failed")
finally:
    for fd_name in ("statefd","keyfd","reportfd","rfd"):
        fd=locals().get(fd_name)
        if isinstance(fd,int):
            try: os.close(fd)
            except OSError: pass
PY
    # Test harnesses may SIGKILL here: the importer succeeded, but both its
    # private report and the sealed plaintext stage still exist. Production's
    # default failure_point is a no-op.
    failure_point legacy_importer_success
    report_identity="$(stat -c '%d:%i:%u:%g:%a' "${report_temp}")"
    [[ "$(stat -c '%d:%i:%u:%g:%a' "${report_temp}")" == "${report_identity}" && \
       "$(stat -c '%F' "${report_temp}")" == "regular file" ]] \
        || die "legacy import report changed during write"
    "${PYTHON3}" -I - "${report_temp}" "${legacy_state_checksum}" <<'PY' || die "legacy import report is invalid"
import json,re,sys
with open(sys.argv[1],"r",encoding="utf-8") as handle: report=json.load(handle)
if not isinstance(report,dict) or set(report)-{"checksum","dry_run","already_imported","proxies","clients","mappings","duplicates","warnings"}: raise SystemExit(1)
if report.get("dry_run") is not False or not re.fullmatch(r"[0-9a-f]{64}",report.get("checksum","")): raise SystemExit(1)
if report["checksum"] != sys.argv[2]: raise SystemExit(1)
if any(not isinstance(report.get(name),int) or report[name] < 0 for name in ("proxies","clients","mappings")): raise SystemExit(1)
PY
    # The snapshot was authenticated before this transaction phase. Keep the
    # operator report beside it under BACKUP_ROOT, never inside the sealed
    # snapshot tree where it would invalidate manifest/HMAC coverage.
    report="${BACKUP_ROOT}/legacy-import-report.$(basename -- "${backup_dir}").json"
    install -o root -g root -m 0600 "${report_temp}" "${report}" || die "could not publish legacy import report"
    rm -f -- "${report_temp}"; rmdir -- "${runtime_dir}" || die "could not clean legacy import runtime data"
    [[ "${sealed_stage}" == "$(host_path /run/pgw)/legacy-sealed.install."* ]] || die "unsafe legacy sealed stage"
    remove_snapshot_stage "${sealed_stage}" || die "could not clean sealed legacy state"
    legacy_sealed_stage=""
    "${PYTHON3}" -I - "${live_state}" <<'PY' || die "could not durably remove imported legacy state"
import os,stat,sys
target=sys.argv[1]
if not os.path.isabs(target) or os.path.normpath(target)!=target:
    raise SystemExit("unsafe legacy state path")
parent_path,name=os.path.dirname(target),os.path.basename(target)
parent=os.open(os.sep,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    for part in (value for value in parent_path.split(os.sep) if value):
        child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        if not stat.S_ISDIR(os.fstat(child).st_mode):
            os.close(child); raise SystemExit("unsafe legacy state parent")
        os.close(parent); parent=child
    item=os.stat(name,dir_fd=parent,follow_symlinks=False)
    if not stat.S_ISREG(item.st_mode):
        raise SystemExit("legacy state is not a regular file")
    os.unlink(name,dir_fd=parent)
    os.fsync(parent)
finally:
    os.close(parent)
PY
    legacy_state_pending=0
    log "sealed legacy state imported atomically; secret-free checksum report retained beside the rollback snapshot"
}

# SIGKILL can strand only the fixed report name in root-owned /run tmpfs. A
# later operation removes that exact inode after strict checks; unexpected
# content fails closed rather than broadening cleanup into a recursive delete.
cleanup_legacy_import_runtime() {
    local runtime_dir expected_uid=0
    runtime_dir="$(host_path /run/pgw/legacy-import)"
    ((installer_sourced)) && expected_uid="${EUID}"
    [[ -e "${runtime_dir}" || -L "${runtime_dir}" ]] || return 0
    "${PYTHON3}" -I "$(release_file deploy/snapshot_payload.py)" \
        remove-legacy-report "${runtime_dir}" "${expected_uid}"
}

install_units_and_policy() {
    local unit
    atomic_install_file "$(release_file deploy/polkit-1/rules.d/50-pgw-agent-forwarder.rules)" \
        "$(host_path /etc/polkit-1/rules.d/50-pgw-agent-forwarder.rules)" root root 0644
    for unit in pgw-api.service pgw-agent.service pgw-fwd@.service pgw-ui.service pgw-health.service; do
        atomic_install_file "$(release_file "deploy/systemd/${unit}")" \
            "$(host_path "/etc/systemd/system/${unit}")" root root 0644
    done
    atomic_install_file "$(release_file deploy/systemd/nftables.service.d/pgw.conf)" \
        "$(host_path /etc/systemd/system/nftables.service.d/pgw.conf)" root root 0644
    atomic_install_file "$(release_file deploy/systemd/systemd-sysctl.service.d/pgw.conf)" \
        "$(host_path /etc/systemd/system/systemd-sysctl.service.d/pgw.conf)" root root 0644
    rm -f "$(host_path /etc/sudoers.d/pgw)"
    if [[ -e "$(host_path /etc/systemd/system/pgw-webhook.service)" ]] || systemctl cat pgw-webhook.service >/dev/null 2>&1; then
        systemctl disable --now pgw-webhook.service >/dev/null
    fi
    rm -f "$(host_path /etc/systemd/system/pgw-webhook.service)"
    systemctl daemon-reload
}

install_firewall_and_sysctl() {
    local nftables_config sysctl_config
    nftables_config="$(host_path /etc/nftables.conf)"
    sysctl_config="$(host_path /etc/sysctl.d/99-pgw.conf)"
    force_forwarding_off
    if ((installer_sourced)); then
        "${PGW_INSTALL_TEST_COMMAND}" install-base "${validated_test_root}" "${backup_dir}" \
            "${lan_interface}" "${wan_interface}" "${management_ports}"
    else
        /usr/local/sbin/pgw-install-base --lan "${lan_interface}" --wan "${wan_interface}" --management-ports "${management_ports}"
    fi
    atomic_install_file "$(release_file deploy/nftables.conf)" "${nftables_config}" root root 0644
    atomic_install_file "$(release_file deploy/sysctl-pgw.conf)" "${sysctl_config}" root root 0644
    nft -c -f "${nftables_config}"
    systemctl enable nftables.service pgw-api.service pgw-agent.service pgw-ui.service pgw-health.service
    systemctl restart nftables.service
    verify_base_semantics
    force_forwarding_off
}

enable_forwarding_after_install() {
    force_forwarding_off
    verify_base_semantics
    systemctl restart systemd-sysctl.service
    [[ "$(sysctl -n net.ipv4.ip_forward)" == 1 ]] || die "IPv4 forwarding was not enabled after base verification"
    verify_base_semantics
}

restore_forwarders_after_upgrade() {
    local unit enabled active
    while IFS=$'\t' read -r unit enabled active; do
        valid_forwarder_unit "${unit}" || die "invalid saved forwarder instance: ${unit}"
        set_unit_enablement "${unit}" "${enabled}"
        set_unit_activity "${unit}" "${active}"
        [[ "${active}" != active ]] || verify_process_binary "${unit}" /usr/local/bin/pgw-fwd
    done <"${backup_dir}/forwarders"
}

verify_installation() {
    local unit service command_name installed
    for unit in pgw-api.service pgw-agent.service pgw-fwd@.service pgw-ui.service pgw-health.service; do
        installed="$(host_path "/etc/systemd/system/${unit}")"
        cmp -s "$(release_file "deploy/systemd/${unit}")" "${installed}" || die "unit hash mismatch: ${unit}"
        [[ "$(sha256sum "$(release_file "deploy/systemd/${unit}")" | awk '{print $1}')" == \
           "$(sha256sum "${installed}" | awk '{print $1}')" ]] || die "unit SHA-256 mismatch: ${unit}"
    done
    for command_name in api agent fwd ui health snapshot-crypt; do
        installed="$(host_path "/usr/local/bin/pgw-${command_name}")"
        cmp -s "$(release_file "artifacts/pgw-${command_name}")" "${installed}" || die "binary checksum mismatch: pgw-${command_name}"
        [[ "$(stat -c '%U:%G:%a' "${installed}")" == root:root:755 ]] || die "binary owner/mode mismatch: pgw-${command_name}"
    done
    cmp -s "$(release_file deploy/install-pgw-base.sh)" "$(host_path /usr/local/sbin/pgw-install-base)" || die "pgw-install-base checksum mismatch"
    cmp -s "$(release_file deploy/pgw-verify-base.sh)" "$(host_path /usr/local/sbin/pgw-verify-base)" || die "pgw-verify-base checksum mismatch"
    cmp -s "$(release_file deploy/pgw-verify-ui-bind.sh)" "$(host_path /usr/local/sbin/pgw-verify-ui-bind)" || die "pgw-verify-ui-bind checksum mismatch"
    [[ "$(stat -c '%U:%G:%a' "$(host_path /var/lib/pgw)")" == pgw-api:pgw-control:750 ]] || die "invalid DB directory ownership"
    [[ "$(stat -c '%U:%G:%a' "$(host_path /var/lib/pgw/rules)")" == pgw-agent:pgw-agent:750 ]] || die "invalid rules directory ownership"
    [[ "$(stat -c '%U:%G:%a' "$(host_path /run/pgw/forwarders)")" == pgw-agent:pgw-fwd:750 ]] || die "invalid forwarder runtime ownership"
    [[ "$(stat -c '%U:%G:%a' "${UI_ROOT}")" == pgw-ui:pgw-ui:550 ]] || die "invalid UI asset root ownership"
    cmp -s "$(release_file deploy/ui-assets.sha256)" "${UI_ROOT}/.manifest.sha256" \
        || { sed 's#  web/#  #' "$(release_file deploy/ui-assets.sha256)" | cmp -s - "${UI_ROOT}/.manifest.sha256"; } \
        || die "installed UI manifest mismatch"
    (cd -- "${UI_ROOT}" && sha256sum -c .manifest.sha256 >/dev/null) || die "installed UI asset checksum mismatch"
    verify_base_semantics
    for service in pgw-api.service pgw-agent.service pgw-ui.service pgw-health.service; do
        systemctl is-active --quiet "${service}" || die "service is not active after install: ${service}"
    done
    verify_process_binary pgw-api.service /usr/local/bin/pgw-api
    verify_process_binary pgw-agent.service /usr/local/bin/pgw-agent
    verify_process_binary pgw-ui.service /usr/local/bin/pgw-ui
    verify_process_binary pgw-health.service /usr/local/bin/pgw-health
    verify_ui_http_smoke
}

verify_ui_http_smoke() {
    local ui_host index_body asset certificate
    certificate="$(host_path /etc/pgw/credentials-current/ui.crt)"
    ui_host="$(openssl x509 -in "${certificate}" -noout -ext subjectAltName 2>/dev/null | sed -n 's/.*DNS:\([^, ]*\).*/\1/p' | head -n1)"
    [[ -n "${ui_host}" ]] || ui_host="$(openssl x509 -in "${certificate}" -noout -ext subjectAltName 2>/dev/null | sed -n 's/.*IP Address:\([^, ]*\).*/\1/p' | head -n1)"
    [[ -n "${ui_host}" ]] || ui_host="$(openssl x509 -in "${certificate}" -noout -subject -nameopt RFC2253 | sed -n 's/.*CN=\([^,]*\).*/\1/p')"
    [[ -n "${ui_host}" ]] || die "UI certificate has no DNS identity for smoke validation"
    index_body="$(curl --fail --silent --show-error --cacert "${certificate}" --resolve "${ui_host}:8081:${lan_address}" "https://${ui_host}:8081/login")"
    [[ "${index_body}" == *'/static/styles.css'* && "${index_body}" == *'/static/login.js'* ]] || die "UI index smoke contract failed"
    for asset in app.js styles.css login.js layout.css; do
        curl --fail --silent --show-error --output /dev/null --cacert "${certificate}" \
            --resolve "${ui_host}:8081:${lan_address}" "https://${ui_host}:8081/static/${asset}" \
            || die "UI static smoke failed: ${asset}"
    done
}

execute_install_phase() {
    local phase="$1"
    case "${phase}" in
        after_accounts) install_accounts_and_paths ;;
        after_binaries) install_binaries ;;
        after_ui_assets) install_ui_assets ;;
        after_credentials) install_config_and_credentials ;;
		after_legacy_import) import_legacy_state ;;
        after_units) install_units_and_policy ;;
        after_firewall) install_firewall_and_sysctl ;;
        after_services)
            systemctl restart pgw-api.service
            restore_forwarders_after_upgrade
            systemctl restart pgw-agent.service pgw-ui.service pgw-health.service
            verify_installation
            enable_forwarding_after_install
            ;;
        *) die "unknown install transaction phase: ${phase}" ;;
    esac
}

run_install_transaction() {
    local phase
    failure_point after_snapshot
    for phase in after_accounts after_binaries after_ui_assets after_credentials after_legacy_import after_units after_firewall after_services; do
        force_forwarding_off
        write_recovery_journal "${phase}"
        execute_install_phase "${phase}"
        [[ "${phase}" == after_services ]] || force_forwarding_off
        failure_point "${phase}"
    done
}

main() {
    parse_arguments "$@"
    if ((developer_dry_run && !dry_run)); then
        die "unsigned checkout mode is non-root dry-run only; production requires pgw-release-launcher"
    fi
    trap on_exit EXIT
    if [[ -n "${rollback_request}" ]]; then
    [[ "${EUID}" -eq 0 ]] || die "rollback requires root"
    for command_name in systemctl nft sysctl sha256sum cmp awk stat flock tac readlink cp mktemp sleep sort; do
        require_command "${command_name}"
    done
    validate_fixed_python
    prepare_lifecycle_roots
    exec 9>"${LIFECYCLE_LOCK}"
    flock -n 9 || die "another PGW lifecycle operation is running"
    validate_rollback_snapshot "${rollback_request}"
    trap - EXIT
    set +e
    (
        set -Eeuo pipefail
        restore_snapshot
    )
    manual_restore_rc=$?
    if ((manual_restore_rc != 0)); then
        log "CRITICAL: manual rollback was partial or failed; snapshot retained at ${backup_dir}"
        exit 125
    fi
    log "rollback restored and verified: ${backup_dir}"
        exit 0
    fi

    validate_source
    if ((dry_run)); then
        log "dry-run PASS: source manifests, privilege boundaries and base-only persistence contract are valid; host interfaces/accounts are checked only by a real preflight"
        exit 0
    fi
    validate_host
    prepare_lifecycle_roots
    exec 9>"${LIFECYCLE_LOCK}"
    flock -n 9 || die "another PGW lifecycle operation is running"
    # A journal-bearing interrupted migration is cleaned inside recovery only
    # after its snapshot restore, so its durable authentication marker spans
    # every plaintext cleanup. Ordinary startup may clean a stale report.
    if [[ -e "${RECOVERY_JOURNAL}" || -L "${RECOVERY_JOURNAL}" ]]; then
        recover_interrupted_lifecycle
    else
        cleanup_legacy_import_runtime || die "could not safely clean interrupted legacy import runtime data"
    fi
    capture_state
    run_install_transaction
    clear_recovery_journal
    mutated=0
    log "installation complete; rollback snapshot retained at ${backup_dir}"
}

if ((installer_sourced == 0)); then
    main "$@"
fi
