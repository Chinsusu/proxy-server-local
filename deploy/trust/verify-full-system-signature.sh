#!/bin/bash
set -Eeuo pipefail

((EUID != 0)) || { printf 'full-system signature verification must run unprivileged\n' >&2; exit 96; }
(($# == 2)) || { printf 'usage: verify-full-system-signature.sh MANIFEST SIGNATURE\n' >&2; exit 2; }

readonly TRUSTED_KEY=/opt/pgw-release-trust/full-system.pem
readonly TRUSTED_OPENSSL=/usr/bin/openssl
readonly MAX_MANIFEST_BYTES=4096
readonly MAX_SIGNATURE_BYTES=16384
manifest="$1"
signature="$2"

[[ -f "${manifest}" && ! -L "${manifest}" && -f "${signature}" && ! -L "${signature}" ]] || {
    printf 'signed full-system metadata must be regular files\n' >&2; exit 65;
}
manifest_size="$(/usr/bin/stat -c '%s' -- "${manifest}")"
signature_size="$(/usr/bin/stat -c '%s' -- "${signature}")"
((manifest_size > 0 && manifest_size <= MAX_MANIFEST_BYTES &&
   signature_size >= 64 && signature_size <= MAX_SIGNATURE_BYTES)) || {
    printf 'signed full-system metadata exceeds size policy\n' >&2; exit 65;
}
[[ -x "${TRUSTED_OPENSSL}" && ! -L "${TRUSTED_OPENSSL}" ]] || {
    printf 'fixed OpenSSL verifier is unavailable\n' >&2; exit 69;
}
[[ -f "${TRUSTED_KEY}" && ! -L "${TRUSTED_KEY}" ]] || {
    printf 'fixed full-system public key is unavailable\n' >&2; exit 69;
}
for trusted_path in / /opt /opt/pgw-release-trust; do
    [[ ! -L "${trusted_path}" && "$(/usr/bin/stat -c '%u' -- "${trusted_path}")" == 0 ]] || {
        printf 'trusted key ancestor ownership/type rejected: %s\n' "${trusted_path}" >&2; exit 69;
    }
    trusted_mode="$(/usr/bin/stat -c '%a' -- "${trusted_path}")"
    (( (8#${trusted_mode} & 8#022) == 0 )) || {
        printf 'trusted key ancestor is group/world writable: %s\n' "${trusted_path}" >&2; exit 69;
    }
done
[[ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "${TRUSTED_KEY}")" == '0:0:444:regular file' ]] || {
    printf 'fixed full-system public key owner/mode/type rejected\n' >&2; exit 69;
}

# Pin all three inputs by descriptor. This helper is valid only on the
# independently administered verifier host where candidate code has no sudo or
# root path; inode checks additionally detect a privileged concurrent swap.
exec {key_fd}<"${TRUSTED_KEY}"
exec {manifest_fd}<"${manifest}"
exec {signature_fd}<"${signature}"
key_fd_path="/proc/$$/fd/${key_fd}"
manifest_fd_path="/proc/$$/fd/${manifest_fd}"
signature_fd_path="/proc/$$/fd/${signature_fd}"
key_identity="$(/usr/bin/stat -Lc '%d:%i:%s:%u:%g:%a' -- "${key_fd_path}")"
manifest_identity="$(/usr/bin/stat -Lc '%d:%i:%s:%Y:%Z' -- "${manifest_fd_path}")"
signature_identity="$(/usr/bin/stat -Lc '%d:%i:%s:%Y:%Z' -- "${signature_fd_path}")"
[[ "${key_identity}" == "$(/usr/bin/stat -Lc '%d:%i:%s:%u:%g:%a' -- "${TRUSTED_KEY}")" ]] || {
    printf 'fixed full-system public key changed while opening\n' >&2; exit 69;
}

"${TRUSTED_OPENSSL}" dgst -sha256 -verify "${key_fd_path}" \
    -signature "${signature_fd_path}" "${manifest_fd_path}" >/dev/null || {
        printf 'full-system detached signature verification failed\n' >&2; exit 65;
    }
[[ "${key_identity}" == "$(/usr/bin/stat -Lc '%d:%i:%s:%u:%g:%a' -- "${key_fd_path}")" &&
   "${key_identity}" == "$(/usr/bin/stat -Lc '%d:%i:%s:%u:%g:%a' -- "${TRUSTED_KEY}")" &&
   "${manifest_identity}" == "$(/usr/bin/stat -Lc '%d:%i:%s:%Y:%Z' -- "${manifest_fd_path}")" &&
   "${signature_identity}" == "$(/usr/bin/stat -Lc '%d:%i:%s:%Y:%Z' -- "${signature_fd_path}")" ]] || {
    printf 'signature verification input changed during verification\n' >&2; exit 65;
}
exec {signature_fd}<&-
exec {manifest_fd}<&-
exec {key_fd}<&-
printf 'full-system detached signature verified with fixed trust root\n'
