#!/bin/bash
set -Eeuo pipefail

((EUID != 0)) || { printf 'full-system trust bootstrap test must run unprivileged\n' >&2; exit 96; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
fixture="$(mktemp -d)"
trap 'rm -rf -- "${fixture}"' EXIT
printf 'signed manifest fixture\n' >"${fixture}/manifest"
head -c 256 /dev/zero >"${fixture}/signature"
printf 'untrusted key\n' >"${fixture}/fake.pem"
mkdir "${fixture}/hostile"
cat >"${fixture}/hostile/openssl" <<EOF
#!/bin/bash
printf 'ambient openssl executed\n' >${fixture@Q}/ambient-openssl-ran
exit 0
EOF
chmod 0755 "${fixture}/hostile/openssl"

set +e
PATH="${fixture}/hostile:${PATH}" PGW_FULL_SYSTEM_PUBLIC_KEY="${fixture}/fake.pem" \
    /bin/bash "${ROOT}/deploy/trust/verify-full-system-signature.sh" \
    "${fixture}/manifest" "${fixture}/signature" >/dev/null 2>&1
missing_rc=$?
set -e
[[ "${missing_rc}" == 69 && ! -e "${fixture}/ambient-openssl-ran" ]]

cp "${ROOT}/deploy/trust/verify-full-system-signature.sh" "${fixture}/mismatch-verifier.sh"
sed -i "s#readonly TRUSTED_KEY=/opt/pgw-release-trust/full-system.pem#readonly TRUSTED_KEY=${fixture}/fake.pem#" \
    "${fixture}/mismatch-verifier.sh"
set +e
/bin/bash "${fixture}/mismatch-verifier.sh" "${fixture}/manifest" "${fixture}/signature" >/dev/null 2>&1
mismatch_rc=$?
set -e
[[ "${mismatch_rc}" == 69 ]]
printf 'fixed full-system key path, mode, and hostile environment tests: PASS\n'
