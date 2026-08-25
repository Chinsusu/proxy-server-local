# Continuous Integration Standard

Workflow chuẩn là `.github/workflows/ci.yml`. CI tách validation của pull
request khỏi release pipeline có đặc quyền.

## Pull request và validation thông thường

Ba job `quality`, `test`, `security` chạy với `contents: read` và user thường:

- `gofmt`, `go vet`, Bash syntax, ShellCheck và hardening contracts;
- `go test -count=1 ./...`;
- `go mod verify`, Gitleaks ratchet cho commit mới và `govulncheck` blocking.

PR không chạy `sudo`, không chạy script bằng root, không mint OIDC token, không
có quyền ghi attestation, không publish và không deploy. Test release local chỉ
tạo candidate có `candidate_only true`.

Go được pin `1.26.7` và `GOTOOLCHAIN=local`. Tất cả action bên thứ ba dùng full
commit SHA. Khi nâng toolchain hoặc scanner, thay version và bằng chứng pin trong
cùng PR.

## Protected push candidate

Mọi job trong workflow hiện tại, kể cả `protected-systemd` và
`candidate-release`, có đúng `permissions: contents: read`. Job nào checkout
hoặc chạy shell/script từ candidate không có `id-token`, `attestations`, secret
hay trust-key material. `candidate-release` build từ fresh exact-SHA Git export,
build offline hai lần, chạy non-root rehearsal, scan/finalize và upload duy nhất
`pgw-candidate-diagnostic-<sha>`. Artifact vẫn là `candidate_only true`; workflow
này không thể phát hành production attestation.

Các job có `sudo` chỉ chạy trên protected push để kiểm compatibility/isolation,
nhưng passwordless sudo trên hosted runner không phải trust boundary. Vì vậy
không public/private key hay signer authority nào được provision cho chúng.
The protected systemd job explicitly validates Ubuntu 22.04 / systemd 249 unit compatibility.

Production promotion cần một orchestrator độc lập, pin ngoài candidate
repository/SHA. Orchestrator đó chỉ download closed tar như data; không checkout
candidate repository, không chạy file trong tar và không dùng workflow hiện tại
làm signer. Contract machine-readable nằm tại
`deploy/trust/external-attestor-handoff.json` và hiện ghi
`BLOCKED_UNPROVISIONED`. Chưa có orchestrator/pinned signer được provision, nên
P0-09 và production promotion vẫn unavailable/fail-closed.

Khi orchestrator độc lập được triển khai, operator cài policy v2, attestor,
`gh`, custom Sigstore trusted root và native entrypoint dưới
`/opt/pgw-release-trust` với root ownership/mode cố định. `attestor` và
`verify-release-attestation` phải là đúng hai hardlink của cùng static binary;
candidate repo không phân phối shell trust entrypoint. Policy pin toàn bộ digest và identity của signer,
verifier và evidence producer, bao gồm ref/SHA/run-attempt cùng DER-SPKI key
SHA-256. Candidate CI không được tạo hoặc sửa các trust root này.

Snapshot manifest v2 preflight toàn cây trước materialization: mọi file và
directory đều tính vào record count, depth và aggregate path bytes. Default cap
là 200,000 records/depth 64/32 MiB path bytes; evidence cap là 256 records/depth
8/64 KiB path bytes. Wide/deep tree fail trước khi output directory được tạo.

## Verification trước deploy

```bash
/opt/pgw-release-trust/bin/verify-release-attestation \
  /var/lib/pgw/promotion-inbox/pgw-release-candidate.tar \
  /var/lib/pgw/promotion-inbox/attestation.bundle.jsonl
```

Nếu external policy/custom trusted root chưa tồn tại, promotion unavailable.
Promoter chỉ dùng offline bundle (`--bundle`, `--custom-trusted-root`,
`--no-public-good`), không gọi attestation API và không nhận PAT. Thành công phải
stage release, ghi receipt và thay trust manifest nguyên tử; output print-only
không được coi là promotion.

`argv[0]` là dữ liệu caller kiểm soát và không có quyền trust. Native binary chỉ
dispatch khi kernel `AT_EXECFN`, đọc có giới hạn từ `/proc/self/auxv` và
`/proc/self/mem`, đúng tuyệt đối fixed clean absolute entrypoint; sau đó vẫn
kiểm tra hardlink pair và `/proc/self/exe` cùng inode. Vì không qua shell nên
`BASH_ENV` không có pre-interpreter hook. Sau verification, JSON `pgw-promotion-result-v1` trên stdout bind release,
candidate, bundle và predicate; stderr rỗng. Mapping authoritative là
`promoted=0`, `pre_commit_failed=75`, `commit_indeterminate=76`, và
`committed_durability_indeterminate=77`. Automation phải lưu stdout nhưng quyết
định theo exit code; `76/77` dừng rollout để operator reconcile trạng thái.
Pre-verification failure vẫn stdout rỗng, stderr sanitized và giữ nguyên code.
Copy, symlink, alias sai hoặc link count khác hai đều fail trước promotion.

## Chạy local

```bash
go vet ./...
go test -count=1 ./...
go mod verify
bash deploy/tests/hardening_test.sh
```

Syft 1.34.2 và Gitleaks 8.28.0 là bắt buộc để chạy finalizer thật. Local và CI
output chỉ dùng rehearsal/diagnostic và không được promote.
