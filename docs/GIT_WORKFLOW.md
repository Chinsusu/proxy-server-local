# Git Collaboration Workflow

Tài liệu này là quy ước bắt buộc khi thay đổi mã nguồn PGW. Mục tiêu là giữ `main` luôn có thể phát hành, tạo lịch sử dễ truy vết và bảo vệ các thuộc tính an toàn của data-plane, đặc biệt là **fail-close**, `web_only` mặc định, IPv6/UDP deny và không direct-WAN fallback.

## 1. Trạng thái và mô hình nhánh

PGW dùng **trunk-based development**:

```text
main       o---o--------o-----------o   luôn có thể phát hành
                \      / \         /
feat/...         o----o   o-------o     nhánh ngắn hạn + PR
```

- `main` là nhánh dài hạn duy nhất, được bảo vệ và không nhận push trực tiếp.
- Mọi thay đổi đi qua nhánh ngắn hạn và pull request (PR).
- Không tạo `develop`, nhánh theo môi trường hoặc nhánh release sống lâu. Môi trường được triển khai từ commit/tag bất biến, không phải từ nhánh riêng.
- Nhánh nên tồn tại dưới 5 ngày làm việc. Nếu công việc lớn hơn, chia thành các PR độc lập, giữ tương thích và ẩn phần chưa sẵn sàng sau feature flag.
- Nhánh stale quá 30 ngày cần rebase/đóng; không giữ nhánh đã merge.

## 2. Issue và tên nhánh

Mỗi thay đổi có hành vi người dùng/vận hành phải có issue. Fix typo hoặc bảo trì rất nhỏ có thể không cần issue nếu PR giải thích đầy đủ.

Tên issue nên mô tả kết quả, ví dụ: `Agent keeps last-known-good rules when validation fails`. Dùng label theo loại (`bug`, `feature`, `security`, `documentation`, `dependencies`) và vùng (`api`, `agent`, `fwd`, `ui`, `deploy`). Với thay đổi mạng, issue phải ghi rõ behavior trước/sau, compatibility và cách chứng minh không fail-open.

Tên nhánh có dạng `<type>/<issue>-<slug>`:

```text
feat/123-socks5-adapter
fix/247-agent-keeps-lkg
docs/301-backup-runbook
chore/88-update-go-toolchain
hotfix/412-block-direct-wan-regression
```

`<issue>-` được khuyến nghị và có thể bỏ khi không có issue. Dùng chữ thường, ASCII và dấu gạch ngang; không dùng tên cá nhân hoặc tên chung như `changes`, `test`, `final`.

## 3. Conventional Commits

Commit theo dạng:

```text
<type>(<scope>): <mệnh lệnh ngắn>

[body: lý do, ràng buộc và tác động]

[footer]
```

Type được chấp nhận:

| Type | Dùng cho |
|---|---|
| `feat` | Thêm hành vi/capability |
| `fix` | Sửa lỗi |
| `perf` | Cải thiện hiệu năng có thể đo |
| `refactor` | Đổi cấu trúc nhưng không đổi hành vi |
| `test` | Chỉ thay đổi test/fixture |
| `docs` | Chỉ thay đổi tài liệu |
| `build` | Build, dependency, packaging |
| `ci` | Workflow và automation CI/CD |
| `chore` | Bảo trì không thuộc nhóm trên |
| `revert` | Hoàn tác một commit/PR |

Scope ưu tiên: `api`, `agent`, `fwd`, `ui`, `auth`, `store`, `policy`, `nft`, `health`, `deploy`, `docs`, `deps`, `release`. Có thể thêm scope mới khi nó đại diện một module ổn định.

Quy tắc subject:

- Viết ở thể mệnh lệnh, không viết hoa chữ đầu và không có dấu chấm cuối; tối đa 72 ký tự.
- Mô tả một thay đổi có thể quan sát, không dùng `update`, `misc fixes`, `WIP` hoặc `final` đơn lẻ.
- Body giải thích **vì sao** và trade-off; không lặp lại diff.
- Footer liên kết issue bằng `Refs: #123` hoặc `Closes: #123`.
- Breaking change dùng `!` và footer `BREAKING CHANGE:`. Thay đổi API không tương thích phải đi qua `/v2`; không silently alter `/v1`.

Ví dụ:

```text
fix(agent): preserve base drop rules on reconcile failure

Validate the dynamic ruleset before the atomic swap so an invalid desired
generation cannot remove the LAN-to-WAN kill-switch.

Closes: #247
```

## 4. Commit nguyên tử

Một commit chỉ làm một việc và có thể revert độc lập:

- Không gộp refactor lớn với feature, dependency update hoặc protocol adapter.
- Tách thay đổi cơ học khỏi thay đổi hành vi.
- Code và test trực tiếp chứng minh hành vi nên nằm cùng commit; tài liệu bắt buộc của cùng contract cũng có thể nằm cùng commit.
- Mỗi commit phải build được và không cố ý làm test đỏ. Ngoại lệ chỉ dành cho chuỗi commit được tạo tự động rồi squash trước review.
- Không commit binary build, secret, credential thật, log chứa dữ liệu nhạy cảm hoặc file backup tạm.
- Dùng `git add -p` và kiểm tra `git diff --cached` trước commit.

Có thể dùng `fixup!` trong lúc phát triển, nhưng phải autosquash trước khi PR sẵn sàng review:

```bash
git commit --fixup <commit>
git rebase -i --autosquash origin/main
```

## 5. Bắt đầu và cập nhật nhánh

Tạo nhánh từ `origin/main` mới nhất:

```bash
git fetch origin --prune
git switch --create feat/123-short-name origin/main
```

Trước khi merge hoặc release:

```bash
git fetch origin
git rebase origin/main
go test ./...
go vet ./...
go build ./cmd/...
```

Kiểm tra formatting bằng `gofmt` trên file Go đã đổi và bảo đảm `git diff --check` không báo lỗi whitespace.

Chỉ rewrite lịch sử trên nhánh cá nhân chưa có người khác dựa vào. Sau rebase, dùng:

```bash
git push --force-with-lease
```

Không dùng `git push --force`, không force-push `main`, nhánh release/tag hoặc nhánh đang được nhiều người chia sẻ. Với nhánh dùng chung, merge `origin/main` hoặc phối hợp rõ với các contributor thay vì tự rewrite lịch sử.

## 6. Vòng đời thay đổi

1. Có thể mở Draft PR để CI chạy và lưu context, nhưng PR không bắt buộc khi chỉ có một maintainer.
2. Tự kiểm tra diff, bỏ debug/backup/generated artifact không chủ đích và cập nhật test/docs.
3. Rebase lên `origin/main`, xử lý conflict tại nhánh nguồn và chạy lại verification.
4. Khi có contributor, xử lý comment bằng commit mới hoặc `fixup!`.
5. Khi toàn bộ check liên quan xanh, maintainer có thể tự merge theo chiến lược ở mục 8.
6. Xóa nhánh sau merge và theo dõi deployment/smoke test nếu thay đổi có runtime impact.

Maintainer chịu trách nhiệm cho chất lượng thay đổi. Review bên ngoài là tùy chọn
khi có team, không phải điều kiện để dùng dự án cá nhân.

## 7. Quality gate và bằng chứng

Mọi thay đổi trước khi merge phải có:

- Nhánh up-to-date với `main` và toàn bộ required CI checks thành công.
- Test tương xứng với thay đổi; bug fix có regression test khi khả thi.
- Tài liệu, config example, migration/rollback note và changelog được cập nhật khi có tác động tương ứng.
- Không có plaintext secret trong code, fixture, log hoặc screenshot.

Thay đổi rủi ro cao cần bằng chứng bổ sung, nhưng không cần approval của người
khác khi maintainer là người duy nhất vận hành dự án:

- nftables, routing, TPROXY, Agent reconcile hoặc Forwarder.
- Authentication/authorization, secret storage, cryptography hoặc audit.
- Migration/schema, backup/restore hoặc deployment/systemd chạy đặc quyền.
- API breaking change, release/hotfix hoặc thay đổi default network policy.

Bằng chứng bổ sung theo vùng:

| Vùng thay đổi | Bằng chứng bắt buộc |
|---|---|
| Agent/firewall/data-plane | Linux network namespace E2E; invalid reconcile giữ LKG; forwarder/proxy down không direct-WAN fallback |
| Policy/proxy adapter | Capability matrix; positive và negative test; chứng minh UDP/IPv6 không được suy diễn từ protocol |
| Store/migration | Migration transaction test; import/backup/restore; rollback note |
| Secret/auth | Negative tests; log/API/state scan không có plaintext; RBAC test |
| API | Contract test; compatibility impact với `/v1`; idempotency/concurrency khi liên quan |
| UI | Screenshot hoặc recording; error/loading/empty state; accessibility check cơ bản |
| Performance | Baseline, workload, before/after và guardrail |

Nếu CI chưa có môi trường phù hợp cho network E2E, maintainer phải lưu bằng
chứng chạy thủ công có thể tái tạo. Không được đánh dấu hoàn tất nếu không có
log, artifact hoặc mô tả lệnh/kết quả.

## 8. Chiến lược merge

**Squash merge** là mặc định. Tiêu đề PR phải là Conventional Commit vì nó trở thành commit trên `main`; body PR lưu context và liên kết issue.

Dùng **rebase merge** chỉ khi chuỗi commit nguyên tử, mỗi commit đều pass và lịch sử riêng lẻ có giá trị cho `git bisect`/revert.

Không dùng merge commit cho feature PR. Chỉ maintainer mới được dùng merge commit trong tình huống tích hợp được ghi nhận rõ. Không merge khi check đang pending/skip ngoài dự kiến và không bypass branch protection để “sửa sau”.

Sau merge, kiểm tra commit trên `main` và xóa nhánh nguồn. Nếu merge gây regression, ưu tiên revert nhanh thay vì sửa trực tiếp trên `main`.

## 9. Release, hotfix và revert

PGW dùng Semantic Versioning và annotated tag từ commit đã kiểm chứng trên `main`:

```bash
git switch main
git pull --ff-only origin main
git tag -a v2.0.0 -m "release: v2.0.0"
git push origin v2.0.0
```

Release PR cập nhật `CHANGELOG.md`, migration/rollback runbook và phiên bản nếu có; CI tạo artifact bất biến, checksum, SBOM và provenance theo capability hiện có. Không build lại thủ công rồi gắn cùng một version.

Hotfix dùng cùng quality gate, có thể thực hiện trực tiếp bởi maintainer:

1. Tạo `hotfix/<issue>-<slug>` từ `origin/main` (hoặc từ tag đang chạy nếu maintainer tuyên bố maintenance line).
2. Chỉ đưa minimal fix, regression test và rollback procedure.
3. Chạy full required checks; vùng fail-close/security cần negative test, backup và rollback procedure rõ ràng.
4. Merge vào `main`, phát hành patch version và xác minh production.

Hoàn tác bằng PR chứa `git revert`, không reset hoặc rewrite `main`:

```bash
git switch -c revert/412-problem origin/main
git revert <bad-commit>
git push -u origin HEAD
```

Nếu revert migration/data-plane không an toàn, dừng rollout, dùng runbook/LKG đã kiểm chứng và mở incident. PR revert phải liên kết PR gốc, nêu dữ liệu/config chịu tác động và điều kiện forward-fix.

## 10. Cấu hình Git đề xuất

Cấu hình ruleset cho `main`:

- Pull request và CODEOWNERS là tùy chọn; một maintainer có thể merge trực tiếp sau khi tự kiểm tra quality gate.
- Nếu dùng PR thì đó là công cụ tự tổ chức diff và chạy required checks cho chính maintainer.
- Require status checks và branch up-to-date trước merge. Baseline: formatting/lint, unit test, `go vet`, build tất cả binaries, secret/dependency scan; thêm network E2E khi workflow sẵn sàng.
- Require signed commits cho maintainer/release automation khi tổ chức đã quản lý key; luôn require signed annotated release tags.
- Block force pushes và deletion; không cho bypass ngoại trừ break-glass role được audit.
- Có thể restrict direct pushes khi có team; với dự án cá nhân, giữ quyền direct push cho maintainer.
- Require linear history, automatic branch deletion và tag protection cho `v*`.

Không cấu hình số approval hoặc team membership làm release blocker cho dự án
cá nhân. Technical checks, backup, canary và rollback mới là gate bắt buộc.

## 11. Khôi phục Git an toàn

Sau thao tác nhầm trên nhánh cá nhân, dùng `git reflog` để tìm commit và tạo nhánh cứu hộ trước khi thay đổi thêm:

```bash
git reflog
git switch -c rescue/<date>-<topic> <commit>
```

Không dùng `reset --hard` để “sửa” nhánh đã chia sẻ. Nếu đã push commit sai, dùng `git revert`. Nếu nghi có secret bị commit, coi secret đã lộ: rotate/revoke ngay, mở security incident, sau đó maintainer mới quyết định quy trình rewrite lịch sử toàn repository.

## 12. Definition of Done

Một thay đổi chỉ hoàn tất khi code đã merge, CI pass, test và bằng chứng đúng
mức rủi ro, docs/config/migration note đã cập nhật, không lộ secret, và có
rollback khả thi. Với release v2.0, Definition of Done chi tiết trong blueprint
vẫn là chuẩn cao hơn và được ưu tiên khi có khác biệt.
