
## Problem

<!-- Vấn đề cụ thể, ai/hệ thống nào bị ảnh hưởng và vì sao cần sửa? -->

## Scope

<!-- Thay đổi nằm trong PR này. Giữ PR nhỏ và có thể review/revert độc lập. -->

## Out of scope

<!-- Những việc liên quan nhưng chủ động không làm trong PR. -->

## Linked issues

Closes #

## Behavior before

<!-- Hành vi có thể quan sát trước thay đổi. -->

## Behavior after

<!-- Hành vi có thể quan sát sau thay đổi. -->

## Compatibility impact

<!-- /v1, config hiện hữu, web_only mặc định, IPv4/IPv6/UDP, upgrade. Ghi "None" kèm lý do nếu không có. -->

## Security impact

<!-- Auth/RBAC, secrets, audit, process privilege, nftables và khả năng fail-open. Ghi "None" kèm lý do nếu không có. -->

## Migration impact

<!-- Schema/data/config migration, backup/restore và downgrade. Ghi "None" kèm lý do nếu không có. -->

## Metrics and logs added

<!-- Metric/log/reason code mới; xác nhận không chứa secret hoặc dữ liệu nhạy cảm. -->

## Tests and evidence

<!-- Liệt kê lệnh + kết quả. Đính kèm log/artifact/screenshot có thể tái tạo. -->

- [ ] `gofmt` đã chạy trên các file Go thay đổi; `git diff --check` sạch
- [ ] `go test ./...` pass
- [ ] `go vet ./...` pass
- [ ] `go build ./cmd/...` pass
- [ ] Regression/negative tests đã được thêm hoặc giải thích vì sao không phù hợp
- [ ] UI evidence đã đính kèm nếu thay đổi giao diện

### Network/data-plane evidence (nếu liên quan)

- [ ] Network namespace E2E pass
- [ ] Forwarder/proxy failure không tạo direct-WAN fallback
- [ ] Invalid reconcile giữ base kill-switch và last-known-good
- [ ] UDP/IPv6 vẫn deny trừ khi issue chủ động thay đổi policy và có capability evidence

## Rollback procedure

<!-- Lệnh/bước rollback, tác động dữ liệu và cách xác minh. Không chỉ ghi "revert PR" nếu có migration hoặc runtime state. -->

## Reviewer checklist

- [ ] PR có phạm vi nguyên tử; không trộn refactor lớn với feature/fix
- [ ] Title theo Conventional Commits
- [ ] Không có plaintext secret trong code, fixture, log hoặc screenshot
- [ ] API/docs/config/changelog được cập nhật khi cần
- [ ] CI required checks xanh và mọi conversation đã resolve
- [ ] Thay đổi rủi ro cao có 2 approvals và bằng chứng theo `docs/GIT_WORKFLOW.md`
