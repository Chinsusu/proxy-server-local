# Tiêu chuẩn coding của Proxy Gateway Manager

Tài liệu này là chuẩn bắt buộc cho code mới và các phần code được sửa trong Proxy Gateway Manager (PGW). Mục tiêu là giữ code dễ review, đồng thời bảo toàn thuộc tính an toàn quan trọng nhất của hệ thống: **mọi lỗi phải fail-close, không được làm traffic của managed client đi trực tiếp ra WAN**.

Repository đang trong giai đoạn chuyển tiếp từ skeleton v1 sang kiến trúc v2. Khi code hiện tại khác với tài liệu này, không sao chép mẫu legacy sang code mới. Hãy sửa phần liên quan trong phạm vi PR hoặc tạo issue kỹ thuật nếu việc sửa vượt phạm vi.

## 1. Phạm vi và mức độ ưu tiên

Chuẩn này áp dụng cho:

- Go trong `cmd/` và `pkg/`;
- shell script trong `deploy/`, `scripts/` và thư mục gốc;
- HTML, CSS và JavaScript trong `web/` hoặc template của `cmd/ui`;
- test, migration, cấu hình, tài liệu và artifact phát hành.

Khi có xung đột, thứ tự ưu tiên là:

1. Thuộc tính security và fail-close trong blueprint v2.
2. API contract, schema và ADR đã được phê duyệt.
3. Tài liệu này.
4. Cách triển khai legacy đang tồn tại.

Các từ **PHẢI**, **KHÔNG ĐƯỢC**, **NÊN** và **CÓ THỂ** thể hiện mức độ bắt buộc tương ứng.

## 2. Go

### 2.1 Phiên bản, format và kiểm tra tĩnh

- Dùng phiên bản Go được khai báo trong `go.mod`; không tự ý đổi `go` hoặc `toolchain` trong một PR không liên quan.
- Mọi file `.go` PHẢI qua `gofmt`. Import được sắp xếp theo nhóm standard library, dòng trống, rồi module bên thứ ba/nội bộ; dùng `goimports` nếu dự án đưa công cụ này vào CI.
- Code PHẢI qua `go vet ./...` và test. Không tắt cảnh báo linter bằng `//nolint` nếu không ghi tên rule và lý do ngay tại vị trí tắt.
- Dùng tên Go tự nhiên: acronym giữ dạng `ID`, `IP`, `HTTP`, `API`, `JWT`; tránh tên mơ hồ như `data`, `obj`, `tmp` ngoài phạm vi rất ngắn.
- Không nén nhiều câu lệnh lên một dòng. Ưu tiên code đọc được trong review hơn code ngắn.
- Exported type, function, constant và biến PHẢI có Go doc bắt đầu bằng đúng tên symbol và giải thích contract, không chỉ lặp lại tên.

### 2.2 Ranh giới package và tiến trình

`cmd/<service>/main.go` chỉ làm composition root: đọc cấu hình, ghép dependency, đăng ký transport, quản lý lifecycle và graceful shutdown. Logic có thể unit test phải chuyển vào package thích hợp.

Ranh giới hiện tại và hướng phát triển:

| Khu vực | Trách nhiệm |
|---|---|
| `cmd/api` | Khởi tạo HTTP API và dependency control plane; không sở hữu nftables |
| `cmd/agent` | Reconcile desired state và là thành phần duy nhất được apply nftables |
| `cmd/fwd` | Kết nối client tới upstream proxy; không thay đổi desired state |
| `cmd/health` | Probe/telemetry; không tự thay policy |
| `cmd/ui` | Phục vụ UI; không chạy lệnh đặc quyền |
| `pkg/types` | Domain/value types ổn định; không chứa HTTP handler hoặc persistence |
| `pkg/store` | Interface và implementation persistence; transaction nằm ở boundary này |
| `pkg/config` | Parse và validate cấu hình typed |
| `pkg/auth` | Authentication/authorization primitives |
| `pkg/check` | Probe có timeout và cancellation |
| `pkg/httpx` | HTTP transport helper, response và middleware dùng chung |
| `pkg/logging` | Structured logging và redaction dùng chung |

Package mới phải có một trách nhiệm rõ ràng, tên ngắn, không tạo vòng phụ thuộc. Domain không import `cmd/*`, HTTP, HTML hoặc chi tiết systemd. Store không quyết định policy. UI/API không import hoặc gọi helper apply nft.

Không thêm code mới để API/UI chạy `nft`, `sudo`, `systemctl` hoặc giữ `CAP_NET_ADMIN`. Những mẫu này còn tồn tại trong legacy phải được loại dần; agent hoặc helper đặc quyền có interface hẹp mới được thực hiện thao tác data plane.

### 2.3 Dependency và interface

- Nhận dependency qua constructor; không tạo store/client/logger mới sâu trong business logic.
- Định nghĩa interface ở phía consumer và giữ interface nhỏ. Không tạo interface chỉ để bọc một concrete type mà không có nhu cầu test hoặc thay implementation.
- Standard library được ưu tiên. Dependency mới cần lý do, kiểm tra maintenance/license/security và phải cập nhật `go.mod`/`go.sum` trong cùng PR.
- Không dùng mutable global cho state nghiệp vụ. Hằng số hoặc logger process-wide là ngoại lệ có chủ đích; dependency testable vẫn nên được inject.

### 2.4 Context, concurrency và lifecycle

- Function thực hiện I/O hoặc có thể chờ phải nhận `context.Context` làm tham số đầu tiên. Không dùng `context.Background()` khi request context đang có sẵn.
- Mọi HTTP client, dial, subprocess, DB operation và shutdown phải có timeout hoặc deadline hợp lý.
- Goroutine phải có owner, điều kiện dừng và đường thu lỗi. Không tạo goroutine fire-and-forget cho thay đổi state quan trọng.
- Dùng `errgroup`, channel hoặc `WaitGroup` để chờ worker; đóng channel ở phía producer. Không ghi vào channel đã đóng và không giữ lock trong lúc gọi mạng/subprocess.
- State chia sẻ phải được bảo vệ nhất quán bằng mutex/atomic hoặc được một goroutine sở hữu. Copy dữ liệu ra khỏi lock trước khi thực hiện I/O.
- Reconcile nftables phải serialize. Yêu cầu mới chỉ nâng `pending_generation`; tuyệt đối không chạy hai lần apply đồng thời.
- Background loop dùng `time.Ticker` phải `Stop()`, quan sát `ctx.Done()` và có backoff/jitter khi lỗi để tránh retry storm.
- PR thay đổi concurrency phải chạy `go test -race ./...` và có test cho cancellation, timeout hoặc race liên quan.

### 2.5 Lỗi

- Trả lỗi cho caller; chỉ `main`/startup boundary mới được quyết định thoát process. Library code không dùng `log.Fatal`, `panic` hoặc `os.Exit` cho lỗi vận hành.
- Bọc lỗi bằng `%w` và thêm ngữ cảnh hành động: `fmt.Errorf("load desired generation %d: %w", generation, err)`.
- Dùng sentinel/typed error khi caller thực sự cần phân nhánh với `errors.Is`/`errors.As`; không phân nhánh theo chuỗi lỗi.
- Không bỏ lỗi bằng `_ =` trừ cleanup/best-effort đã được chứng minh an toàn. Phải comment lý do và log/metric nếu lỗi ảnh hưởng vận hành.
- Error message viết chữ thường, không dấu chấm cuối, không chứa secret/token/password. Giữ nguyên cause để observability truy vết được.
- Lỗi apply, verify hoặc persist generation phải giữ base kill-switch và last-known-good; không được “phục hồi” bằng đường WAN trực tiếp.

### 2.6 Cấu hình

- Tất cả biến môi trường của dự án dùng prefix `PGW_` và được parse tập trung thành typed config.
- Default chỉ dành cho giá trị an toàn. Production phải từ chối khởi động khi thiếu secret, interface, path hoặc giá trị security-critical; không tự dùng credential demo.
- Parse nghiêm ngặt và trả lỗi rõ ràng cho duration, port, CIDR, enum và boolean. Không âm thầm thay input sai bằng default.
- Validate quan hệ chéo khi startup, ví dụ dải port, WAN/LAN khác nhau, policy tương thích capability và đường dẫn có permission đúng.
- Không đọc `os.Getenv` rải rác trong business logic mới. Không log toàn bộ environment hoặc config chứa credential.
- Thay đổi tên/default/semantics của config phải cập nhật `docs/CONFIG_REFERENCE.md`, `docs/ENV_TEMPLATE.env`, unit system và migration note trong cùng PR.

## 3. API và domain model

### 3.1 Contract

- API mới dùng prefix `/v2`; `/v1` là compatibility surface và không được phá vỡ ngoài quy trình deprecation/migration đã duyệt.
- Handler chỉ làm transport: authenticate/authorize, decode, validate, gọi service và encode response. Policy và persistence không nằm trong closure handler.
- Chỉ chấp nhận method đã khai báo; trả `405` kèm header `Allow`. Giới hạn body, kiểm tra `Content-Type`, từ chối unknown field cho request cấu hình và chỉ decode đúng một JSON value.
- Response luôn có `Content-Type: application/json; charset=utf-8`. Không trả lỗi nội bộ, stack trace, output của shell/nft hoặc plaintext secret cho client.
- Dùng status code đúng nghĩa: `201` create, `204` delete không body, `400` malformed/validation, `401` chưa xác thực, `403` không đủ quyền, `404`, `409` conflict, `412` stale `If-Match`, `422` capability/policy không hợp lệ, `429`, `500/503` cho lỗi server/dependency.
- API v2 dùng error envelope ổn định, ví dụ:

```json
{
  "error": {
    "code": "POLICY_CAPABILITY_MISMATCH",
    "message": "proxy does not support the requested UDP policy",
    "field": "udp_mode",
    "request_id": "..."
  }
}
```

- `code` dành cho máy, ổn định và được test; `message` an toàn cho người dùng; `field` và `request_id` là tùy chọn.
- Mutation phải có authorization, validation và audit. Dùng idempotency key cho create/action có thể retry; dùng version hoặc `If-Match` cho optimistic concurrency.
- Struct domain, request DTO, response DTO và persistence model nên tách khi quyền đọc/ghi khác nhau. Không serialize trực tiếp persistence model ra API.

### 3.2 Validation và compatibility

- Validate tại boundary và normalize một lần: IP/CIDR bằng `net/netip`, port `1..65535`, enum bằng typed constants, string có length limit.
- Không tự suy capability từ nhãn protocol. UDP/IPv6 chỉ active sau probe end-to-end và policy tương thích.
- `web_only` là default tương thích v1: chỉ TCP 80/443; UDP và IPv6 bị deny. Thay đổi default này là breaking/security-sensitive change.
- Trạng thái và generation phải có transition rõ ràng. Không đánh dấu `APPLIED` trước khi nft apply, verify và persist kết quả thành công.
- Khi thêm/sửa endpoint, cập nhật OpenAPI trong `docs/API_SPEC.yaml`, ví dụ request/response/error và tài liệu migration nếu contract thay đổi.

## 4. Logging, metrics và audit

- Code mới dùng `log/slog` qua `pkg/logging`; log dạng JSON trong runtime. Legacy `Printf` chỉ được giữ để tương thích trong phần chưa sửa.
- Log event bằng message ổn định và field typed: `service`, `request_id`, `mapping_id`, `proxy_id`, `generation`, `ruleset_hash`, `duration_ms`, `result`, `error`.
- Không ghép dữ liệu người dùng vào format string. Không log password, JWT, API key, `Authorization`, cookie, encryption key, plaintext secret, proxy URL có userinfo hoặc full request body.
- Redaction phải diễn ra trước logger/telemetry boundary và được test. Giá trị secret write-only không được xuất hiện ở bất kỳ level log nào.
- `ERROR` là hành động thất bại cần xử lý; `WARN` là suy giảm/điều kiện bất thường; `INFO` là lifecycle và thay đổi state; tránh log từng connection ở `INFO` nếu không sampling.
- Prometheus label phải low-cardinality. Không dùng connection ID, destination IP/domain, request ID hoặc raw error làm label.
- Audit là append-only và khác application log. Mọi mutation phải ghi actor, action, resource, timestamp, request ID, before/after đã redact và kết quả. API thường không được sửa/xóa audit record.

## 5. Security và secret

- Không commit credential thật, private key, token, `.env`, database dump hoặc captured traffic. Dùng placeholder rõ ràng trong example.
- Password/secret API là **write-only**: response chỉ cho biết trạng thái như `has_password`; không trả plaintext hoặc encrypted blob.
- Production secret dùng AES-256-GCM envelope encryption, nonce riêng cho mỗi secret. Master key lấy từ file mode `0600`, systemd credential hoặc secret manager; không đặt trong source, DB, CLI argument hay nftables.
- Không giữ secret lâu hơn cần thiết; không đưa secret vào error, `fmt.Sprintf`, process list, metric hoặc audit before/after.
- Mọi endpoint có mutation phải kiểm tra authentication và RBAC server-side. UI visibility không phải authorization.
- Không dựng command string từ input. Dùng API hệ điều hành hoặc `exec.CommandContext` với binary/argument allowlist; validate interface, table, chain, port và path trước khi gọi.
- API/UI chạy non-root. Agent chỉ giữ capability tối thiểu (`CAP_NET_ADMIN`) hoặc gọi helper đặc quyền có giao diện hẹp. Không tạo shell/debug endpoint trên production listener.
- File state/secret phải có owner và mode tối thiểu cần thiết; tạo file atomically, chống symlink/path traversal khi path chịu ảnh hưởng từ input.
- Thay đổi auth, crypto, secret, command execution, nftables, install/update hoặc quyền systemd cần negative test và security review riêng.

## 6. nftables và data-plane safety

Đây là khu vực security-critical. Mọi PR chạm rule generation/reconcile phải chứng minh các invariant sau:

1. Base kill-switch tồn tại độc lập với mapping động và không bị xóa trong reconcile thông thường.
2. Managed LAN không thể forward trực tiếp ra WAN khi API, Agent, Forwarder, upstream hoặc apply bị lỗi.
3. `web_only` chỉ redirect TCP 80/443; TCP khác, UDP và IPv6 bị deny theo policy mặc định.
4. UI/API không apply nftables; Agent là single writer.
5. Desired snapshot bất biến theo generation; apply và ACK cùng một generation/hash.

Quy tắc triển khai:

- Sinh rules từ typed, validated model; không nối raw user input thành nft syntax.
- Output phải deterministic: sort collection trước khi render để cùng desired state luôn có cùng ruleset/hash.
- Validate bằng `nft -c -f <file>` trước apply. Apply cả ruleset động trong **một transaction nguyên tử**; không xóa rules cũ trước rồi mới thử add rules mới.
- Sau apply, đọc lại/verify các invariant quan trọng. Chỉ sau đó persist `applied_generation`, hash, timestamp và ACK.
- Lưu last-known-good (LKG) atomically. Nếu generation mới lỗi, giữ base kill-switch và rules LKG; ghi trạng thái/error có giới hạn, không fallback direct.
- Không flush/xóa table/chain ngoài ownership đã xác định. Cleanup phải idempotent và không mở cửa sổ traffic leak.
- Mọi command phải có timeout, capture output có giới hạn và không chứa secret. Không dùng `sh -c`, `eval` hoặc command interpolation.
- Golden test phải bao phủ render/diff của base rules, `web_only`, overlapping CIDR, duplicate mapping, invalid port/CIDR, UDP deny, IPv6 deny và stable hash.
- Integration test trên Linux network namespace phải chứng minh egress đúng proxy và các failure mode fail-close; unit test chuỗi rule không đủ để phê duyệt thay đổi enforcement.

## 7. Shell script và Makefile

### 7.1 Shell

- Script mới dùng `#!/usr/bin/env bash` và bắt đầu bằng `set -Eeuo pipefail`. Nếu một lệnh được phép lỗi, xử lý bằng `if`/`case` và comment; không thêm `|| true` không giải thích.
- Quote mọi expansion: `"${value}"`. Dùng array cho argument, `[[ ... ]]` cho test, `$(...)` thay backtick và `printf` thay `echo` khi dữ liệu có thể bắt đầu bằng `-` hoặc chứa escape.
- Biến môi trường viết hoa; biến/function local viết thường và khai báo bằng `local`. Constant phải `readonly` khi phù hợp.
- Kiểm tra dependency, quyền root, input, path và precondition trước mutation. Error ghi `stderr` và exit khác `0`.
- Dùng `mktemp -d` và `trap` để cleanup. File cấu hình/secret được tạo với `umask 077` hoặc mode cụ thể; write vào temp cùng filesystem rồi `mv` atomically.
- Không dùng `eval`, parse `ls`, word-splitting từ command output, unquoted glob, hoặc `curl ... | bash` trong automation production.
- Download phải dùng HTTPS, `curl --fail --show-error --location` và verify checksum/signature trước install. Pin version; không tự pull `main` cho release production.
- Trước `rm -rf`, `mv`, restore hoặc rollback, resolve và kiểm tra target tuyệt đối nằm trong thư mục cho phép. Backup/rollback phải có retention rõ và test restore.
- Không đọc secret bằng pipeline dễ lộ trong argv/log. Không bật `set -x` quanh credential. Dùng environment file/credential file có permission đúng.
- Script thay đổi nftables/systemd/deploy phải idempotent, có preflight, health check sau apply và rollback khi health check thất bại.
- Script phải qua `shellcheck`; ngoại lệ ghi directive tại dòng liên quan kèm lý do.

### 7.2 Makefile

- Target phải deterministic và fail khi command con lỗi. Khai báo `.PHONY` cho target không tạo file.
- Artifact build đi vào `bin/`; không ghi binary vào `cmd/` hoặc repository root.
- Dùng biến cho tool/flag dùng chung (`GO ?= go`, `BIN_DIR ?= bin`) và quote path trong recipe khi có thể.
- Target chuẩn nên gồm `fmt-check`, `vet`, `test`, `test-race`, `build`, `lint` và `ci`; `ci` phải phản ánh gate chạy trên CI.
- Không đưa credential/default production vào recipe. Target deploy/release không được chạy như side effect của `build` hoặc `test`.

## 8. Frontend HTML, CSS và JavaScript

Frontend hiện là vanilla HTML/CSS/JavaScript với Bootstrap ở một số view. Giữ cách triển khai này cho tới khi có ADR thay stack.

- JavaScript dùng `const` mặc định, `let` khi cần gán lại, không dùng `var`; dùng `async`/`await` và xử lý cả HTTP error lẫn network error.
- Tách API client, state và DOM rendering khi file bắt đầu có nhiều trách nhiệm. Không đặt business/security policy chỉ ở client.
- Không dùng `innerHTML` cho dữ liệu API/người dùng. Dùng `textContent`, DOM API hoặc escaping đã được review. URL/query phải qua `URL`/`URLSearchParams`.
- Không lưu password, JWT dài hạn hoặc secret trong DOM, URL, `localStorage`, console hay downloadable export. Không export cột credential.
- Mọi form có `<label>` liên kết, validation message dễ hiểu, keyboard access và focus management. Nút icon có accessible name; toast/status dùng ARIA phù hợp và không chỉ dựa vào màu.
- Không dùng inline event handler/style cho code mới. Event listener đăng ký ở module/script; không tạo nhiều `DOMContentLoaded` handler cho cùng một flow.
- CSS dùng custom property cho token lặp lại, class semantic, mobile-first và breakpoint có lý do. Không dùng `!important` nếu chưa ghi lý do; hỗ trợ focus-visible, reduced motion và contrast WCAG AA.
- UI phải hiển thị trạng thái chính xác: `PENDING`, `APPLIED`, `FAILED`, desired/applied generation và `IPv6: BLOCKED BY POLICY`; không đổi lỗi thành trạng thái thành công để “dễ dùng”.
- Mutation cần trạng thái loading, chặn double-submit, xử lý `401/403/409/412/422/429/5xx` và refresh state từ server sau thành công.
- Chạy formatter/linter được repository cấu hình. Khi chưa có toolchain frontend, giữ style nhất quán với file hiện tại và test bằng browser ở viewport desktop/mobile.

## 9. Testing

### 9.1 Test pyramid và cách viết test

- Test phải deterministic, độc lập thứ tự, không gọi Internet thật và không phụ thuộc clock/random/global environment nếu không inject/control được.
- Unit test đặt cạnh code bằng `_test.go`, ưu tiên table-driven test với tên case mô tả behavior. Dùng `t.TempDir()`, `t.Setenv()` và `t.Cleanup()` thay path/state dùng chung.
- Test observable contract, không khóa chặt implementation detail. Mọi bug fix phải có regression test thất bại trước khi sửa.
- Test song song chỉ dùng `t.Parallel()` khi không chia sẻ env, port, filesystem hoặc global state.
- HTTP test dùng `httptest`, kiểm tra method/status/header/body/error envelope/auth/RBAC và giới hạn input.
- Persistence test phải kiểm tra transaction, constraint, migration, concurrent access, crash/locked behavior và backup/restore. Migration đã phát hành không được sửa; thêm migration mới và test upgrade.
- Security-sensitive code cần negative test: malformed JSON/CIDR, traversal/injection, stale version, role sai, secret redaction và unauthorized mutation.

### 9.2 Gate theo loại thay đổi

Mọi PR Go tối thiểu format toàn bộ file Go được thêm/sửa và chạy:

```bash
go vet ./...
go test ./...
go build ./cmd/...
```

CI tạm áp dụng `gofmt` theo changed-file ratchet vì repository còn formatting
debt lịch sử. File đã chạm vào không được giữ debt; mục tiêu sau cleanup PR là
kiểm tra `gofmt` trên toàn repository như mô tả trong `CI.md`.

Chạy thêm `go test -race ./...` cho concurrency/store/network code. Shell chạy `shellcheck` trên file thay đổi. Frontend chạy lint/test tự động nếu được cấu hình và smoke test các flow bị ảnh hưởng.

PR chạm data plane phải chạy Linux-only integration test bằng network namespaces cho:

- traffic được map đi qua đúng proxy/exit IP;
- TCP ngoài policy, UDP và IPv6 bị chặn;
- proxy/forwarder/API/agent dừng vẫn không direct egress;
- nft syntax/apply lỗi giữ base kill-switch và LKG;
- hai generation liên tiếp không apply đè/race;
- reboot/reconcile khôi phục đúng rules.

Không merge bằng cách skip/xóa test thất bại. Nếu môi trường CI không chạy được test đặc quyền, PR phải dẫn tới kết quả từ lab tương đương và có issue để tự động hóa; reviewer data-plane xác nhận bằng chứng.

## 10. Tài liệu và thay đổi contract

- Code và tài liệu ship trong cùng PR. Comment giải thích **vì sao/invariant**, không diễn giải từng dòng code.
- Public API phải có OpenAPI entry, ví dụ thành công, error và auth requirement. Config mới phải có type, default, phạm vi, sensitivity, reload behavior và ví dụ an toàn.
- Breaking change phải có migration guide và rollback trước release. Thay đổi schema phải ghi compatibility với binary cũ/mới và backup requirement.
- User-facing text dùng thuật ngữ trong `docs/GLOSSARY.md`; tài liệu dùng câu chủ động, command có thể chạy được và nêu expected output/failure.
- Cập nhật changelog cho thay đổi người dùng/vận hành thấy được. ADR dùng cho quyết định kiến trúc dài hạn hoặc thay đổi ownership/trust boundary.
- Không xóa tài liệu phiên bản cũ khi còn release được hỗ trợ; đánh dấu deprecated và dẫn sang phiên bản thay thế.

## 11. Generated file, backup và binary

- Không commit binary build (`pgw-*`, file trong `cmd/*`), database/state, coverage output, log, packet capture, editor backup (`*.bak`, `*.backup`, `*.pre-*`) hoặc file sinh tạm.
- Artifact release phải do CI build từ tag, có version/commit metadata, checksum và provenance/signature theo release policy.
- Production root lifecycle chỉ bắt đầu tại launcher tĩnh root-owned đã được package/image pin. Launcher phải xóa toàn bộ environment, đặt PATH tuyệt đối, từ chối source/toolchain/checkout override và chỉ chuyển descriptor artifact đã xác minh vào installer.
- Root không build từ checkout. Release manifest có allowlist chính xác; mọi ancestor/file phải root-owned, không group/world-writable, không symlink; hash và copy/exec cùng descriptor đã mở.
- Snapshot rollback phải có provenance độc lập (HMAC/signature root-only), fsync file và directory trước mutation, durable recovery journal và restore atomic cùng filesystem hoặc fail-close có thể resume.
- Management UI bind đúng địa chỉ LAN đã validate. Bảng base phải cho phép LAN/loopback rõ ràng và chặn non-LAN IPv4 cùng IPv6 trên port management; wildcard bind là release blocker.
- File generated được phép commit chỉ khi consumer cần nó mà không có generator, hoặc project đã quyết định review generated diff. File phải có header “generated; do not edit”, lệnh/source sinh và CI check rằng regenerate không tạo diff.
- Sửa source/template/generator, không sửa generated output bằng tay. Generated output và source thay đổi trong cùng PR.
- Nếu gặp binary/backup legacy đã tracked, không cập nhật nó trong PR tính năng. Tạo cleanup PR riêng sau khi xác nhận deployment không phụ thuộc file đó và bổ sung `.gitignore` phù hợp.

## 12. Checklist tự review và review PR

Tác giả và reviewer dùng checklist này theo phạm vi thay đổi:

### Correctness và thiết kế

- [ ] Thay đổi nằm đúng process/package boundary; `cmd` chỉ ghép dependency.
- [ ] Input được validate/normalize; error có context và không bị bỏ qua.
- [ ] I/O có context/timeout; goroutine có owner, stop path và error path.
- [ ] Concurrent state không race; test race đã chạy khi liên quan.
- [ ] API/config/schema compatibility được giữ hoặc có migration/deprecation rõ.

### Security và data plane

- [ ] Không có secret trong response, log, metric, audit, argv, nft hoặc artifact.
- [ ] Authentication, RBAC, rate limit/concurrency control phù hợp với endpoint.
- [ ] Không có shell injection, path traversal hoặc quyền tiến trình tăng không cần thiết.
- [ ] Base kill-switch luôn tồn tại; mọi failure mode vẫn fail-close.
- [ ] nft rules deterministic, validated, atomic, verified và gắn generation/hash/LKG.
- [ ] Có negative/security test cho đường nhạy cảm.

### Chất lượng và vận hành

- [ ] `gofmt`, `go vet`, test, build và lint liên quan đều pass.
- [ ] Regression/integration/namespace/chaos test phù hợp đã chạy và có bằng chứng.
- [ ] Log/metric/audit đủ chẩn đoán nhưng không high-cardinality hoặc lộ dữ liệu.
- [ ] Deploy/migration có preflight, health check, backup và rollback đã test.
- [ ] API spec, config reference, docs, changelog và example đã cập nhật.
- [ ] PR không chứa binary, backup, state, credential hoặc thay đổi ngoài phạm vi.

Một PR không được xem là hoàn tất nếu reviewer chưa thể trả lời: **khi dependency hoặc apply thất bại, traffic của managed client sẽ đi đâu?** Câu trả lời hợp lệ mặc định là: bị chặn hoặc tiếp tục qua rules last-known-good đã xác minh; không bao giờ đi trực tiếp ra WAN.
