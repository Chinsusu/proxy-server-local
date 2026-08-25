package sqlite

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
)

type cancelAfterFirstRead struct {
	reader io.Reader
	cancel context.CancelFunc
	done   bool
}

func (r *cancelAfterFirstRead) Read(buffer []byte) (int, error) {
	count, err := r.reader.Read(buffer)
	if !r.done {
		r.done = true
		r.cancel()
	}
	return count, err
}

const validLegacyState = `{
  "proxies": {"p1": {"id":"p1","label":"legacy","type":"http","host":"proxy.example","port":8080,"username":"alice","password":"import-canary","enabled":true,"status":"DOWN"}},
  "clients": {"c1": {"id":"c1","ip_cidr":"192.168.2.101","note":"legacy client","enabled":true}},
  "mappings": {"m1": {"id":"m1","client_id":"c1","proxy_id":"p1","protocol":"http","local_redirect_port":15001,"state":"APPLIED"}}
}`

func TestImportStateDryRunAtomicIdempotentAndRedacted(t *testing.T) {
	repository := openTestRepository(t)
	ctx := context.Background()
	dryRun, err := repository.ImportState(ctx, strings.NewReader(validLegacyState), ImportOptions{DryRun: true, Actor: "migration"})
	if err != nil || dryRun.Proxies != 1 || dryRun.Clients != 1 || dryRun.Mappings != 1 {
		t.Fatalf("dry run counts=%d/%d/%d err=%v", dryRun.Proxies, dryRun.Clients, dryRun.Mappings, err)
	}
	var count int
	if err := repository.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM proxies`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("dry run wrote rows count=%d err=%v", count, err)
	}

	report, err := repository.ImportState(ctx, strings.NewReader(validLegacyState), ImportOptions{Actor: "migration"})
	if err != nil {
		t.Fatal(err)
	}
	if report.AlreadyImported || report.Checksum == "" || len(report.Warnings) == 0 {
		t.Fatalf("unexpected import report already=%t checksum_present=%t warnings=%d", report.AlreadyImported, report.Checksum != "", len(report.Warnings))
	}
	proxy, err := repository.GetProxy(ctx, "p1")
	if err != nil || !proxy.PasswordConfigured {
		t.Fatalf("proxy configured=%t err=%v", proxy.PasswordConfigured, err)
	}
	mapping, err := repository.GetMapping(ctx, "m1")
	if err != nil || mapping.PolicyID != "default-web-only" || mapping.DesiredState != domain.DesiredDraft {
		t.Fatalf("mapping policy=%q state=%q err=%v", mapping.PolicyID, mapping.DesiredState, err)
	}
	var ciphertext []byte
	if err := repository.DB().QueryRowContext(ctx, `SELECT ciphertext FROM proxy_secrets WHERE proxy_id = 'p1'`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("import-canary")) {
		t.Fatal("imported plaintext is stored in ciphertext")
	}
	var eventCount int
	if err := repository.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE action = 'migration.import_v1'`).Scan(&eventCount); err != nil || eventCount != 3 {
		t.Fatalf("import audits=%d err=%v", eventCount, err)
	}

	retry, err := repository.ImportState(ctx, strings.NewReader(validLegacyState), ImportOptions{Actor: "migration"})
	if err != nil || !retry.AlreadyImported {
		t.Fatalf("idempotent retry already=%t err=%v", retry.AlreadyImported, err)
	}
}

func TestImportStateRejectsUnknownFieldsAndReportsExistingDuplicates(t *testing.T) {
	repository := openTestRepository(t)
	ctx := context.Background()
	invalid := strings.Replace(validLegacyState, `"enabled":true,"status"`, `"enabled":true,"unknown":1,"status"`, 1)
	if _, err := repository.ImportState(ctx, strings.NewReader(invalid), ImportOptions{}); err == nil {
		t.Fatal("unknown field import succeeded")
	} else {
		var validation *domain.ValidationError
		if !errors.As(err, &validation) {
			t.Fatalf("want validation got %T %v", err, err)
		}
	}
	if _, err := repository.ImportState(ctx, strings.NewReader(validLegacyState), ImportOptions{}); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(validLegacyState, `"label":"legacy"`, `"label":"different"`, 1)
	report, err := repository.ImportState(ctx, strings.NewReader(changed), ImportOptions{})
	if err == nil {
		t.Fatal("conflicting import succeeded")
	}
	var conflict *ImportConflictError
	if !errors.As(err, &conflict) || len(report.Duplicates) != 3 {
		t.Fatalf("duplicates=%d err=%T %v", len(report.Duplicates), err, err)
	}
}

func TestImportStateRejectsNestedDuplicateJSONKeys(t *testing.T) {
	repository := openTestRepository(t)
	duplicate := strings.Replace(validLegacyState, `"host":"proxy.example"`, `"host":"proxy.example","host":"shadow.example"`, 1)
	if _, err := repository.ImportState(context.Background(), strings.NewReader(duplicate), ImportOptions{DryRun: true}); err == nil {
		t.Fatal("nested duplicate key import succeeded")
	} else {
		var validation *domain.ValidationError
		if !errors.As(err, &validation) {
			t.Fatalf("expected validation error, got %T", err)
		}
	}
}

func TestNestedJSONValidationHonorsCancellationAndTokenBudget(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rejectDuplicateJSONKeys(canceled, []byte(`{"a":1}`)); err == nil {
		t.Fatal("canceled nested validation succeeded")
	}
	var document strings.Builder
	document.WriteByte('[')
	for i := 0; i <= maxLegacyJSONTokens; i++ {
		if i > 0 {
			document.WriteByte(',')
		}
		document.WriteByte('0')
	}
	document.WriteByte(']')
	if err := rejectDuplicateJSONKeys(context.Background(), []byte(document.String())); err == nil {
		t.Fatal("nested token budget was not enforced")
	}
}

func TestImportStateChecksContextDuringLargeDecode(t *testing.T) {
	repository := openTestRepository(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	large := `{"proxies":{"p1":{"id":"p1","label":"` + strings.Repeat("x", maxLegacyFieldBytes*8) + `","type":"http","host":"proxy.example","port":8080}},"clients":{},"mappings":{}}`
	reader := &cancelAfterFirstRead{reader: strings.NewReader(large), cancel: cancel}
	if _, err := repository.ImportState(ctx, reader, ImportOptions{DryRun: true}); !errors.Is(err, context.Canceled) {
		t.Fatalf("large decode cancellation error=%v", err)
	}
}

func TestLegacySecretUsesBytesAndPreservesNullMissingSemantics(t *testing.T) {
	state, err := decodeLegacyState(context.Background(), strings.NewReader(`{
        "proxies": {
          "missing": {"id":"missing","type":"http","host":"proxy.example","port":8080},
          "null": {"id":"null","type":"http","host":"proxy.example","port":8080,"password":null},
          "escaped": {"id":"escaped","type":"http","host":"proxy.example","port":8080,"password":"a\n\uD83D\uDE00"}
        }, "clients": {}, "mappings": {}
    }`))
	if err != nil {
		t.Fatal(err)
	}
	if state.Proxies["missing"].Password.set || state.Proxies["null"].Password.bytes != nil || !state.Proxies["null"].Password.set {
		t.Fatal("missing/null password semantics changed")
	}
	secret := state.Proxies["escaped"].Password.bytes
	if !bytes.Equal(secret, []byte("a\n😀")) {
		t.Fatalf("secret decode mismatch length=%d", len(secret))
	}
	zeroLegacyStateSecrets(state)
	if len(state.Proxies["escaped"].Password.bytes) != 0 {
		t.Fatal("legacy secret bytes were not wiped")
	}
}

func TestPartialDecodeErrorWipesByteBackedSecrets(t *testing.T) {
	wipes := 0
	legacySecretWipeHook = func() { wipes++ }
	defer func() { legacySecretWipeHook = nil }()
	state, err := decodeLegacyState(context.Background(), strings.NewReader(`{
        "proxies": {"p1":{"id":"p1","type":"http","host":"proxy.example","port":8080,"password":"transient"}},
        "unknown": {}
    }`))
	if err == nil {
		t.Fatal("partial decode with unknown field succeeded")
	}
	if wipes == 0 || len(state.Proxies["p1"].Password.bytes) != 0 {
		t.Fatalf("partial secret cleanup failed wipes=%d secret_length=%d", wipes, len(state.Proxies["p1"].Password.bytes))
	}
}

func TestImportStateDryRunReportsCIDRCollisionAndConcurrentRetryIsIdempotent(t *testing.T) {
	repository := openTestRepository(t)
	ctx := context.Background()
	if _, err := repository.CreateClient(ctx, CreateClientInput{ID: "other", IPCIDR: "192.168.2.101/32", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	report, err := repository.ImportState(ctx, strings.NewReader(validLegacyState), ImportOptions{DryRun: true})
	if err == nil {
		t.Fatal("dry run CIDR collision succeeded")
	}
	var conflict *ImportConflictError
	if !errors.As(err, &conflict) || !contains(report.Duplicates, "client_ip_cidr:192.168.2.101/32") {
		t.Fatalf("duplicates=%d err=%v", len(report.Duplicates), err)
	}

	// Use a fresh repository for concurrent identical import: one caller writes,
	// the other must observe the committed checksum and return AlreadyImported.
	repository = openTestRepository(t)
	start := make(chan struct{})
	type result struct {
		report ImportReport
		err    error
	}
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			report, err := repository.ImportState(ctx, strings.NewReader(validLegacyState), ImportOptions{Actor: "parallel"})
			results <- result{report: report, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	imports, retries := 0, 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent import err=%v already=%t", result.err, result.report.AlreadyImported)
		}
		if result.report.AlreadyImported {
			retries++
		} else {
			imports++
		}
	}
	if imports != 1 || retries != 1 {
		t.Fatalf("imports=%d retries=%d", imports, retries)
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
