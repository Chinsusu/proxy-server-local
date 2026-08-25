package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Chinsusu/proxy-server-local/internal/snapshotcrypto"
)

func TestParseModeAndNumericIDs(t *testing.T) {
	t.Parallel()
	mode, err := parseMode("0640")
	if err != nil || mode != 0o640 {
		t.Fatalf("parseMode = %#o, %v", mode, err)
	}
	for input, expected := range map[string]uint32{"0000": 0o0000, "7777": 0o7777} {
		if mode, err := parseMode(input); err != nil || mode != expected {
			t.Fatalf("parseMode(%q) = %#o, %v", input, mode, err)
		}
	}
	for _, invalid := range []string{"", "88", "60000", "06x0", "0o600"} {
		if _, err := parseMode(invalid); err == nil {
			t.Fatalf("parseMode(%q) accepted", invalid)
		}
	}
	if value, err := parseUint32("4294967295", "uid"); err != nil || value != ^uint32(0) {
		t.Fatalf("parseUint32 max = %d, %v", value, err)
	}
	if _, err := parseUint32("-1", "uid"); err == nil {
		t.Fatal("negative uid accepted")
	}
}

func TestResultWriteFailureIsReturned(t *testing.T) {
	t.Parallel()
	failure := errors.New("stdout closed")
	if err := writeResult(errorWriter{failure}, "verified", snapshotcrypto.Metadata{}, "", "", "", nil); !errors.Is(err, failure) {
		t.Fatalf("writeResult error = %v", err)
	}
}

type errorWriter struct{ err error }

func (writer errorWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestResultJSONContract(t *testing.T) {
	t.Parallel()
	metadata := snapshotcrypto.Metadata{
		FormatVersion: snapshotcrypto.FormatVersion, SnapshotID: "s", ReleaseID: "r", KeyID: "k",
		KeyObjectSequence: 7, LogicalPath: "/etc/pgw/a", UID: 1, GID: 2, Mode: 0o600,
		SourceDevice: 3, SourceInode: 4, PlaintextLength: 5, SourceMTimeNS: 6,
		SourceCTimeNS: 7, ChunkSize: snapshotcrypto.MinChunkSize,
	}
	var output bytes.Buffer
	if err := writeResult(&output, "published", metadata, "/cipher", "", "/live", nil); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not one JSON object: %v", err)
	}
	if result["status"] != "published" || result["destination"] != "/live" || result["key_object_sequence"] != float64(7) {
		t.Fatalf("unexpected JSON result: %v", result)
	}
	if _, exists := result["temporary_path"]; exists {
		t.Fatal("plaintext temporary path leaked into v2 JSON contract")
	}
	if _, exists := result["output"]; exists {
		t.Fatal("empty output field was not omitted")
	}
}

func TestRunRejectsUnknownAndMissingFlagsWithoutOutput(t *testing.T) {
	t.Parallel()
	for _, arguments := range [][]string{{}, {"unknown"}, {"decrypt"}, {"verify"}, {"encrypt", "--unknown"}} {
		var stdout bytes.Buffer
		if err := run(arguments, &stdout); err == nil {
			t.Fatalf("run(%v) succeeded", arguments)
		}
		if stdout.Len() != 0 {
			t.Fatalf("run(%v) wrote success output", arguments)
		}
	}
}

func TestTypedFailureExitAndJSONContracts(t *testing.T) {
	t.Parallel()
	receipt := snapshotcrypto.PublicationReceipt{Destination: "/safe/final", Known: true, Device: 1, Inode: 2, Size: 3, UID: 4, GID: 5, Mode: 0o640}
	tests := []struct {
		outcome snapshotcrypto.CommitOutcome
		code    int
	}{
		{snapshotcrypto.OutcomePreCommit, snapshotcrypto.ExitPreCommit},
		{snapshotcrypto.OutcomeCommitIndeterminate, snapshotcrypto.ExitCommitIndeterminate},
		{snapshotcrypto.OutcomeDurabilityIndeterminate, snapshotcrypto.ExitDurabilityIndeterminate},
		{snapshotcrypto.OutcomeDurableAckFailure, snapshotcrypto.ExitDurableAckFailure},
	}
	for _, test := range tests {
		var stdout, stderr bytes.Buffer
		err := &snapshotcrypto.PublicationError{Outcome: test.outcome, Receipt: receipt, Cause: errors.New("injected")}
		if code := emitFailure([]string{"decrypt-publish"}, err, &stdout, &stderr); code != test.code {
			t.Fatalf("outcome %s exit=%d want=%d", test.outcome, code, test.code)
		}
		var result failureResult
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("outcome %s JSON: %v", test.outcome, err)
		}
		if result.Outcome != test.outcome || result.ExitCode != test.code || result.Destination != receipt.Destination || !result.FinalIdentityKnown {
			t.Fatalf("outcome %s result=%+v", test.outcome, result)
		}
	}
}

func TestCommittedStdoutFailurePreservesExitCode(t *testing.T) {
	t.Parallel()
	failure := errors.New("stdout unavailable")
	receipt := snapshotcrypto.PublicationReceipt{Destination: "/safe/final", Inode: 2}
	err := snapshotcrypto.DurableAckFailure(receipt, failure)
	var stderr bytes.Buffer
	if code := emitFailure([]string{"encrypt"}, err, errorWriter{failure}, &stderr); code != snapshotcrypto.ExitDurableAckFailure {
		t.Fatalf("exit=%d", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("outcome=durable_committed_ack_failure exit_code=30")) {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
