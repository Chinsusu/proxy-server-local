package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Chinsusu/proxy-server-local/internal/snapshotcrypto"
)

const usage = "usage: snapshot-crypt encrypt|verify|decrypt-publish|reconcile-publish [options]"

type commandResult struct {
	Status             string `json:"status"`
	FormatVersion      uint16 `json:"format_version"`
	SnapshotID         string `json:"snapshot_id"`
	ReleaseID          string `json:"release_id"`
	KeyID              string `json:"key_id"`
	KeyObjectSequence  uint64 `json:"key_object_sequence"`
	LogicalPath        string `json:"logical_path"`
	UID                uint32 `json:"uid"`
	GID                uint32 `json:"gid"`
	Mode               uint32 `json:"mode"`
	SourceDevice       uint64 `json:"source_device"`
	SourceInode        uint64 `json:"source_inode"`
	PlaintextLength    uint64 `json:"plaintext_length"`
	SourceMTimeNS      int64  `json:"source_mtime_ns"`
	SourceCTimeNS      int64  `json:"source_ctime_ns"`
	ChunkSize          uint32 `json:"chunk_size"`
	Input              string `json:"input,omitempty"`
	Output             string `json:"output,omitempty"`
	Destination        string `json:"destination,omitempty"`
	FinalIdentityKnown bool   `json:"final_identity_known"`
	FinalDevice        uint64 `json:"final_device"`
	FinalInode         uint64 `json:"final_inode"`
	FinalSize          uint64 `json:"final_size"`
	FinalUID           uint32 `json:"final_uid"`
	FinalGID           uint32 `json:"final_gid"`
	FinalMode          uint32 `json:"final_mode"`
}

type failureResult struct {
	Status             string                       `json:"status"`
	Outcome            snapshotcrypto.CommitOutcome `json:"outcome"`
	ExitCode           int                          `json:"exit_code"`
	Operation          string                       `json:"operation"`
	ReconcileAction    string                       `json:"reconcile_action"`
	Destination        string                       `json:"destination,omitempty"`
	FinalIdentityKnown bool                         `json:"final_identity_known"`
	FinalDevice        uint64                       `json:"final_device"`
	FinalInode         uint64                       `json:"final_inode"`
	FinalSize          uint64                       `json:"final_size"`
	FinalUID           uint32                       `json:"final_uid"`
	FinalGID           uint32                       `json:"final_gid"`
	FinalMode          uint32                       `json:"final_mode"`
}

func main() {
	if err := snapshotcrypto.HardenProcess(); err != nil {
		os.Exit(emitFailure(os.Args[1:], err, os.Stdout, os.Stderr))
	}
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr))
}

func execute(arguments []string, stdout, stderr io.Writer) int {
	err := run(arguments, stdout)
	if err == nil {
		return 0
	}
	return emitFailure(arguments, err, stdout, stderr)
}

func emitFailure(arguments []string, err error, stdout, stderr io.Writer) int {
	outcome, receipt := snapshotcrypto.ClassifyPublicationError(err)
	exitCode := snapshotcrypto.ExitCodeForOutcome(outcome)
	operation := "unknown"
	if len(arguments) > 0 {
		operation = arguments[0]
	}
	reconcile := "none"
	if outcome != snapshotcrypto.OutcomePreCommit {
		switch operation {
		case "encrypt", "verify":
			reconcile = "verify-existing-ciphertext"
		case "decrypt-publish", "reconcile-publish":
			reconcile = "reconcile-publish"
		}
	}
	payload := failureResult{
		Status: "error", Outcome: outcome, ExitCode: exitCode, Operation: operation,
		ReconcileAction: reconcile, Destination: receipt.Destination, FinalDevice: receipt.Device,
		FinalInode: receipt.Inode, FinalSize: receipt.Size, FinalUID: receipt.UID,
		FinalGID: receipt.GID, FinalMode: receipt.Mode, FinalIdentityKnown: receipt.Known,
	}
	if encodeErr := json.NewEncoder(stdout).Encode(payload); encodeErr != nil {
		fmt.Fprintf(stderr, "snapshot-crypt: result unavailable; outcome=%s exit_code=%d\n", outcome, exitCode)
	}
	return exitCode
}

func run(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New(usage)
	}
	switch arguments[0] {
	case "encrypt":
		return runEncrypt(arguments[1:], stdout)
	case "verify":
		return runVerify(arguments[1:], stdout)
	case "decrypt-publish":
		return runDecryptPublish(arguments[1:], stdout)
	case "reconcile-publish":
		return runReconcilePublish(arguments[1:], stdout)
	default:
		return errors.New(usage)
	}
}

func runEncrypt(arguments []string, stdout io.Writer) (resultErr error) {
	flags := newFlagSet("encrypt")
	keyPath := flags.String("key-file", "", "absolute snapshot master-key path")
	keyID := flags.String("key-id", "", "nonsecret immutable key-generation identifier")
	keyObjectSequenceText := flags.String("key-object-sequence", "", "unique object number under this key id")
	inputPath := flags.String("input", "", "absolute quiesced regular plaintext source")
	outputPath := flags.String("output", "", "absolute absent ciphertext destination")
	snapshotID := flags.String("snapshot-id", "", "snapshot identifier")
	releaseID := flags.String("release-id", "", "release identifier")
	logicalPath := flags.String("logical-path", "", "canonical logical path")
	sourceContract := flags.String("source-contract", "", "must be exactly quiesced")
	chunkSize := flags.Uint("chunk-size", uint(snapshotcrypto.DefaultChunkSize), "plaintext bytes per AEAD chunk")
	if err := parseFlags(flags, arguments, "encrypt"); err != nil {
		return err
	}
	if *keyPath == "" || *keyID == "" || *keyObjectSequenceText == "" || *inputPath == "" || *outputPath == "" || *snapshotID == "" || *releaseID == "" || *logicalPath == "" {
		return errors.New("encrypt requires --key-file, --key-id, --key-object-sequence, --input, --output, --snapshot-id, --release-id, and --logical-path")
	}
	if *sourceContract != "quiesced" {
		return errors.New("encrypt requires the trusted caller assertion --source-contract quiesced")
	}
	keyObjectSequence, err := parseUint64(*keyObjectSequenceText, "key-object-sequence")
	if err != nil || keyObjectSequence >= snapshotcrypto.MaxObjectsPerKeyID {
		return errors.New("key-object-sequence exceeds key rotation limit")
	}
	if uint64(*chunkSize) > uint64(^uint32(0)) {
		return errors.New("chunk-size is out of range")
	}
	key, err := snapshotcrypto.LoadKeyFile(*keyPath)
	if err != nil {
		return err
	}
	defer key.Destroy()
	input, sourceState, err := snapshotcrypto.OpenTrustedSource(*inputPath)
	if err != nil {
		return fmt.Errorf("open trusted plaintext source: %w", err)
	}
	inputOpen := true
	defer func() {
		if inputOpen {
			resultErr = errors.Join(resultErr, input.Close())
		}
	}()
	metadata := sourceState.Metadata(*snapshotID, *releaseID, *keyID, keyObjectSequence, *logicalPath, uint32(*chunkSize))
	if err := snapshotcrypto.ValidateMetadata(metadata); err != nil {
		return fmt.Errorf("source rejected before output creation: %w", err)
	}
	publisher, err := snapshotcrypto.CreateCiphertextPublisher(*outputPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, publisher.Abort()) }()
	if err := snapshotcrypto.Encrypt(publisher.File(), input, &key, metadata); err != nil {
		return err
	}
	if err := snapshotcrypto.RecheckSource(input, sourceState); err != nil {
		return err
	}
	if err := input.Close(); err != nil {
		return fmt.Errorf("close plaintext source: %w", err)
	}
	inputOpen = false
	receipt, err := publisher.Publish()
	if err != nil {
		return err
	}
	if err := writeResult(stdout, "encrypted", metadata, "", *outputPath, "", &receipt); err != nil {
		return snapshotcrypto.DurableAckFailure(receipt, err)
	}
	return nil
}

func runVerify(arguments []string, stdout io.Writer) (resultErr error) {
	flags := newFlagSet("verify")
	keyPath := flags.String("key-file", "", "absolute snapshot master-key path")
	inputPath := flags.String("input", "", "absolute trusted ciphertext input")
	expectedDeviceText := flags.String("expect-final-device", "", "optional expected ciphertext device for reconciliation")
	expectedInodeText := flags.String("expect-final-inode", "", "optional expected ciphertext inode for reconciliation")
	if err := parseFlags(flags, arguments, "verify"); err != nil {
		return err
	}
	if *keyPath == "" || *inputPath == "" {
		return errors.New("verify requires --key-file and --input")
	}
	expectedIdentity, err := optionalExpectedIdentity(*expectedDeviceText, *expectedInodeText, *inputPath)
	if err != nil {
		return err
	}
	key, err := snapshotcrypto.LoadKeyFile(*keyPath)
	if err != nil {
		return err
	}
	defer key.Destroy()
	if expectedIdentity != nil {
		handle, err := snapshotcrypto.OpenPublishedForReconciliation(*inputPath)
		if err != nil {
			return fmt.Errorf("open ciphertext for reconciliation: %w", err)
		}
		defer func() { resultErr = errors.Join(resultErr, handle.Abort()) }()
		metadata, err := snapshotcrypto.Verify(handle.File(), &key)
		if err != nil {
			return err
		}
		receipt, err := handle.ConfirmDurable(nil, expectedIdentity)
		if err != nil {
			return err
		}
		if err := writeResult(stdout, "verified", metadata, *inputPath, "", "", &receipt); err != nil {
			return snapshotcrypto.DurableAckFailure(receipt, err)
		}
		return nil
	}
	input, inputState, err := snapshotcrypto.OpenTrustedSource(*inputPath)
	if err != nil {
		return fmt.Errorf("open trusted ciphertext input: %w", err)
	}
	inputOpen := true
	defer func() {
		if inputOpen {
			resultErr = errors.Join(resultErr, input.Close())
		}
	}()
	metadata, err := snapshotcrypto.Verify(input, &key)
	if err != nil {
		return err
	}
	if err := snapshotcrypto.RecheckSource(input, inputState); err != nil {
		return fmt.Errorf("ciphertext changed during verification: %w", err)
	}
	if err := input.Close(); err != nil {
		return fmt.Errorf("close ciphertext input: %w", err)
	}
	inputOpen = false
	receipt := snapshotcrypto.ReceiptForOpenedFile(inputState, *inputPath)
	return writeResult(stdout, "verified", metadata, *inputPath, "", "", &receipt)
}

type expectedFlagPointers struct {
	snapshotID, releaseID, keyID, keyObjectSequence, logicalPath *string
	uid, gid, mode, device, inode, plaintextLength               *string
	mtimeNS, ctimeNS, chunkSize                                  *string
}

func bindExpectedFlags(flags *flag.FlagSet) expectedFlagPointers {
	return expectedFlagPointers{
		snapshotID:        flags.String("expect-snapshot-id", "", "expected authenticated snapshot id"),
		releaseID:         flags.String("expect-release-id", "", "expected authenticated release id"),
		keyID:             flags.String("expect-key-id", "", "expected authenticated key id"),
		keyObjectSequence: flags.String("expect-key-object-sequence", "", "expected authenticated key object sequence"),
		logicalPath:       flags.String("expect-logical-path", "", "expected authenticated logical path"),
		uid:               flags.String("expect-uid", "", "expected authenticated uid"),
		gid:               flags.String("expect-gid", "", "expected authenticated gid"),
		mode:              flags.String("expect-mode", "", "expected authenticated octal mode"),
		device:            flags.String("expect-device", "", "expected authenticated source device"),
		inode:             flags.String("expect-inode", "", "expected authenticated source inode"),
		plaintextLength:   flags.String("expect-plaintext-length", "", "expected authenticated plaintext length"),
		mtimeNS:           flags.String("expect-mtime-ns", "", "expected authenticated source mtime_ns"),
		ctimeNS:           flags.String("expect-ctime-ns", "", "expected authenticated source ctime_ns"),
		chunkSize:         flags.String("expect-chunk-size", "", "expected authenticated chunk size"),
	}
}

func (values expectedFlagPointers) metadata() (snapshotcrypto.ExpectedMetadata, error) {
	all := []*string{values.snapshotID, values.releaseID, values.keyID, values.keyObjectSequence, values.logicalPath, values.uid, values.gid, values.mode, values.device, values.inode, values.plaintextLength, values.mtimeNS, values.ctimeNS, values.chunkSize}
	for _, value := range all {
		if *value == "" {
			return snapshotcrypto.Metadata{}, errors.New("decrypt-publish requires every --expect-* metadata flag")
		}
	}
	keySequence, err := parseUint64(*values.keyObjectSequence, "expect-key-object-sequence")
	if err != nil {
		return snapshotcrypto.Metadata{}, err
	}
	uid, err := parseUint32(*values.uid, "expect-uid")
	if err != nil {
		return snapshotcrypto.Metadata{}, err
	}
	gid, err := parseUint32(*values.gid, "expect-gid")
	if err != nil {
		return snapshotcrypto.Metadata{}, err
	}
	mode, err := parseMode(*values.mode)
	if err != nil {
		return snapshotcrypto.Metadata{}, err
	}
	device, err := parseUint64(*values.device, "expect-device")
	if err != nil {
		return snapshotcrypto.Metadata{}, err
	}
	inode, err := parseUint64(*values.inode, "expect-inode")
	if err != nil {
		return snapshotcrypto.Metadata{}, err
	}
	length, err := parseUint64(*values.plaintextLength, "expect-plaintext-length")
	if err != nil {
		return snapshotcrypto.Metadata{}, err
	}
	mtime, err := parseInt64(*values.mtimeNS, "expect-mtime-ns")
	if err != nil {
		return snapshotcrypto.Metadata{}, err
	}
	ctime, err := parseInt64(*values.ctimeNS, "expect-ctime-ns")
	if err != nil {
		return snapshotcrypto.Metadata{}, err
	}
	chunk, err := parseUint32(*values.chunkSize, "expect-chunk-size")
	if err != nil {
		return snapshotcrypto.Metadata{}, err
	}
	return snapshotcrypto.Metadata{
		FormatVersion: snapshotcrypto.FormatVersion, SnapshotID: *values.snapshotID, ReleaseID: *values.releaseID,
		KeyID: *values.keyID, KeyObjectSequence: keySequence, LogicalPath: *values.logicalPath,
		UID: uid, GID: gid, Mode: mode, SourceDevice: device, SourceInode: inode,
		PlaintextLength: length, SourceMTimeNS: mtime, SourceCTimeNS: ctime, ChunkSize: chunk,
	}, nil
}

func runDecryptPublish(arguments []string, stdout io.Writer) (resultErr error) {
	flags := newFlagSet("decrypt-publish")
	keyPath := flags.String("key-file", "", "absolute snapshot master-key path")
	inputPath := flags.String("input", "", "absolute trusted ciphertext input")
	destination := flags.String("destination", "", "absolute absent publication destination")
	expectedValues := bindExpectedFlags(flags)
	if err := parseFlags(flags, arguments, "decrypt-publish"); err != nil {
		return err
	}
	if *keyPath == "" || *inputPath == "" || *destination == "" {
		return errors.New("decrypt-publish requires --key-file, --input, and --destination")
	}
	expected, err := expectedValues.metadata()
	if err != nil {
		return err
	}
	if err := snapshotcrypto.ValidateExpected(expected); err != nil {
		return fmt.Errorf("invalid expected metadata: %w", err)
	}
	key, err := snapshotcrypto.LoadKeyFile(*keyPath)
	if err != nil {
		return err
	}
	defer key.Destroy()
	input, inputState, err := snapshotcrypto.OpenTrustedSource(*inputPath)
	if err != nil {
		return fmt.Errorf("open trusted ciphertext input: %w", err)
	}
	inputOpen := true
	defer func() {
		if inputOpen {
			resultErr = errors.Join(resultErr, input.Close())
		}
	}()
	publisher, err := snapshotcrypto.CreatePlaintextPublisher(*destination)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, publisher.Abort()) }()
	metadata, err := snapshotcrypto.Decrypt(publisher.File(), input, &key)
	if err != nil {
		return err
	}
	if err := snapshotcrypto.MatchExpected(metadata, expected); err != nil {
		return err
	}
	if err := snapshotcrypto.RecheckSource(input, inputState); err != nil {
		return fmt.Errorf("ciphertext changed during decryption: %w", err)
	}
	if err := input.Close(); err != nil {
		return fmt.Errorf("close ciphertext input: %w", err)
	}
	inputOpen = false
	receipt, err := publisher.Publish(metadata.UID, metadata.GID, metadata.Mode, metadata.PlaintextLength)
	if err != nil {
		return err
	}
	if err := writeResult(stdout, "published", metadata, *inputPath, "", *destination, &receipt); err != nil {
		return snapshotcrypto.DurableAckFailure(receipt, err)
	}
	return nil
}

func runReconcilePublish(arguments []string, stdout io.Writer) (resultErr error) {
	flags := newFlagSet("reconcile-publish")
	keyPath := flags.String("key-file", "", "absolute snapshot master-key path")
	inputPath := flags.String("input", "", "absolute trusted ciphertext input")
	destination := flags.String("destination", "", "absolute existing publication destination")
	expectedFinalDevice := flags.String("expect-final-device", "", "optional prior publication receipt device")
	expectedFinalInode := flags.String("expect-final-inode", "", "optional prior publication receipt inode")
	expectedValues := bindExpectedFlags(flags)
	if err := parseFlags(flags, arguments, "reconcile-publish"); err != nil {
		return err
	}
	if *keyPath == "" || *inputPath == "" || *destination == "" {
		return errors.New("reconcile-publish requires --key-file, --input, and --destination")
	}
	expected, err := expectedValues.metadata()
	if err != nil {
		return err
	}
	if err := snapshotcrypto.ValidateExpected(expected); err != nil {
		return fmt.Errorf("invalid expected metadata: %w", err)
	}
	expectedIdentity, err := optionalExpectedIdentity(*expectedFinalDevice, *expectedFinalInode, *destination)
	if err != nil {
		return err
	}
	key, err := snapshotcrypto.LoadKeyFile(*keyPath)
	if err != nil {
		return err
	}
	defer key.Destroy()
	ciphertext, ciphertextState, err := snapshotcrypto.OpenTrustedSource(*inputPath)
	if err != nil {
		return err
	}
	ciphertextOpen := true
	defer func() {
		if ciphertextOpen {
			resultErr = errors.Join(resultErr, ciphertext.Close())
		}
	}()
	final, err := snapshotcrypto.OpenPublishedForReconciliation(*destination)
	if err != nil {
		return fmt.Errorf("open existing published file: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, final.Abort()) }()
	comparison := &comparisonWriter{source: final.File()}
	metadata, err := snapshotcrypto.Decrypt(comparison, ciphertext, &key)
	if err != nil {
		return err
	}
	if err := comparison.Finish(); err != nil {
		return err
	}
	if err := snapshotcrypto.MatchExpected(metadata, expected); err != nil {
		return err
	}
	if err := snapshotcrypto.RecheckSource(ciphertext, ciphertextState); err != nil {
		return fmt.Errorf("ciphertext changed during reconciliation: %w", err)
	}
	if err := ciphertext.Close(); err != nil {
		return fmt.Errorf("close ciphertext input: %w", err)
	}
	ciphertextOpen = false
	receipt, err := final.ConfirmDurable(&expected, expectedIdentity)
	if err != nil {
		return err
	}
	if err := writeResult(stdout, "reconciled", metadata, *inputPath, "", *destination, &receipt); err != nil {
		return snapshotcrypto.DurableAckFailure(receipt, err)
	}
	return nil
}

func optionalExpectedIdentity(deviceText, inodeText, destination string) (*snapshotcrypto.PublicationReceipt, error) {
	if (deviceText == "") != (inodeText == "") {
		return nil, errors.New("both --expect-final-device and --expect-final-inode are required when either is set")
	}
	if deviceText == "" {
		return nil, nil
	}
	device, err := parseUint64(deviceText, "expect-final-device")
	if err != nil {
		return nil, err
	}
	inode, err := parseUint64(inodeText, "expect-final-inode")
	if err != nil {
		return nil, err
	}
	return &snapshotcrypto.PublicationReceipt{Destination: destination, Known: true, Device: device, Inode: inode}, nil
}

type comparisonWriter struct{ source io.Reader }

func (writer *comparisonWriter) Write(plaintext []byte) (int, error) {
	comparison := make([]byte, len(plaintext))
	defer zero(comparison)
	if _, err := io.ReadFull(writer.source, comparison); err != nil {
		return 0, errors.New("published file is shorter than authenticated plaintext")
	}
	if !bytes.Equal(comparison, plaintext) {
		return 0, errors.New("published file content does not match authenticated plaintext")
	}
	return len(plaintext), nil
}

func (writer *comparisonWriter) Finish() error {
	var extra [1]byte
	count, err := io.ReadFull(writer.source, extra[:])
	if count != 0 || err == nil {
		return errors.New("published file is longer than authenticated plaintext")
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return fmt.Errorf("read published file during reconciliation: %w", err)
}

func zero(contents []byte) {
	for index := range contents {
		contents[index] = 0
	}
}

func newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

func parseFlags(flags *flag.FlagSet, arguments []string, command string) error {
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%s accepts no positional arguments", command)
	}
	return nil
}

func parseUint32(value, label string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid %s", label)
	}
	return uint32(parsed), nil
}

func parseUint64(value, label string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s", label)
	}
	return parsed, nil
}

func parseInt64(value, label string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s", label)
	}
	return parsed, nil
}

func parseMode(value string) (uint32, error) {
	if len(value) < 3 || len(value) > 4 {
		return 0, errors.New("mode must contain three or four octal digits")
	}
	for _, character := range value {
		if character < '0' || character > '7' {
			return 0, errors.New("mode must contain three or four octal digits")
		}
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil || parsed > 0o7777 {
		return 0, errors.New("invalid mode")
	}
	return uint32(parsed), nil
}

func writeResult(stdout io.Writer, status string, metadata snapshotcrypto.Metadata, input, output, destination string, receipt *snapshotcrypto.PublicationReceipt) error {
	result := commandResult{
		Status: status, FormatVersion: metadata.FormatVersion, SnapshotID: metadata.SnapshotID,
		ReleaseID: metadata.ReleaseID, KeyID: metadata.KeyID, KeyObjectSequence: metadata.KeyObjectSequence,
		LogicalPath: metadata.LogicalPath, UID: metadata.UID, GID: metadata.GID, Mode: metadata.Mode,
		SourceDevice: metadata.SourceDevice, SourceInode: metadata.SourceInode,
		PlaintextLength: metadata.PlaintextLength, SourceMTimeNS: metadata.SourceMTimeNS,
		SourceCTimeNS: metadata.SourceCTimeNS, ChunkSize: metadata.ChunkSize,
		Input: input, Output: output, Destination: destination,
	}
	if receipt != nil {
		result.FinalIdentityKnown = receipt.Known
		result.FinalDevice, result.FinalInode, result.FinalSize = receipt.Device, receipt.Inode, receipt.Size
		result.FinalUID, result.FinalGID, result.FinalMode = receipt.UID, receipt.GID, receipt.Mode
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("write result metadata: %w", err)
	}
	return nil
}
