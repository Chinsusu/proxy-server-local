//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/snapshotcrypto"
)

func TestSnapshotCryptCLIChild(t *testing.T) {
	encoded := os.Getenv("PGW_SNAPSHOT_CLI_TEST_ARGS")
	if encoded == "" {
		return
	}
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		os.Exit(99)
	}
	var arguments []string
	if json.Unmarshal(payload, &arguments) != nil || snapshotcrypto.HardenProcess() != nil {
		os.Exit(99)
	}
	os.Exit(execute(arguments, os.Stdout, os.Stderr))
}

func TestLinuxExecutableEncryptVerifyDecryptPublishAndNegatives(t *testing.T) {
	directory := cliTrustedRootTemp(t)
	probe, err := snapshotcrypto.CreateCiphertextPublisher(filepath.Join(directory, "probe"))
	if err != nil {
		t.Skipf("O_TMPFILE/linkat publication unavailable: %v", err)
	}
	if err := probe.Abort(); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "key")
	wrongKeyPath := filepath.Join(directory, "wrong-key")
	writeKey := func(path string, fill byte) {
		if err := os.WriteFile(path, bytes.Repeat([]byte{fill}, snapshotcrypto.KeySize), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeKey(keyPath, 1)
	writeKey(wrongKeyPath, 2)
	plaintext := bytes.Repeat([]byte("authenticated rollback payload|"), 1000)
	source := filepath.Join(directory, "source")
	if err := os.WriteFile(source, plaintext, 0o640); err != nil {
		t.Fatal(err)
	}
	ciphertext := filepath.Join(directory, "object.pgw")
	encryptArgs := []string{"encrypt", "--key-file", keyPath, "--key-id", "key-gen-1", "--key-object-sequence", "7", "--input", source, "--output", ciphertext, "--snapshot-id", "snap-1", "--release-id", "release-1", "--logical-path", "/etc/pgw/source", "--source-contract", "quiesced", "--chunk-size", strconv.FormatUint(uint64(snapshotcrypto.MinChunkSize), 10)}
	output, code := runCLIProcess(t, encryptArgs)
	if code != 0 {
		t.Fatalf("encrypt exit=%d output=%s", code, output)
	}
	var encrypted commandResult
	if err := json.Unmarshal(output, &encrypted); err != nil {
		t.Fatal(err)
	}
	verifyOutput, code := runCLIProcess(t, []string{"verify", "--key-file", keyPath, "--input", ciphertext, "--expect-final-device", strconv.FormatUint(encrypted.FinalDevice, 10), "--expect-final-inode", strconv.FormatUint(encrypted.FinalInode, 10)})
	if code != 0 {
		t.Fatalf("verify exit=%d output=%s", code, verifyOutput)
	}
	var verified commandResult
	if err := json.Unmarshal(verifyOutput, &verified); err != nil || verified.FinalInode != encrypted.FinalInode {
		t.Fatalf("verify receipt mismatch: %+v error=%v", verified, err)
	}
	if mismatchOutput, mismatchCode := runCLIProcess(t, []string{"verify", "--key-file", keyPath, "--input", ciphertext, "--expect-final-device", strconv.FormatUint(encrypted.FinalDevice, 10), "--expect-final-inode", strconv.FormatUint(encrypted.FinalInode+1, 10)}); mismatchCode != snapshotcrypto.ExitPreCommit {
		t.Fatalf("verify inode mismatch exit=%d output=%s", mismatchCode, mismatchOutput)
	}
	destination := filepath.Join(directory, "published")
	decryptArgs := append([]string{"decrypt-publish", "--key-file", keyPath, "--input", ciphertext, "--destination", destination}, expectedArguments(encrypted)...)
	decryptOutput, code := runCLIProcess(t, decryptArgs)
	if code != 0 {
		t.Fatalf("decrypt-publish exit=%d output=%s", code, decryptOutput)
	}
	var published commandResult
	if err := json.Unmarshal(decryptOutput, &published); err != nil || !published.FinalIdentityKnown {
		t.Fatalf("decrypt-publish receipt missing: %+v error=%v", published, err)
	}
	if restored, err := os.ReadFile(destination); err != nil || !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored mismatch error=%v", err)
	}
	reconcilePrefix := []string{
		"reconcile-publish", "--key-file", keyPath, "--input", ciphertext, "--destination", destination,
		"--expect-final-device", strconv.FormatUint(published.FinalDevice, 10),
		"--expect-final-inode", strconv.FormatUint(published.FinalInode, 10),
	}
	reconcileOutput, code := runCLIProcess(t, append(reconcilePrefix, expectedArguments(encrypted)...))
	if code != 0 {
		t.Fatalf("reconcile exit=%d output=%s", code, reconcileOutput)
	}
	if wrongOutput, wrongCode := runCLIProcess(t, []string{"verify", "--key-file", wrongKeyPath, "--input", ciphertext}); wrongCode != snapshotcrypto.ExitPreCommit {
		t.Fatalf("wrong-key verify exit=%d output=%s", wrongCode, wrongOutput)
	}
	mismatch := encrypted
	mismatch.SourceInode++
	mismatchDestination := filepath.Join(directory, "metadata-mismatch")
	mismatchOutput, mismatchCode := runCLIProcess(t, append([]string{"decrypt-publish", "--key-file", keyPath, "--input", ciphertext, "--destination", mismatchDestination}, expectedArguments(mismatch)...))
	if mismatchCode != snapshotcrypto.ExitPreCommit {
		t.Fatalf("metadata mismatch exit=%d output=%s", mismatchCode, mismatchOutput)
	}
	if _, err := os.Stat(mismatchDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("metadata mismatch published destination: %v", err)
	}
	racedDestination := filepath.Join(directory, "raced")
	if err := os.WriteFile(racedDestination, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	raceOutput, raceCode := runCLIProcess(t, append([]string{"decrypt-publish", "--key-file", keyPath, "--input", ciphertext, "--destination", racedDestination}, expectedArguments(encrypted)...))
	if raceCode != snapshotcrypto.ExitPreCommit {
		t.Fatalf("raced destination exit=%d output=%s", raceCode, raceOutput)
	}
	if live, _ := os.ReadFile(racedDestination); string(live) != "live" {
		t.Fatal("raced destination was overwritten")
	}
}

func TestLinuxExecutableRejectsOversizeBeforeOutputAndConcurrentMutation(t *testing.T) {
	directory := cliTrustedRootTemp(t)
	keyPath := filepath.Join(directory, "key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{1}, snapshotcrypto.KeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	oversize := filepath.Join(directory, "oversize")
	file, err := os.OpenFile(oversize, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(snapshotcrypto.MaxPlaintextPerObject + 1)); err != nil {
		t.Fatal(err)
	}
	file.Close()
	oversizeOutput := filepath.Join(directory, "oversize.pgw")
	arguments := encryptTestArguments(keyPath, oversize, oversizeOutput, 1)
	if output, code := runCLIProcess(t, arguments); code != snapshotcrypto.ExitPreCommit {
		t.Fatalf("oversize exit=%d output=%s", code, output)
	}
	if _, err := os.Stat(oversizeOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversize source created output: %v", err)
	}

	mutable := filepath.Join(directory, "mutable")
	mutableFile, err := os.OpenFile(mutable, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := mutableFile.Truncate(128 << 20); err != nil {
		t.Fatal(err)
	}
	mutableFile.Close()
	mutableOutput := filepath.Join(directory, "mutable.pgw")
	command := cliProcess(t, encryptTestArguments(keyPath, mutable, mutableOutput, 2))
	var stdout bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stdout
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		writer, openErr := os.OpenFile(mutable, os.O_WRONLY, 0)
		if openErr != nil {
			return
		}
		defer writer.Close()
		value := byte(1)
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = writer.WriteAt([]byte{value}, 0)
				_ = writer.Sync()
				value++
				time.Sleep(time.Millisecond)
			}
		}
	}()
	err = command.Wait()
	close(stop)
	if exitCode(err) != snapshotcrypto.ExitPreCommit {
		t.Fatalf("mutating source exit=%d output=%s error=%v", exitCode(err), stdout.Bytes(), err)
	}
	if _, err := os.Stat(mutableOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mutating source created output: %v", err)
	}
}

func cliTrustedRootTemp(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root required for executable publication tests")
	}
	directory, err := os.MkdirTemp("/root", "pgw-snapshot-cli-test-")
	if err != nil {
		t.Skipf("trusted test directory unavailable: %v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func expectedArguments(result commandResult) []string {
	return []string{
		"--expect-snapshot-id", result.SnapshotID, "--expect-release-id", result.ReleaseID,
		"--expect-key-id", result.KeyID, "--expect-key-object-sequence", strconv.FormatUint(result.KeyObjectSequence, 10),
		"--expect-logical-path", result.LogicalPath, "--expect-uid", strconv.FormatUint(uint64(result.UID), 10),
		"--expect-gid", strconv.FormatUint(uint64(result.GID), 10), "--expect-mode", fmt.Sprintf("%04o", result.Mode),
		"--expect-device", strconv.FormatUint(result.SourceDevice, 10), "--expect-inode", strconv.FormatUint(result.SourceInode, 10),
		"--expect-plaintext-length", strconv.FormatUint(result.PlaintextLength, 10), "--expect-mtime-ns", strconv.FormatInt(result.SourceMTimeNS, 10),
		"--expect-ctime-ns", strconv.FormatInt(result.SourceCTimeNS, 10), "--expect-chunk-size", strconv.FormatUint(uint64(result.ChunkSize), 10),
	}
}

func encryptTestArguments(key, source, output string, sequence uint64) []string {
	return []string{"encrypt", "--key-file", key, "--key-id", "key-gen-1", "--key-object-sequence", strconv.FormatUint(sequence, 10), "--input", source, "--output", output, "--snapshot-id", "snap-1", "--release-id", "release-1", "--logical-path", "/etc/pgw/source", "--source-contract", "quiesced", "--chunk-size", strconv.FormatUint(uint64(snapshotcrypto.MinChunkSize), 10)}
}

func runCLIProcess(t *testing.T, arguments []string) ([]byte, int) {
	t.Helper()
	command := cliProcess(t, arguments)
	output, err := command.CombinedOutput()
	return output, exitCode(err)
}

func cliProcess(t *testing.T, arguments []string) *exec.Cmd {
	t.Helper()
	payload, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestSnapshotCryptCLIChild$")
	command.Env = append(os.Environ(), "PGW_SNAPSHOT_CLI_TEST_ARGS="+base64.StdEncoding.EncodeToString(payload))
	return command
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}
