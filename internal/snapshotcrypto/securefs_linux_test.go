//go:build linux

package snapshotcrypto

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func trustedRootTemp(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root required for root-owned publication contract")
	}
	directory, err := os.MkdirTemp("/root", "pgw-snapshotcrypto-test-")
	if err != nil {
		t.Skipf("cannot allocate trusted root test directory: %v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func trustedCallerTemp(t *testing.T) string {
	t.Helper()
	parent, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(parent, ".pgw-snapshotcrypto-caller-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func TestTrustedSourceAllowsPrivateCallerOwnedTree(t *testing.T) {
	directory := trustedCallerTemp(t)
	source := filepath.Join(directory, "source")
	if err := os.WriteFile(source, []byte("snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, _, err := OpenTrustedSource(source)
	if err != nil {
		t.Fatalf("caller-owned trusted source rejected: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	publisher, err := CreateCiphertextPublisher(filepath.Join(directory, "ciphertext"))
	if err != nil {
		t.Fatalf("create caller-owned ciphertext publisher: %v", err)
	}
	if _, err := publisher.File().Write([]byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(); err != nil {
		t.Fatalf("publish caller-owned unnamed ciphertext: %v", err)
	}

	unsafe := filepath.Join(directory, "unsafe")
	if err := os.Mkdir(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(unsafe, "source"), []byte("snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenTrustedSource(filepath.Join(unsafe, "source")); err == nil {
		t.Fatal("group/world-writable caller-owned ancestor was accepted")
	}
}

func TestRootCallerRejectsForeignOwnedAncestor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership boundary requires root")
	}
	directory := trustedRootTemp(t)
	foreign := filepath.Join(directory, "foreign")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(foreign, "source")
	if err := os.WriteFile(source, []byte("snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(foreign, 1, -1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenTrustedSource(source); err == nil {
		t.Fatal("root caller accepted a foreign-owned ancestor")
	}
}

func TestQuiescedSourceTrustsDeclaredAncestorOwnerOnly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership boundary requires root")
	}
	directory := trustedRootTemp(t)
	serviceOwned := filepath.Join(directory, "service-state")
	if err := os.Mkdir(serviceOwned, 0o750); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(serviceOwned, "state.json")
	if err := os.WriteFile(source, []byte("snapshot"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(source, 1, -1); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(serviceOwned, 1, -1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenTrustedSource(source); err == nil {
		t.Fatal("strict open accepted a service-owned ancestor")
	}
	if _, _, err := OpenTrustedQuiescedSource(source, 2); err == nil {
		t.Fatal("quiesced open accepted an ancestor outside the declared owner")
	}
	file, state, err := OpenTrustedQuiescedSource(source, 1)
	if err != nil {
		t.Fatalf("quiesced open rejected the declared service-owned ancestor: %v", err)
	}
	defer file.Close()
	if err := RecheckSource(file, state); err != nil {
		t.Fatalf("quiesced source identity recheck failed: %v", err)
	}
}

func TestTrustedSourceIdentityAndConcurrentMutation(t *testing.T) {
	directory := trustedRootTemp(t)
	path := filepath.Join(directory, "source")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), int(MinChunkSize)+1), 0o640); err != nil {
		t.Fatal(err)
	}
	file, before, err := OpenTrustedSource(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("source lacks O_NONBLOCK: flags=%#x error=%v", flags, err)
	}
	metadata := before.Metadata("snapshot", "release", "key", 1, "/etc/pgw/source", MinChunkSize)
	var encrypted bytes.Buffer
	reader := &mutatingFileReader{file: file, path: path}
	if err := encryptWithRandom(&encrypted, reader, testKey(1), metadata, bytes.NewReader(bytes.Repeat([]byte{1}, SaltSize))); err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if err := RecheckSource(file, before); !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("RecheckSource() error = %v, want ErrSourceChanged", err)
	}
}

type mutatingFileReader struct {
	file    *os.File
	path    string
	mutated bool
}

func (reader *mutatingFileReader) Read(destination []byte) (int, error) {
	count, err := reader.file.Read(destination)
	if count > 0 && !reader.mutated {
		reader.mutated = true
		writer, openErr := os.OpenFile(reader.path, os.O_WRONLY, 0)
		if openErr != nil {
			return count, openErr
		}
		_, writeErr := writer.WriteAt([]byte{'z'}, 0)
		syncErr := writer.Sync()
		closeErr := writer.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return count, errors.Join(writeErr, syncErr, closeErr)
		}
	}
	return count, err
}

func TestTrustedSourceRejectsUnsafeAncestorAndSymlink(t *testing.T) {
	directory := trustedRootTemp(t)
	unsafe := filepath.Join(directory, "unsafe")
	if err := os.Mkdir(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(unsafe, "source")
	if err := os.WriteFile(source, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenTrustedSource(source); err == nil {
		t.Fatal("group/world-writable ancestor was accepted")
	}
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenTrustedSource(link); err == nil {
		t.Fatal("source symlink was accepted")
	}
	fifo := filepath.Join(directory, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenTrustedSource(fifo); err == nil {
		t.Fatal("FIFO source was accepted")
	}
}

func TestCiphertextStageAtomicNoReplaceAndCleanup(t *testing.T) {
	directory := trustedRootTemp(t)
	destination := filepath.Join(directory, "object.pgw")
	publisher, err := CreateCiphertextPublisher(destination)
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("ciphertext O_TMPFILE created a name: entries=%v error=%v", entries, err)
	}
	if _, err := publisher.File().Write([]byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil || string(contents) != "ciphertext" {
		t.Fatalf("published contents=%q error=%v", contents, err)
	}
	retry, err := CreateCiphertextPublisher(destination)
	if err == nil {
		_ = retry.Abort()
		t.Fatal("ciphertext publisher accepted existing destination")
	}
	raceDestination := filepath.Join(directory, "raced-object.pgw")
	retry, err = CreateCiphertextPublisher(raceDestination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retry.File().Write([]byte("replacement")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(raceDestination, []byte("racer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := retry.Publish(); err == nil {
		t.Fatal("ciphertext publisher replaced raced destination")
	}
	if err := retry.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationFaultOutcomeClassification(t *testing.T) {
	tests := []struct {
		name       string
		inject     func(*CiphertextPublisher)
		want       CommitOutcome
		wantLinked bool
	}{
		{"link", func(publisher *CiphertextPublisher) {
			publisher.ops.link = func(int, string, int, string, int) error { return unix.EIO }
		}, OutcomeCommitIndeterminate, false},
		{"parent-fsync", func(publisher *CiphertextPublisher) {
			publisher.ops.directorySync = func(int) error { return unix.EIO }
		}, OutcomeDurabilityIndeterminate, true},
		{"file-close", func(publisher *CiphertextPublisher) {
			publisher.ops.fileClose = func(file *os.File) error { return errors.Join(file.Close(), unix.EIO) }
		}, OutcomeDurableAckFailure, true},
		{"directory-close", func(publisher *CiphertextPublisher) {
			publisher.ops.directoryClose = func(fd int) error { return errors.Join(unix.Close(fd), unix.EIO) }
		}, OutcomeDurableAckFailure, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := trustedRootTemp(t)
			destination := filepath.Join(directory, "object")
			publisher, err := CreateCiphertextPublisher(destination)
			if err != nil {
				t.Skipf("O_TMPFILE unavailable: %v", err)
			}
			if _, err := publisher.File().Write([]byte("ciphertext")); err != nil {
				t.Fatal(err)
			}
			test.inject(publisher)
			receipt, err := publisher.Publish()
			if err == nil {
				t.Fatal("injected publication fault succeeded")
			}
			outcome, classifiedReceipt := ClassifyPublicationError(err)
			if outcome != test.want {
				t.Fatalf("outcome=%s want=%s error=%v", outcome, test.want, err)
			}
			if test.wantLinked && (receipt.Inode == 0 || classifiedReceipt.Inode != receipt.Inode) {
				t.Fatalf("linked failure omitted receipt: returned=%+v classified=%+v", receipt, classifiedReceipt)
			}
			if _, statErr := os.Stat(destination); (statErr == nil) != test.wantLinked {
				t.Fatalf("linked=%v stat error=%v", test.wantLinked, statErr)
			}
			if abortErr := publisher.Abort(); abortErr != nil && !publisher.closed {
				t.Fatalf("abort error=%v", abortErr)
			}
		})
	}
}

func TestPublicationFileFsyncFailureIsPreCommit(t *testing.T) {
	directory := trustedRootTemp(t)
	destination := filepath.Join(directory, "object")
	publisher, err := CreateCiphertextPublisher(destination)
	if err != nil {
		t.Skipf("O_TMPFILE unavailable: %v", err)
	}
	publisher.ops.fileSync = func(*os.File) error { return unix.EIO }
	if _, err := publisher.Publish(); err == nil {
		t.Fatal("injected file fsync fault succeeded")
	} else if outcome, _ := ClassifyPublicationError(err); outcome != OutcomePreCommit {
		t.Fatalf("outcome=%s error=%v", outcome, err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("precommit failure created destination: %v", err)
	}
	if err := publisher.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestReconciliationDurabilityFaultOutcomes(t *testing.T) {
	tests := []struct {
		name   string
		inject func(*ReconciliationHandle)
	}{
		{"file-fsync", func(handle *ReconciliationHandle) {
			handle.ops.fileSync = func(*os.File) error { return unix.EIO }
		}},
		{"parent-fsync", func(handle *ReconciliationHandle) {
			handle.ops.directorySync = func(int) error { return unix.EIO }
		}},
		{"final-stat", func(handle *ReconciliationHandle) {
			handle.ops.statAt = func(int, string, *unix.Stat_t, int) error { return unix.EIO }
		}},
		{"final-identity", func(handle *ReconciliationHandle) {
			realStatAt := handle.ops.statAt
			handle.ops.statAt = func(directory int, base string, stat *unix.Stat_t, flags int) error {
				if err := realStatAt(directory, base, stat, flags); err != nil {
					return err
				}
				stat.Ino++
				return nil
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := trustedRootTemp(t)
			destination := filepath.Join(directory, "published")
			if err := os.WriteFile(destination, []byte("authenticated"), 0o600); err != nil {
				t.Fatal(err)
			}
			handle, err := OpenPublishedForReconciliation(destination)
			if err != nil {
				t.Fatal(err)
			}
			test.inject(handle)
			receipt, err := handle.ConfirmDurable(nil, nil)
			if err == nil {
				t.Fatal("injected reconciliation durability fault succeeded")
			}
			outcome, classified := ClassifyPublicationError(err)
			if outcome != OutcomeDurabilityIndeterminate {
				t.Fatalf("outcome=%s want=%s error=%v", outcome, OutcomeDurabilityIndeterminate, err)
			}
			if code := ExitCodeForOutcome(outcome); code != ExitDurabilityIndeterminate {
				t.Fatalf("durability outcome exit=%d want=%d", code, ExitDurabilityIndeterminate)
			}
			if !receipt.Known || !classified.Known || classified.Inode != receipt.Inode {
				t.Fatalf("durability failure omitted canonical receipt: returned=%+v classified=%+v", receipt, classified)
			}
			if abortErr := handle.Abort(); abortErr != nil {
				t.Fatal(abortErr)
			}
		})
	}
}

func TestReconciliationRejectsRacedFinalName(t *testing.T) {
	directory := trustedRootTemp(t)
	destination := filepath.Join(directory, "published")
	displaced := filepath.Join(directory, "displaced")
	if err := os.WriteFile(destination, []byte("authenticated"), 0o600); err != nil {
		t.Fatal(err)
	}
	handle, err := OpenPublishedForReconciliation(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(destination, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	receipt, err := handle.ConfirmDurable(nil, nil)
	if err == nil {
		t.Fatal("raced final name was accepted")
	}
	outcome, classified := ClassifyPublicationError(err)
	if outcome != OutcomeDurabilityIndeterminate || !receipt.Known || classified.Inode != receipt.Inode {
		t.Fatalf("race outcome=%s receipt=%+v classified=%+v error=%v", outcome, receipt, classified, err)
	}
	if abortErr := handle.Abort(); abortErr != nil {
		t.Fatal(abortErr)
	}
}

func TestUnnamedPlaintextAbortAndPublish(t *testing.T) {
	directory := trustedRootTemp(t)
	destination := filepath.Join(directory, "published")
	publisher, err := CreatePlaintextPublisher(destination)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
			t.Skipf("filesystem does not support O_TMPFILE: %v", err)
		}
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("O_TMPFILE created a name: entries=%v error=%v", entries, err)
	}
	if _, err := publisher.File().Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Abort(); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("abort left plaintext residue: entries=%v error=%v", entries, err)
	}

	publisher, err = CreatePlaintextPublisher(destination)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.File().Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(0, 0, 0o640, uint64(len("secret"))); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil || string(contents) != "secret" {
		t.Fatalf("published plaintext=%q error=%v", contents, err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("published mode=%v", info.Mode())
	}
	if _, err := CreatePlaintextPublisher(destination); err == nil {
		t.Fatal("existing plaintext destination was accepted")
	}
}

func TestUnnamedPlaintextPartialWriteFailsBeforePublish(t *testing.T) {
	directory := trustedRootTemp(t)
	destination := filepath.Join(directory, "published")
	publisher, err := CreatePlaintextPublisher(destination)
	if err != nil {
		t.Skipf("O_TMPFILE unavailable: %v", err)
	}
	if _, err := publisher.File().Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(0, 0, 0o600, 99); err == nil {
		t.Fatal("partial plaintext was published")
	}
	if err := publisher.Abort(); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("partial write left plaintext name: entries=%v error=%v", entries, err)
	}
}

func TestAuthenticationFailureLeavesNoPlaintextName(t *testing.T) {
	directory := trustedRootTemp(t)
	destination := filepath.Join(directory, "published")
	metadata := testMetadata(32, MinChunkSize)
	ciphertext := encryptFixture(t, deterministicBytes(32), metadata, bytes.Repeat([]byte{1}, SaltSize))
	publisher, err := CreatePlaintextPublisher(destination)
	if err != nil {
		t.Skipf("O_TMPFILE unavailable: %v", err)
	}
	if _, err := Decrypt(publisher.File(), bytes.NewReader(ciphertext), testKey(2)); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Decrypt error = %v", err)
	}
	if err := publisher.Abort(); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("authentication failure left plaintext name: entries=%v error=%v", entries, err)
	}
}

func TestExpectedMetadataMismatchLeavesNoPlaintextName(t *testing.T) {
	directory := trustedRootTemp(t)
	destination := filepath.Join(directory, "published")
	metadata := testMetadata(32, MinChunkSize)
	ciphertext := encryptFixture(t, deterministicBytes(32), metadata, bytes.Repeat([]byte{1}, SaltSize))
	publisher, err := CreatePlaintextPublisher(destination)
	if err != nil {
		t.Skipf("O_TMPFILE unavailable: %v", err)
	}
	actual, err := Decrypt(publisher.File(), bytes.NewReader(ciphertext), testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	expected := actual
	expected.SourceInode++
	if err := MatchExpected(actual, expected); err == nil {
		t.Fatal("mismatched expected metadata was accepted")
	}
	if err := publisher.Abort(); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("metadata mismatch left plaintext name: entries=%v error=%v", entries, err)
	}
}

func TestPlaintextSIGKILLLeavesNoNamedResidue(t *testing.T) {
	if os.Getenv("PGW_OTMPFILE_SIGKILL_CHILD") == "1" {
		destination := os.Getenv("PGW_OTMPFILE_DESTINATION")
		publisher, err := CreatePlaintextPublisher(destination)
		if err != nil {
			fmt.Fprintf(os.Stdout, "ERROR:%v\n", err)
			os.Exit(2)
		}
		if _, err := io.WriteString(publisher.File(), "secret plaintext"); err != nil {
			os.Exit(3)
		}
		fmt.Fprintln(os.Stdout, "READY")
		_ = os.Stdout.Sync()
		for {
			time.Sleep(time.Hour)
		}
	}
	directory := trustedRootTemp(t)
	destination := filepath.Join(directory, "published")
	command := exec.Command(os.Args[0], "-test.run=^TestPlaintextSIGKILLLeavesNoNamedResidue$")
	command.Env = append(os.Environ(), "PGW_OTMPFILE_SIGKILL_CHILD=1", "PGW_OTMPFILE_DESTINATION="+destination)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("child did not become ready: %v", scanner.Err())
	}
	if line := scanner.Text(); line != "READY" {
		_ = command.Wait()
		t.Skipf("O_TMPFILE unavailable in child: %s", line)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("SIGKILL left plaintext name: entries=%v error=%v", entries, err)
	}
}

func TestO_TMPFILEUnavailableFailsClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required")
	}
	if _, err := CreatePlaintextPublisher("/proc/pgw-snapshotcrypto-must-not-exist"); err == nil {
		t.Fatal("unsupported O_TMPFILE publication unexpectedly succeeded")
	}
}
