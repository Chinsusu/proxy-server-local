//go:build linux

package snapshotcrypto

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maxFilesystemPath = 4096

func HardenProcess() error {
	unix.Umask(0o077)
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("disable process dumpability: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no-new-privileges: %w", err)
	}
	return nil
}

type SourceState struct {
	device  uint64
	inode   uint64
	size    int64
	mtimeNS int64
	ctimeNS int64
	uid     uint32
	gid     uint32
	mode    uint32
}

func sourceStateFromStat(stat unix.Stat_t) (SourceState, error) {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 {
		return SourceState{}, errors.New("snapshot source is not a regular file")
	}
	return SourceState{
		device: uint64(stat.Dev), inode: stat.Ino, size: stat.Size,
		mtimeNS: timespecNS(stat.Mtim), ctimeNS: timespecNS(stat.Ctim),
		uid: stat.Uid, gid: stat.Gid, mode: uint32(stat.Mode) & 0o7777,
	}, nil
}

func (state SourceState) Metadata(snapshotID, releaseID, keyID string, keyObjectSequence uint64, logicalPath string, chunkSize uint32) Metadata {
	return Metadata{
		FormatVersion:     FormatVersion,
		SnapshotID:        snapshotID,
		ReleaseID:         releaseID,
		KeyID:             keyID,
		KeyObjectSequence: keyObjectSequence,
		LogicalPath:       logicalPath,
		UID:               state.uid,
		GID:               state.gid,
		Mode:              state.mode,
		SourceDevice:      state.device,
		SourceInode:       state.inode,
		PlaintextLength:   uint64(state.size),
		SourceMTimeNS:     state.mtimeNS,
		SourceCTimeNS:     state.ctimeNS,
		ChunkSize:         chunkSize,
	}
}

// OpenTrustedSource opens a regular source with O_NONBLOCK and rejects every
// symlink, non-root-owned ancestor, and group/world-writable ancestor.
func OpenTrustedSource(name string) (*os.File, SourceState, error) {
	var empty SourceState
	directory, base, err := openTrustedParentDirectory(name)
	if err != nil {
		return nil, empty, err
	}
	fd, err := unix.Openat(directory, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, empty, errors.Join(err, unix.Close(directory))
	}
	state, err := sourceState(fd)
	if err != nil {
		return nil, empty, errors.Join(err, unix.Close(fd), unix.Close(directory))
	}
	if err := unix.Close(directory); err != nil {
		return nil, empty, errors.Join(fmt.Errorf("close source parent: %w", err), unix.Close(fd))
	}
	return os.NewFile(uintptr(fd), name), state, nil
}

// OpenTrustedCiphertext is the same trust-boundary open used by verify and
// decrypt-publish. Ciphertext is not allowed through attacker-writable paths.
func OpenTrustedCiphertext(name string) (*os.File, error) {
	file, _, err := OpenTrustedSource(name)
	return file, err
}

func RecheckSource(file *os.File, before SourceState) error {
	after, err := sourceState(int(file.Fd()))
	if err != nil {
		return fmt.Errorf("%w: fstat after read: %v", ErrSourceChanged, err)
	}
	if before != after {
		return fmt.Errorf("%w: inode/size/mtime/ctime/ownership/mode mismatch", ErrSourceChanged)
	}
	return nil
}

func ValidatePublishedFile(state SourceState, expected ExpectedMetadata, destination string) (PublicationReceipt, error) {
	if state.size < 0 || uint64(state.size) != expected.PlaintextLength || state.uid != expected.UID || state.gid != expected.GID || state.mode != expected.Mode {
		return PublicationReceipt{}, errors.New("published file metadata does not match authenticated snapshot metadata")
	}
	return PublicationReceipt{Destination: destination, Known: true, Device: state.device, Inode: state.inode, Size: uint64(state.size), UID: state.uid, GID: state.gid, Mode: state.mode}, nil
}

func ReceiptForOpenedFile(state SourceState, destination string) PublicationReceipt {
	return PublicationReceipt{Destination: destination, Known: true, Device: state.device, Inode: state.inode, Size: uint64(state.size), UID: state.uid, GID: state.gid, Mode: state.mode}
}

func sourceState(fd int) (SourceState, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return SourceState{}, err
	}
	return sourceStateFromStat(stat)
}

func timespecNS(value unix.Timespec) int64 {
	return value.Sec*1_000_000_000 + value.Nsec
}

type publicationOps struct {
	fileSync       func(*os.File) error
	link           func(int, string, int, string, int) error
	directorySync  func(int) error
	fileClose      func(*os.File) error
	directoryClose func(int) error
}

var realPublicationOps = publicationOps{
	fileSync:       func(file *os.File) error { return file.Sync() },
	link:           unix.Linkat,
	directorySync:  unix.Fsync,
	fileClose:      func(file *os.File) error { return file.Close() },
	directoryClose: unix.Close,
}

type reconciliationOps struct {
	fileSync       func(*os.File) error
	directorySync  func(int) error
	statAt         func(int, string, *unix.Stat_t, int) error
	fileClose      func(*os.File) error
	directoryClose func(int) error
}

var realReconciliationOps = reconciliationOps{
	fileSync:       func(file *os.File) error { return file.Sync() },
	directorySync:  unix.Fsync,
	statAt:         unix.Fstatat,
	fileClose:      func(file *os.File) error { return file.Close() },
	directoryClose: unix.Close,
}

// ReconciliationHandle pins both the existing final inode and its validated
// parent directory until authentication, durability, and final-name identity
// validation have all completed.
type ReconciliationHandle struct {
	file        *os.File
	directory   int
	base        string
	destination string
	before      SourceState
	closed      bool
	ops         reconciliationOps
}

func OpenPublishedForReconciliation(name string) (*ReconciliationHandle, error) {
	directory, base, err := openTrustedParentDirectory(name)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(directory, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.Join(err, unix.Close(directory))
	}
	state, err := sourceState(fd)
	if err != nil {
		return nil, errors.Join(err, unix.Close(fd), unix.Close(directory))
	}
	return &ReconciliationHandle{
		file: os.NewFile(uintptr(fd), name), directory: directory, base: base,
		destination: name, before: state, ops: realReconciliationOps,
	}, nil
}

func (handle *ReconciliationHandle) File() *os.File {
	if handle == nil {
		return nil
	}
	return handle.file
}

func (handle *ReconciliationHandle) Receipt() PublicationReceipt {
	if handle == nil {
		return PublicationReceipt{}
	}
	return ReceiptForOpenedFile(handle.before, handle.destination)
}

// ConfirmDurable must be called only after the caller has authenticated and
// completely consumed File. expectedMetadata is supplied for plaintext
// publication; expectedIdentity pins a prior receipt when one is available.
func (handle *ReconciliationHandle) ConfirmDurable(expectedMetadata *ExpectedMetadata, expectedIdentity *PublicationReceipt) (PublicationReceipt, error) {
	if handle == nil || handle.closed || handle.file == nil || handle.directory < 0 {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, errors.New("invalid reconciliation handle lifecycle"))
	}
	receipt := handle.Receipt()
	if expectedIdentity != nil && expectedIdentity.Known && (receipt.Device != expectedIdentity.Device || receipt.Inode != expectedIdentity.Inode) {
		return receipt, publicationFailure(OutcomePreCommit, receipt, errors.New("existing final inode does not match reconciliation receipt"))
	}
	if expectedMetadata != nil {
		if _, err := ValidatePublishedFile(handle.before, *expectedMetadata, handle.destination); err != nil {
			return receipt, publicationFailure(OutcomePreCommit, receipt, err)
		}
	}
	if err := RecheckSource(handle.file, handle.before); err != nil {
		return receipt, publicationFailure(OutcomeDurabilityIndeterminate, receipt, fmt.Errorf("recheck opened final before durability sync: %w", err))
	}
	if err := handle.ops.fileSync(handle.file); err != nil {
		return receipt, publicationFailure(OutcomeDurabilityIndeterminate, receipt, fmt.Errorf("fsync reconciled final: %w", err))
	}
	if err := handle.ops.directorySync(handle.directory); err != nil {
		return receipt, publicationFailure(OutcomeDurabilityIndeterminate, receipt, fmt.Errorf("fsync reconciled parent: %w", err))
	}
	var pathStat unix.Stat_t
	if err := handle.ops.statAt(handle.directory, handle.base, &pathStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return receipt, publicationFailure(OutcomeDurabilityIndeterminate, receipt, fmt.Errorf("revalidate reconciled final name: %w", err))
	}
	pathState, err := sourceStateFromStat(pathStat)
	if err != nil || pathState != handle.before {
		return receipt, publicationFailure(OutcomeDurabilityIndeterminate, receipt, errors.New("reconciled final name no longer refers to the authenticated inode and metadata"))
	}
	if expectedMetadata != nil {
		if _, err := ValidatePublishedFile(pathState, *expectedMetadata, handle.destination); err != nil {
			return receipt, publicationFailure(OutcomeDurabilityIndeterminate, receipt, err)
		}
	}
	if err := handle.close(); err != nil {
		return receipt, publicationFailure(OutcomeDurableAckFailure, receipt, err)
	}
	return receipt, nil
}

func (handle *ReconciliationHandle) close() error {
	var result error
	if handle.file != nil {
		result = errors.Join(result, handle.ops.fileClose(handle.file))
		handle.file = nil
	}
	if handle.directory >= 0 {
		result = errors.Join(result, handle.ops.directoryClose(handle.directory))
		handle.directory = -1
	}
	handle.closed = true
	return result
}

func (handle *ReconciliationHandle) Abort() error {
	if handle == nil || handle.closed {
		return nil
	}
	return handle.close()
}

type CiphertextPublisher struct {
	file        *os.File
	directory   int
	final       string
	destination string
	published   bool
	closed      bool
	ops         publicationOps
}

func CreateCiphertextPublisher(destination string) (*CiphertextPublisher, error) {
	directory, base, err := openTrustedParentDirectory(destination)
	if err != nil {
		return nil, err
	}
	if err := requireAbsentAt(directory, base); err != nil {
		return nil, errors.Join(err, unix.Close(directory))
	}
	fd, err := unix.Openat(directory, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create unnamed ciphertext inode: %w", err), unix.Close(directory))
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 0 || uint32(stat.Mode)&0o7777 != 0o600 {
		return nil, errors.Join(errors.New("O_TMPFILE did not create an unnamed mode-0600 ciphertext inode"), unix.Close(fd), unix.Close(directory))
	}
	return &CiphertextPublisher{file: os.NewFile(uintptr(fd), "unnamed-snapshot-ciphertext"), directory: directory, final: base, destination: destination, ops: realPublicationOps}, nil
}

func (publisher *CiphertextPublisher) File() *os.File { return publisher.file }

func (publisher *CiphertextPublisher) Publish() (PublicationReceipt, error) {
	if publisher == nil || publisher.closed || publisher.published {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, errors.New("invalid ciphertext publisher lifecycle"))
	}
	if err := publisher.ops.fileSync(publisher.file); err != nil {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, fmt.Errorf("fsync unnamed ciphertext: %w", err))
	}
	fd := int(publisher.file.Fd())
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 0 || uint32(stat.Mode)&0o7777 != 0o600 {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, errors.New("unnamed ciphertext identity or mode changed"))
	}
	if err := requireAbsentAt(publisher.directory, publisher.final); err != nil {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, err)
	}
	if err := publisher.ops.link(fd, "", publisher.directory, publisher.final, unix.AT_EMPTY_PATH); err != nil {
		outcome := OutcomeCommitIndeterminate
		if errors.Is(err, unix.EEXIST) {
			outcome = OutcomePreCommit
		}
		return PublicationReceipt{}, publicationFailure(outcome, PublicationReceipt{Destination: publisher.destination}, fmt.Errorf("atomically publish ciphertext: %w", err))
	}
	publisher.published = true
	receipt := receiptFromStat(publisher.destination, stat)
	if err := publisher.ops.directorySync(publisher.directory); err != nil {
		closeErr := publisher.closePublished("ciphertext")
		return receipt, publicationFailure(OutcomeDurabilityIndeterminate, receipt, errors.Join(fmt.Errorf("fsync ciphertext parent: %w", err), closeErr))
	}
	if err := publisher.closePublished("ciphertext"); err != nil {
		return receipt, publicationFailure(OutcomeDurableAckFailure, receipt, err)
	}
	return receipt, nil
}

func (publisher *CiphertextPublisher) closePublished(label string) error {
	var result error
	if publisher.file != nil {
		if err := publisher.ops.fileClose(publisher.file); err != nil {
			result = errors.Join(result, fmt.Errorf("close %s file: %w", label, err))
		}
		publisher.file = nil
	}
	if publisher.directory >= 0 {
		if err := publisher.ops.directoryClose(publisher.directory); err != nil {
			result = errors.Join(result, fmt.Errorf("close %s parent: %w", label, err))
		}
		publisher.directory = -1
	}
	publisher.closed = true
	return result
}

func (publisher *CiphertextPublisher) Abort() error {
	if publisher == nil || publisher.closed {
		return nil
	}
	var result error
	if publisher.file != nil {
		if err := publisher.ops.fileClose(publisher.file); err != nil {
			result = errors.Join(result, fmt.Errorf("close unnamed ciphertext: %w", err))
		}
		publisher.file = nil
	}
	if err := publisher.ops.directoryClose(publisher.directory); err != nil {
		result = errors.Join(result, fmt.Errorf("close ciphertext parent: %w", err))
	}
	publisher.directory = -1
	publisher.closed = true
	return result
}

type PlaintextPublisher struct {
	file        *os.File
	directory   int
	final       string
	destination string
	published   bool
	closed      bool
	ops         publicationOps
}

func CreatePlaintextPublisher(destination string) (*PlaintextPublisher, error) {
	directory, base, err := openTrustedParentDirectory(destination)
	if err != nil {
		return nil, err
	}
	if err := requireAbsentAt(directory, base); err != nil {
		return nil, errors.Join(err, unix.Close(directory))
	}
	fd, err := unix.Openat(directory, ".", unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create unnamed plaintext inode: %w", err), unix.Close(directory))
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 0 {
		return nil, errors.Join(errors.New("O_TMPFILE did not create an unnamed regular inode"), unix.Close(fd), unix.Close(directory))
	}
	return &PlaintextPublisher{file: os.NewFile(uintptr(fd), "unnamed-snapshot-plaintext"), directory: directory, final: base, destination: destination, ops: realPublicationOps}, nil
}

func (publisher *PlaintextPublisher) File() *os.File { return publisher.file }

func (publisher *PlaintextPublisher) Publish(uid, gid, mode uint32, plaintextLength uint64) (PublicationReceipt, error) {
	if publisher == nil || publisher.closed || publisher.published || mode > 0o7777 {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, errors.New("invalid plaintext publisher lifecycle or metadata"))
	}
	fd := int(publisher.file.Fd())
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, fmt.Errorf("apply published ownership: %w", err))
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, fmt.Errorf("apply published mode: %w", err))
	}
	if err := publisher.ops.fileSync(publisher.file); err != nil {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, fmt.Errorf("fsync unnamed plaintext: %w", err))
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, fmt.Errorf("inspect unnamed plaintext: %w", err))
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 0 || stat.Uid != uid || stat.Gid != gid || uint32(stat.Mode)&0o7777 != mode || stat.Size < 0 || uint64(stat.Size) != plaintextLength {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, errors.New("unnamed plaintext metadata did not persist"))
	}
	if err := requireAbsentAt(publisher.directory, publisher.final); err != nil {
		return PublicationReceipt{}, publicationFailure(OutcomePreCommit, PublicationReceipt{}, err)
	}
	if err := publisher.ops.link(fd, "", publisher.directory, publisher.final, unix.AT_EMPTY_PATH); err != nil {
		outcome := OutcomeCommitIndeterminate
		if errors.Is(err, unix.EEXIST) {
			outcome = OutcomePreCommit
		}
		return PublicationReceipt{}, publicationFailure(outcome, PublicationReceipt{Destination: publisher.destination}, fmt.Errorf("atomically publish unnamed plaintext: %w", err))
	}
	publisher.published = true
	receipt := receiptFromStat(publisher.destination, stat)
	if err := publisher.ops.directorySync(publisher.directory); err != nil {
		closeErr := publisher.closePublished("plaintext")
		return receipt, publicationFailure(OutcomeDurabilityIndeterminate, receipt, errors.Join(fmt.Errorf("fsync plaintext parent: %w", err), closeErr))
	}
	if err := publisher.closePublished("plaintext"); err != nil {
		return receipt, publicationFailure(OutcomeDurableAckFailure, receipt, err)
	}
	return receipt, nil
}

func (publisher *PlaintextPublisher) closePublished(label string) error {
	var result error
	if publisher.file != nil {
		if err := publisher.ops.fileClose(publisher.file); err != nil {
			result = errors.Join(result, fmt.Errorf("close %s file: %w", label, err))
		}
		publisher.file = nil
	}
	if publisher.directory >= 0 {
		if err := publisher.ops.directoryClose(publisher.directory); err != nil {
			result = errors.Join(result, fmt.Errorf("close %s parent: %w", label, err))
		}
		publisher.directory = -1
	}
	publisher.closed = true
	return result
}

func (publisher *PlaintextPublisher) Abort() error {
	if publisher == nil || publisher.closed {
		return nil
	}
	var result error
	if publisher.file != nil {
		if err := publisher.ops.fileClose(publisher.file); err != nil {
			result = errors.Join(result, fmt.Errorf("close unnamed plaintext: %w", err))
		}
		publisher.file = nil
	}
	if err := publisher.ops.directoryClose(publisher.directory); err != nil {
		result = errors.Join(result, fmt.Errorf("close plaintext parent: %w", err))
	}
	publisher.directory = -1
	publisher.closed = true
	return result
}

func receiptFromStat(destination string, stat unix.Stat_t) PublicationReceipt {
	return PublicationReceipt{Destination: destination, Known: true, Device: uint64(stat.Dev), Inode: stat.Ino, Size: uint64(stat.Size), UID: stat.Uid, GID: stat.Gid, Mode: uint32(stat.Mode) & 0o7777}
}

func requireAbsentAt(directory int, base string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(directory, base, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return errors.New("publication destination already exists")
	}
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect publication destination: %w", err)
	}
	return nil
}

func openTrustedParentDirectory(name string) (int, string, error) {
	if !cleanAbsolutePath(name) || len(name) > maxFilesystemPath {
		return -1, "", fmt.Errorf("%w: path must be clean and absolute", ErrUnsafePath)
	}
	parent, base := filepath.Split(name)
	parent = filepath.Clean(parent)
	if base == "" || base == "." || base == ".." || strings.ContainsRune(base, '/') {
		return -1, "", ErrUnsafePath
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return -1, "", err
	}
	if err := validateTrustedDirectory(fd); err != nil {
		return -1, "", errors.Join(err, unix.Close(fd))
	}
	for _, component := range strings.Split(strings.TrimPrefix(parent, "/"), "/") {
		if component == "" {
			continue
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if openErr != nil {
			return -1, "", errors.Join(openErr, unix.Close(fd))
		}
		if statErr := validateTrustedDirectory(next); statErr != nil {
			return -1, "", errors.Join(statErr, unix.Close(next), unix.Close(fd))
		}
		if closeErr := unix.Close(fd); closeErr != nil {
			return -1, "", errors.Join(fmt.Errorf("close traversed path ancestor: %w", closeErr), unix.Close(next))
		}
		fd = next
	}
	return fd, base, nil
}

func validateTrustedDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || uint32(stat.Mode)&0o022 != 0 {
		return errors.New("path ancestor must be a root-owned non-group/world-writable directory")
	}
	return nil
}

func cleanAbsolutePath(name string) bool {
	return filepath.IsAbs(name) && filepath.Clean(name) == name && !strings.ContainsRune(name, 0)
}
