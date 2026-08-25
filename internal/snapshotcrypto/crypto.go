package snapshotcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"

	"golang.org/x/crypto/hkdf"
)

// Key is an independently provisioned master key. It is never used directly
// with AES; every object gets a fresh HKDF-derived AES-256 key.
type Key [KeySize]byte

func NewKey(raw []byte) (Key, error) {
	var key Key
	if len(raw) != KeySize {
		return key, ErrInvalidKey
	}
	copy(key[:], raw)
	return key, nil
}

func (key *Key) Destroy() {
	if key == nil {
		return
	}
	wipe(key[:])
}

// Encrypt consumes exactly Metadata.PlaintextLength bytes. Production callers
// must obtain Metadata from the already-opened source descriptor and recheck
// that descriptor after Encrypt returns.
func Encrypt(destination io.Writer, source io.Reader, master *Key, metadata Metadata) error {
	return encryptWithRandom(destination, source, master, metadata, rand.Reader)
}

func encryptWithRandom(destination io.Writer, source io.Reader, master *Key, metadata Metadata, random io.Reader) error {
	if master == nil {
		return ErrInvalidKey
	}
	if random == nil {
		return errors.New("snapshot salt source is unavailable")
	}
	var salt [SaltSize]byte
	if _, err := io.ReadFull(random, salt[:]); err != nil {
		return fmt.Errorf("generate snapshot salt: %w", err)
	}
	header, err := buildHeader(metadata, salt)
	if err != nil {
		return err
	}
	aead, destroy, err := newObjectAEAD(master, salt, header)
	if err != nil {
		return err
	}
	defer destroy()
	if err := writeAll(destination, header); err != nil {
		return fmt.Errorf("write snapshot header: %w", err)
	}
	count, err := chunkCount(metadata.PlaintextLength, metadata.ChunkSize)
	if err != nil {
		return err
	}
	remaining := metadata.PlaintextLength
	plaintext := make([]byte, metadata.ChunkSize)
	defer wipe(plaintext)
	for counter := uint64(0); counter < count; counter++ {
		plainLength := uint64(metadata.ChunkSize)
		if remaining < plainLength {
			plainLength = remaining
		}
		chunk := plaintext[:int(plainLength)]
		if _, err := io.ReadFull(source, chunk); err != nil {
			return fmt.Errorf("snapshot plaintext truncated: %w", err)
		}
		final := counter+1 == count
		nonce := makeNonce(counter)
		aad := makeAAD(header, counter, final)
		ciphertext := aead.Seal(nil, nonce[:], chunk, aad)
		record := makeRecordHeader(counter, final, uint32(len(ciphertext)))
		if err := writeAll(destination, record[:]); err != nil {
			wipe(ciphertext)
			return fmt.Errorf("write snapshot record header: %w", err)
		}
		if err := writeAll(destination, ciphertext); err != nil {
			wipe(ciphertext)
			return fmt.Errorf("write snapshot ciphertext: %w", err)
		}
		wipe(ciphertext)
		wipe(chunk)
		remaining -= plainLength
	}
	return requireEOF(source, "snapshot plaintext grew while encrypting")
}

// Verify authenticates the complete stream without retaining or emitting
// plaintext. Metadata is returned only after authenticated EOF.
func Verify(source io.Reader, master *Key) (Metadata, error) {
	return consume(source, io.Discard, master)
}

// Decrypt writes authenticated chunks to destination. The Linux CLI only uses
// this with an unnamed O_TMPFILE and publishes it after complete verification
// and an exact expected-metadata comparison.
func Decrypt(destination io.Writer, source io.Reader, master *Key) (Metadata, error) {
	return consume(source, destination, master)
}

func consume(source io.Reader, destination io.Writer, master *Key) (Metadata, error) {
	if master == nil {
		return Metadata{}, ErrInvalidKey
	}
	header, err := readHeader(source)
	if err != nil {
		return Metadata{}, err
	}
	aead, destroy, err := newObjectAEAD(master, header.salt, header.encoded)
	if err != nil {
		return Metadata{}, err
	}
	defer destroy()
	count, err := chunkCount(header.metadata.PlaintextLength, header.metadata.ChunkSize)
	if err != nil {
		return Metadata{}, err
	}
	remaining := header.metadata.PlaintextLength
	for counter := uint64(0); counter < count; counter++ {
		plainLength := uint64(header.metadata.ChunkSize)
		if remaining < plainLength {
			plainLength = remaining
		}
		var record [RecordHeaderSize]byte
		if _, err := io.ReadFull(source, record[:]); err != nil {
			return Metadata{}, fmt.Errorf("%w: truncated record header", ErrInvalidFormat)
		}
		final := counter+1 == count
		recordCounter, recordFinal, ciphertextLength := parseRecordHeader(record)
		if recordCounter != counter {
			return Metadata{}, fmt.Errorf("%w: reused or nonmonotonic chunk counter", ErrInvalidFormat)
		}
		expectedFinal := byte(0)
		if final {
			expectedFinal = 1
		}
		if recordFinal != expectedFinal {
			return Metadata{}, fmt.Errorf("%w: invalid final marker", ErrInvalidFormat)
		}
		expectedCiphertextLength := uint32(plainLength) + uint32(aead.Overhead())
		if ciphertextLength != expectedCiphertextLength || ciphertextLength > MaxChunkSize+GCMTagSize {
			return Metadata{}, fmt.Errorf("%w: invalid ciphertext chunk size", ErrInvalidFormat)
		}
		ciphertext := make([]byte, ciphertextLength)
		if _, err := io.ReadFull(source, ciphertext); err != nil {
			wipe(ciphertext)
			return Metadata{}, fmt.Errorf("%w: truncated ciphertext", ErrInvalidFormat)
		}
		nonce := makeNonce(recordCounter)
		aad := makeAAD(header.encoded, recordCounter, final)
		plaintext, openErr := aead.Open(nil, nonce[:], ciphertext, aad)
		wipe(ciphertext)
		if openErr != nil {
			wipe(plaintext)
			return Metadata{}, ErrAuthentication
		}
		if len(plaintext) != int(plainLength) {
			wipe(plaintext)
			return Metadata{}, fmt.Errorf("%w: plaintext length mismatch", ErrInvalidFormat)
		}
		if err := writeAll(destination, plaintext); err != nil {
			wipe(plaintext)
			return Metadata{}, fmt.Errorf("write decrypted snapshot: %w", err)
		}
		wipe(plaintext)
		remaining -= plainLength
	}
	if err := requireEOF(source, "snapshot ciphertext has trailing bytes"); err != nil {
		return Metadata{}, err
	}
	return header.metadata, nil
}

func MatchExpected(actual Metadata, expected ExpectedMetadata) error {
	if actual != expected {
		return errors.New("authenticated snapshot metadata does not match expected manifest metadata")
	}
	return nil
}

func ValidateExpected(expected ExpectedMetadata) error {
	return validateMetadata(expected)
}

// ValidateMetadata enforces format and cryptographic-use budgets before a
// caller allocates an output publisher.
func ValidateMetadata(metadata Metadata) error {
	return validateMetadata(metadata)
}

func newObjectAEAD(master *Key, salt [SaltSize]byte, header []byte) (cipher.AEAD, func(), error) {
	derived, err := deriveObjectKey(master, salt, header)
	if err != nil {
		return nil, func() {}, err
	}
	block, err := aes.NewCipher(derived[:])
	if err != nil {
		derived.Destroy()
		return nil, func() {}, fmt.Errorf("initialize snapshot cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		derived.Destroy()
		return nil, func() {}, fmt.Errorf("initialize snapshot AEAD: %w", err)
	}
	if aead.NonceSize() != 12 || aead.Overhead() != GCMTagSize {
		derived.Destroy()
		return nil, func() {}, errors.New("unexpected AES-GCM parameters")
	}
	return aead, func() { derived.Destroy() }, nil
}

func deriveObjectKey(master *Key, salt [SaltSize]byte, header []byte) (Key, error) {
	var derived Key
	if master == nil {
		return derived, ErrInvalidKey
	}
	info := make([]byte, 0, len(kdfDomain)+len(header))
	info = append(info, kdfDomain...)
	info = append(info, header...)
	reader := hkdf.New(sha256.New, master[:], salt[:], info)
	if _, err := io.ReadFull(reader, derived[:]); err != nil {
		derived.Destroy()
		return Key{}, fmt.Errorf("derive snapshot object key: %w", err)
	}
	return derived, nil
}

func makeNonce(counter uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[0:4], []byte{'P', 'G', 'W', byte(FormatVersion)})
	binary.BigEndian.PutUint64(nonce[4:12], counter)
	return nonce
}

func makeRecordHeader(counter uint64, final bool, ciphertextLength uint32) [RecordHeaderSize]byte {
	var record [RecordHeaderSize]byte
	binary.BigEndian.PutUint64(record[0:8], counter)
	if final {
		record[8] = 1
	}
	binary.BigEndian.PutUint32(record[9:13], ciphertextLength)
	return record
}

func parseRecordHeader(record [RecordHeaderSize]byte) (uint64, byte, uint32) {
	return binary.BigEndian.Uint64(record[0:8]), record[8], binary.BigEndian.Uint32(record[9:13])
}

func makeAAD(header []byte, counter uint64, final bool) []byte {
	aad := make([]byte, 0, len(aadDomain)+len(header)+9)
	aad = append(aad, aadDomain...)
	aad = append(aad, header...)
	var encodedCounter [8]byte
	binary.BigEndian.PutUint64(encodedCounter[:], counter)
	aad = append(aad, encodedCounter[:]...)
	if final {
		aad = append(aad, 1)
	} else {
		aad = append(aad, 0)
	}
	return aad
}

func readHeader(source io.Reader) (decodedHeader, error) {
	fixed := make([]byte, 16)
	if _, err := io.ReadFull(source, fixed); err != nil {
		return decodedHeader{}, fmt.Errorf("%w: truncated header", ErrInvalidFormat)
	}
	if !bytes.Equal(fixed[:8], formatMagic[:]) {
		return decodedHeader{}, fmt.Errorf("%w: bad magic", ErrInvalidFormat)
	}
	if binary.BigEndian.Uint16(fixed[8:10]) != FormatVersion {
		return decodedHeader{}, fmt.Errorf("%w: unsupported version", ErrInvalidFormat)
	}
	if binary.BigEndian.Uint16(fixed[10:12]) != fieldCount {
		return decodedHeader{}, fmt.Errorf("%w: unknown or missing fields", ErrInvalidFormat)
	}
	payloadLength := binary.BigEndian.Uint32(fixed[12:16])
	if payloadLength > MaxHeaderSize-16 {
		return decodedHeader{}, fmt.Errorf("%w: header exceeds limit", ErrInvalidFormat)
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(source, payload); err != nil {
		return decodedHeader{}, fmt.Errorf("%w: truncated header payload", ErrInvalidFormat)
	}
	encoded := append(fixed, payload...)
	reader := bytes.NewReader(payload)
	values := make(map[uint16][]byte, fieldCount)
	for expected := uint16(1); expected <= fieldCount; expected++ {
		var identifier uint16
		var length uint32
		if err := binary.Read(reader, binary.BigEndian, &identifier); err != nil {
			return decodedHeader{}, fmt.Errorf("%w: malformed field", ErrInvalidFormat)
		}
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return decodedHeader{}, fmt.Errorf("%w: malformed field length", ErrInvalidFormat)
		}
		if identifier != expected {
			return decodedHeader{}, fmt.Errorf("%w: unknown, duplicate, or noncanonical field", ErrInvalidFormat)
		}
		if uint64(length) > uint64(reader.Len()) {
			return decodedHeader{}, fmt.Errorf("%w: truncated field", ErrInvalidFormat)
		}
		value := make([]byte, length)
		if _, err := io.ReadFull(reader, value); err != nil {
			return decodedHeader{}, fmt.Errorf("%w: truncated field", ErrInvalidFormat)
		}
		values[identifier] = value
	}
	if reader.Len() != 0 {
		return decodedHeader{}, fmt.Errorf("%w: unknown trailing fields", ErrInvalidFormat)
	}
	for _, field := range []uint16{fieldUID, fieldGID, fieldMode, fieldChunkSize} {
		if len(values[field]) != 4 {
			return decodedHeader{}, fmt.Errorf("%w: invalid 32-bit field", ErrInvalidFormat)
		}
	}
	for _, field := range []uint16{fieldKeyObjectSequence, fieldSourceDevice, fieldSourceInode, fieldPlaintextLength, fieldSourceMTimeNS, fieldSourceCTimeNS} {
		if len(values[field]) != 8 {
			return decodedHeader{}, fmt.Errorf("%w: invalid 64-bit field", ErrInvalidFormat)
		}
	}
	if len(values[fieldSalt]) != SaltSize {
		return decodedHeader{}, fmt.Errorf("%w: invalid salt", ErrInvalidFormat)
	}
	metadata := Metadata{
		FormatVersion:     FormatVersion,
		SnapshotID:        string(values[fieldSnapshotID]),
		ReleaseID:         string(values[fieldReleaseID]),
		KeyID:             string(values[fieldKeyID]),
		KeyObjectSequence: binary.BigEndian.Uint64(values[fieldKeyObjectSequence]),
		LogicalPath:       string(values[fieldLogicalPath]),
		UID:               binary.BigEndian.Uint32(values[fieldUID]),
		GID:               binary.BigEndian.Uint32(values[fieldGID]),
		Mode:              binary.BigEndian.Uint32(values[fieldMode]),
		SourceDevice:      binary.BigEndian.Uint64(values[fieldSourceDevice]),
		SourceInode:       binary.BigEndian.Uint64(values[fieldSourceInode]),
		PlaintextLength:   binary.BigEndian.Uint64(values[fieldPlaintextLength]),
		SourceMTimeNS:     int64(binary.BigEndian.Uint64(values[fieldSourceMTimeNS])),
		SourceCTimeNS:     int64(binary.BigEndian.Uint64(values[fieldSourceCTimeNS])),
		ChunkSize:         binary.BigEndian.Uint32(values[fieldChunkSize]),
	}
	var salt [SaltSize]byte
	copy(salt[:], values[fieldSalt])
	canonical, err := buildHeader(metadata, salt)
	if err != nil {
		return decodedHeader{}, err
	}
	if !bytes.Equal(encoded, canonical) {
		return decodedHeader{}, fmt.Errorf("%w: noncanonical header", ErrInvalidFormat)
	}
	return decodedHeader{metadata: metadata, salt: salt, encoded: encoded}, nil
}

func requireEOF(source io.Reader, message string) error {
	var extra [1]byte
	n, err := io.ReadFull(source, extra[:])
	if n != 0 || err == nil {
		return fmt.Errorf("%w: %s", ErrInvalidFormat, message)
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return fmt.Errorf("read snapshot stream: %w", err)
}

func writeAll(destination io.Writer, contents []byte) error {
	for len(contents) > 0 {
		written, err := destination.Write(contents)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(contents) {
			return io.ErrShortWrite
		}
		contents = contents[written:]
	}
	return nil
}

func wipe(contents []byte) {
	for index := range contents {
		contents[index] = 0
	}
	runtime.KeepAlive(contents)
}
