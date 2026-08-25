package snapshotcrypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestRoundTripChunkBoundaries(t *testing.T) {
	t.Parallel()
	lengths := []int{
		0, 1, int(MinChunkSize) - 1, int(MinChunkSize), int(MinChunkSize) + 1,
		2*int(MinChunkSize) - 1, 2 * int(MinChunkSize), 2*int(MinChunkSize) + 1,
		int(DefaultChunkSize) - 1, int(DefaultChunkSize), int(DefaultChunkSize) + 1,
	}
	for _, length := range lengths {
		length := length
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			plaintext := deterministicBytes(length)
			chunkSize := MinChunkSize
			if length >= int(DefaultChunkSize)-1 {
				chunkSize = DefaultChunkSize
			}
			metadata := testMetadata(uint64(length), chunkSize)
			ciphertext := encryptFixture(t, plaintext, metadata, bytes.Repeat([]byte{byte(length + 1)}, SaltSize))
			verified, err := Verify(bytes.NewReader(ciphertext), testKey(1))
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if !reflect.DeepEqual(verified, metadata) {
				t.Fatalf("Verify() metadata = %#v, want %#v", verified, metadata)
			}
			var restored bytes.Buffer
			decrypted, err := Decrypt(&restored, bytes.NewReader(ciphertext), testKey(1))
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}
			if !reflect.DeepEqual(decrypted, metadata) || !bytes.Equal(restored.Bytes(), plaintext) {
				t.Fatal("round trip changed metadata or plaintext")
			}
		})
	}
}

func TestPropertyLikeRandomChunkBoundaries(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewSource(42))
	for trial := 0; trial < 64; trial++ {
		length := random.Intn(8*int(MinChunkSize) + 1)
		plaintext := deterministicBytes(length)
		metadata := testMetadata(uint64(length), MinChunkSize)
		ciphertext := encryptFixture(t, plaintext, metadata, bytes.Repeat([]byte{byte(trial + 1)}, SaltSize))
		var restored bytes.Buffer
		if _, err := Decrypt(&restored, bytes.NewReader(ciphertext), testKey(1)); err != nil {
			t.Fatalf("trial %d length %d: %v", trial, length, err)
		}
		if !bytes.Equal(restored.Bytes(), plaintext) {
			t.Fatalf("trial %d length %d: plaintext mismatch", trial, length)
		}
	}
}

func TestEncryptUsesFreshPerObjectSalt(t *testing.T) {
	t.Parallel()
	plaintext := deterministicBytes(100)
	metadata := testMetadata(uint64(len(plaintext)), MinChunkSize)
	var first, second bytes.Buffer
	if err := Encrypt(&first, bytes.NewReader(plaintext), testKey(1), metadata); err != nil {
		t.Fatal(err)
	}
	if err := Encrypt(&second, bytes.NewReader(plaintext), testKey(1), metadata); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("two encrypted files reused a nonce prefix")
	}
}

func TestHKDFSeparatesObjectContext(t *testing.T) {
	t.Parallel()
	plaintext := deterministicBytes(128)
	firstMetadata := testMetadata(uint64(len(plaintext)), MinChunkSize)
	secondMetadata := firstMetadata
	secondMetadata.KeyObjectSequence++
	salt := bytes.Repeat([]byte{9}, SaltSize)
	first := encryptFixture(t, plaintext, firstMetadata, salt)
	second := encryptFixture(t, plaintext, secondMetadata, salt)
	if bytes.Equal(first, second) {
		t.Fatal("different authenticated object context produced identical ciphertext")
	}
	if _, err := Verify(bytes.NewReader(second), testKey(1)); err != nil {
		t.Fatalf("context-separated ciphertext did not verify: %v", err)
	}
}

func TestHKDFSHA256KnownAnswerAndDomainSeparation(t *testing.T) {
	t.Parallel()
	var master Key
	for index := range master {
		master[index] = byte(index)
	}
	var salt [SaltSize]byte
	for index := range salt {
		salt[index] = byte(0xa0 + index)
	}
	derived, err := deriveObjectKey(&master, salt, []byte("canonical-header-test"))
	if err != nil {
		t.Fatal(err)
	}
	defer derived.Destroy()
	want, _ := hex.DecodeString("235ebb55de30f386efd62431e85a50681d400482ba81f8aeafbb5e0174e9b00e")
	if !bytes.Equal(derived[:], want) {
		t.Fatalf("HKDF output=%x want=%x", derived, want)
	}
	changedSalt := salt
	changedSalt[0] ^= 1
	withSalt, err := deriveObjectKey(&master, changedSalt, []byte("canonical-header-test"))
	if err != nil {
		t.Fatal(err)
	}
	defer withSalt.Destroy()
	withContext, err := deriveObjectKey(&master, salt, []byte("canonical-header-tesu"))
	if err != nil {
		t.Fatal(err)
	}
	defer withContext.Destroy()
	if bytes.Equal(derived[:], withSalt[:]) || bytes.Equal(derived[:], withContext[:]) {
		t.Fatal("salt or context change did not separate derived object key")
	}
}

func TestCiphertextDoesNotContainPlaintextPayload(t *testing.T) {
	t.Parallel()
	plaintext := bytes.Repeat([]byte("plaintext-must-not-survive-in-rollback-storage|"), 128)
	metadata := testMetadata(uint64(len(plaintext)), MinChunkSize)
	ciphertext := encryptFixture(t, plaintext, metadata, []byte("1234567890abcdef"))
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("plaintext payload appeared in ciphertext object")
	}
}

func TestCanonicalHeaderAndRecordEncoding(t *testing.T) {
	t.Parallel()
	metadata := testMetadata(0, MinChunkSize)
	ciphertext := encryptFixture(t, nil, metadata, []byte("1234567890abcdef"))
	if !bytes.Equal(ciphertext[:8], []byte{'P', 'G', 'W', 'S', 'N', 'A', 'P', 0}) {
		t.Fatalf("magic = %x", ciphertext[:8])
	}
	if version := binary.BigEndian.Uint16(ciphertext[8:10]); version != FormatVersion {
		t.Fatalf("version = %d", version)
	}
	if count := binary.BigEndian.Uint16(ciphertext[10:12]); count != fieldCount {
		t.Fatalf("field count = %d", count)
	}
	offset := 16
	for identifier := uint16(1); identifier <= fieldCount; identifier++ {
		if actual := binary.BigEndian.Uint16(ciphertext[offset : offset+2]); actual != identifier {
			t.Fatalf("field %d encoded as id %d", identifier, actual)
		}
		offset = nextFieldOffset(ciphertext, offset)
	}
	if offset != encodedHeaderLength(ciphertext) {
		t.Fatalf("TLVs end at %d, header ends at %d", offset, encodedHeaderLength(ciphertext))
	}
	record := ciphertext[offset : offset+RecordHeaderSize]
	if binary.BigEndian.Uint64(record[0:8]) != 0 || record[8] != 1 || binary.BigEndian.Uint32(record[9:13]) != GCMTagSize {
		t.Fatalf("empty-file record header = %x", record)
	}
}

func TestAADMetadataBinding(t *testing.T) {
	t.Parallel()
	plaintext := deterministicBytes(32)
	metadata := testMetadata(uint64(len(plaintext)), MinChunkSize)
	original := encryptFixture(t, plaintext, metadata, []byte("1234567890abcdef"))
	for _, field := range []uint16{
		fieldSnapshotID, fieldReleaseID, fieldKeyID, fieldKeyObjectSequence, fieldLogicalPath, fieldUID, fieldGID,
		fieldMode, fieldSourceDevice, fieldSourceInode, fieldPlaintextLength,
		fieldSourceMTimeNS, fieldSourceCTimeNS, fieldChunkSize, fieldSalt,
	} {
		field := field
		t.Run(strconv.Itoa(int(field)), func(t *testing.T) {
			mutated := append([]byte(nil), original...)
			start, length := fieldValueOffset(t, mutated, field)
			mutated[start+length-1] ^= 1
			if _, err := Verify(bytes.NewReader(mutated), testKey(1)); err == nil {
				t.Fatalf("field %d mutation was accepted", field)
			}
		})
	}
}

func TestRecordCounterFinalLengthAndReplayRejected(t *testing.T) {
	t.Parallel()
	metadata := testMetadata(uint64(2*MinChunkSize), MinChunkSize)
	original := encryptFixture(t, deterministicBytes(int(metadata.PlaintextLength)), metadata, []byte("1234567890abcdef"))
	headerLength := encodedHeaderLength(original)
	tests := map[string]func([]byte){
		"nonmonotonic first counter": func(value []byte) { binary.BigEndian.PutUint64(value[headerLength:headerLength+8], 1) },
		"early final":                func(value []byte) { value[headerLength+8] = 1 },
		"unknown final":              func(value []byte) { value[headerLength+8] = 2 },
		"oversize record": func(value []byte) {
			binary.BigEndian.PutUint32(value[headerLength+9:headerLength+13], MinChunkSize+GCMTagSize+1)
		},
		"replayed second counter": func(value []byte) {
			second := headerLength + RecordHeaderSize + int(MinChunkSize) + GCMTagSize
			binary.BigEndian.PutUint64(value[second:second+8], 0)
		},
		"swapped ciphertext chunks": func(value []byte) {
			first := headerLength + RecordHeaderSize
			second := first + int(MinChunkSize) + GCMTagSize + RecordHeaderSize
			left := append([]byte(nil), value[first:first+int(MinChunkSize)+GCMTagSize]...)
			copy(value[first:first+int(MinChunkSize)+GCMTagSize], value[second:second+int(MinChunkSize)+GCMTagSize])
			copy(value[second:second+int(MinChunkSize)+GCMTagSize], left)
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			mutated := append([]byte(nil), original...)
			mutate(mutated)
			if _, err := Verify(bytes.NewReader(mutated), testKey(1)); err == nil {
				t.Fatal("malformed or replayed record was accepted")
			}
		})
	}
}

func TestWrongKeyTamperTruncationAndTrailingBytesRejected(t *testing.T) {
	t.Parallel()
	metadata := testMetadata(0, MinChunkSize)
	ciphertext := encryptFixture(t, nil, metadata, []byte("1234567890abcdef"))
	if _, err := Verify(bytes.NewReader(ciphertext), testKey(2)); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key error = %v, want authentication failure", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0x80
	if _, err := Verify(bytes.NewReader(tampered), testKey(1)); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tag tamper error = %v, want authentication failure", err)
	}
	for cut := 0; cut < len(ciphertext); cut++ {
		if _, err := Verify(bytes.NewReader(ciphertext[:cut]), testKey(1)); err == nil {
			t.Fatalf("truncation at %d/%d was accepted", cut, len(ciphertext))
		}
	}
	withTrailing := append(append([]byte(nil), ciphertext...), 0)
	if _, err := Verify(bytes.NewReader(withTrailing), testKey(1)); err == nil {
		t.Fatal("trailing byte was accepted")
	}
}

func TestUnknownVersionFieldsAndNoncanonicalHeaderRejected(t *testing.T) {
	t.Parallel()
	ciphertext := encryptFixture(t, nil, testMetadata(0, MinChunkSize), []byte("1234567890abcdef"))
	tests := map[string]func([]byte){
		"version":     func(value []byte) { binary.BigEndian.PutUint16(value[8:10], FormatVersion+1) },
		"field count": func(value []byte) { binary.BigEndian.PutUint16(value[10:12], fieldCount+1) },
		"unknown id":  func(value []byte) { binary.BigEndian.PutUint16(value[16:18], 99) },
		"duplicate id": func(value []byte) {
			second := nextFieldOffset(value, 16)
			binary.BigEndian.PutUint16(value[second:second+2], fieldSnapshotID)
		},
		"oversize header": func(value []byte) { binary.BigEndian.PutUint32(value[12:16], MaxHeaderSize) },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			mutated := append([]byte(nil), ciphertext...)
			mutate(mutated)
			if _, err := Verify(bytes.NewReader(mutated), testKey(1)); err == nil {
				t.Fatal("invalid header was accepted")
			}
		})
	}
}

func TestMetadataBoundsAndTraversal(t *testing.T) {
	t.Parallel()
	valid := testMetadata(0, MinChunkSize)
	tests := []Metadata{
		func() Metadata { value := valid; value.FormatVersion++; return value }(),
		func() Metadata { value := valid; value.SnapshotID = ""; return value }(),
		func() Metadata { value := valid; value.SnapshotID = strings.Repeat("a", MaxSnapshotID+1); return value }(),
		func() Metadata { value := valid; value.ReleaseID = "bad/id"; return value }(),
		func() Metadata { value := valid; value.KeyID = "bad/id"; return value }(),
		func() Metadata { value := valid; value.KeyObjectSequence = MaxObjectsPerKeyID; return value }(),
		func() Metadata { value := valid; value.LogicalPath = "../etc/passwd"; return value }(),
		func() Metadata { value := valid; value.LogicalPath = "a/../b"; return value }(),
		func() Metadata { value := valid; value.LogicalPath = "a\\b"; return value }(),
		func() Metadata {
			value := valid
			value.LogicalPath = strings.Repeat("p", MaxLogicalPath+1)
			return value
		}(),
		func() Metadata { value := valid; value.Mode = 0o10000; return value }(),
		func() Metadata { value := valid; value.ChunkSize = MinChunkSize - 1; return value }(),
		func() Metadata { value := valid; value.ChunkSize = MaxChunkSize + 1; return value }(),
		func() Metadata {
			value := valid
			value.PlaintextLength = uint64(^uint32(0))*uint64(MinChunkSize) + 1
			return value
		}(),
	}
	for index, metadata := range tests {
		if err := Encrypt(io.Discard, bytes.NewReader(nil), testKey(1), metadata); err == nil {
			t.Fatalf("invalid metadata case %d was accepted", index)
		}
	}
	if _, err := buildHeader(valid, [SaltSize]byte{}); err != nil {
		t.Fatalf("valid metadata rejected: %v", err)
	}
}

func TestPerObjectBudgetsExactBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		length    uint64
		chunkSize uint32
		valid     bool
	}{
		{"empty-min-chunk", 0, MinChunkSize, true},
		{"one-gib-min-chunk", MaxPlaintextPerObject, MinChunkSize, true},
		{"one-gib-max-chunk", MaxPlaintextPerObject, MaxChunkSize, true},
		{"one-byte-over", MaxPlaintextPerObject + 1, MinChunkSize, false},
		{"min-chunk-under", 0, MinChunkSize - 1, false},
		{"max-chunk-over", 0, MaxChunkSize + 1, false},
	}
	for _, test := range tests {
		metadata := testMetadata(test.length, test.chunkSize)
		err := ValidateMetadata(metadata)
		if (err == nil) != test.valid {
			t.Fatalf("%s validation error=%v valid=%v", test.name, err, test.valid)
		}
	}
	count, err := chunkCount(MaxPlaintextPerObject, MinChunkSize)
	if err != nil || count != MaxChunksPerObject {
		t.Fatalf("minimum chunk boundary count=%d error=%v want=%d", count, err, MaxChunksPerObject)
	}
	if _, err := chunkCount(MaxPlaintextPerObject+1, MinChunkSize); err == nil {
		t.Fatal("chunk budget accepted one record over the limit")
	}
}

func TestParserEnforcesPerObjectBudget(t *testing.T) {
	t.Parallel()
	ciphertext := encryptFixture(t, nil, testMetadata(0, MinChunkSize), []byte("1234567890abcdef"))
	offset, length := fieldValueOffset(t, ciphertext, fieldPlaintextLength)
	if length != 8 {
		t.Fatalf("plaintext length field size=%d", length)
	}
	binary.BigEndian.PutUint64(ciphertext[offset:offset+length], MaxPlaintextPerObject+1)
	if _, err := Verify(bytes.NewReader(ciphertext), testKey(1)); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("over-budget header error=%v", err)
	}
}

func TestEncryptRejectsShortAndGrowingPlaintext(t *testing.T) {
	t.Parallel()
	shortMetadata := testMetadata(2, MinChunkSize)
	if err := encryptWithRandom(io.Discard, bytes.NewReader([]byte{1}), testKey(1), shortMetadata, bytes.NewReader([]byte("1234567890abcdef"))); err == nil {
		t.Fatal("short plaintext was accepted")
	}
	longMetadata := testMetadata(1, MinChunkSize)
	if err := encryptWithRandom(io.Discard, bytes.NewReader([]byte{1, 2}), testKey(1), longMetadata, bytes.NewReader([]byte("1234567890abcdef"))); err == nil {
		t.Fatal("growing plaintext was accepted")
	}
}

func TestKeyValidationAndDestroy(t *testing.T) {
	t.Parallel()
	if _, err := NewKey(make([]byte, KeySize-1)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewKey short error = %v", err)
	}
	key, err := NewKey(bytes.Repeat([]byte{7}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
	if !bytes.Equal(key[:], make([]byte, KeySize)) {
		t.Fatal("Destroy did not zero key bytes")
	}
}

func TestExpectedMetadataMustMatchEveryField(t *testing.T) {
	t.Parallel()
	actual := testMetadata(17, MinChunkSize)
	if err := MatchExpected(actual, actual); err != nil {
		t.Fatalf("identical metadata rejected: %v", err)
	}
	mutations := []func(*Metadata){
		func(value *Metadata) { value.SnapshotID += "x" },
		func(value *Metadata) { value.ReleaseID += "x" },
		func(value *Metadata) { value.KeyID += "x" },
		func(value *Metadata) { value.KeyObjectSequence++ },
		func(value *Metadata) { value.LogicalPath += "x" },
		func(value *Metadata) { value.UID++ }, func(value *Metadata) { value.GID++ },
		func(value *Metadata) { value.Mode ^= 1 }, func(value *Metadata) { value.SourceDevice++ },
		func(value *Metadata) { value.SourceInode++ }, func(value *Metadata) { value.PlaintextLength++ },
		func(value *Metadata) { value.SourceMTimeNS++ }, func(value *Metadata) { value.SourceCTimeNS++ },
		func(value *Metadata) { value.ChunkSize++ },
	}
	for index, mutate := range mutations {
		expected := actual
		mutate(&expected)
		if err := MatchExpected(actual, expected); err == nil {
			t.Fatalf("metadata mutation %d was accepted", index)
		}
	}
}

func TestWriteFaultsPropagate(t *testing.T) {
	t.Parallel()
	metadata := testMetadata(64, MinChunkSize)
	failure := errors.New("injected write failure")
	if err := encryptWithRandom(failingWriter{failure}, bytes.NewReader(deterministicBytes(64)), testKey(1), metadata, bytes.NewReader(bytes.Repeat([]byte{1}, SaltSize))); !errors.Is(err, failure) {
		t.Fatalf("Encrypt write error = %v", err)
	}
	ciphertext := encryptFixture(t, deterministicBytes(64), metadata, bytes.Repeat([]byte{1}, SaltSize))
	if _, err := Decrypt(failingWriter{failure}, bytes.NewReader(ciphertext), testKey(1)); !errors.Is(err, failure) {
		t.Fatalf("Decrypt write error = %v", err)
	}
}

func TestWriteAllPartialWriterEdges(t *testing.T) {
	t.Parallel()
	partial := &partialWriter{maximum: 3}
	contents := []byte("abcdefghij")
	if err := writeAll(partial, contents); err != nil {
		t.Fatalf("positive partial writes failed: %v", err)
	}
	if !bytes.Equal(partial.contents, contents) {
		t.Fatalf("partial writer contents=%q", partial.contents)
	}
	if err := writeAll(zeroWriter{}, contents); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress writer error=%v", err)
	}
	if err := writeAll(overreportingWriter{}, contents); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("overreporting writer error=%v", err)
	}
}

type failingWriter struct{ err error }

func (writer failingWriter) Write([]byte) (int, error) { return 0, writer.err }

type partialWriter struct {
	maximum  int
	contents []byte
}

func (writer *partialWriter) Write(contents []byte) (int, error) {
	count := writer.maximum
	if len(contents) < count {
		count = len(contents)
	}
	writer.contents = append(writer.contents, contents[:count]...)
	return count, nil
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type overreportingWriter struct{}

func (overreportingWriter) Write(contents []byte) (int, error) { return len(contents) + 1, nil }

func testMetadata(length uint64, chunkSize uint32) Metadata {
	return Metadata{
		FormatVersion:     FormatVersion,
		SnapshotID:        "snapshot-20260825",
		ReleaseID:         "release-42",
		KeyID:             "key-generation-7",
		KeyObjectSequence: 42,
		LogicalPath:       "/etc/pgw/config.json",
		UID:               0,
		GID:               0,
		Mode:              0o640,
		SourceDevice:      2049,
		SourceInode:       998877,
		PlaintextLength:   length,
		SourceMTimeNS:     1_726_000_000_123_456_789,
		SourceCTimeNS:     1_726_000_001_123_456_789,
		ChunkSize:         chunkSize,
	}
}

func testKey(fill byte) *Key {
	key := Key{}
	for index := range key {
		key[index] = fill
	}
	return &key
}

func deterministicBytes(length int) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = byte((index*131 + 17) % 251)
	}
	return value
}

func encryptFixture(t *testing.T, plaintext []byte, metadata Metadata, nonce []byte) []byte {
	t.Helper()
	var ciphertext bytes.Buffer
	if err := encryptWithRandom(&ciphertext, bytes.NewReader(plaintext), testKey(1), metadata, bytes.NewReader(nonce)); err != nil {
		t.Fatalf("encrypt fixture: %v", err)
	}
	return ciphertext.Bytes()
}

func encodedHeaderLength(ciphertext []byte) int {
	return 16 + int(binary.BigEndian.Uint32(ciphertext[12:16]))
}

func fieldValueOffset(t *testing.T, ciphertext []byte, wanted uint16) (int, int) {
	t.Helper()
	offset := 16
	limit := encodedHeaderLength(ciphertext)
	for offset < limit {
		identifier := binary.BigEndian.Uint16(ciphertext[offset : offset+2])
		length := int(binary.BigEndian.Uint32(ciphertext[offset+2 : offset+6]))
		if identifier == wanted {
			return offset + 6, length
		}
		offset += 6 + length
	}
	t.Fatalf("field %d not found", wanted)
	return 0, 0
}

func nextFieldOffset(ciphertext []byte, offset int) int {
	return offset + 6 + int(binary.BigEndian.Uint32(ciphertext[offset+2:offset+6]))
}
