package snapshotcrypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"
)

const (
	FormatVersion    uint16 = 2
	KeySize                 = 32
	SaltSize                = 16
	GCMTagSize              = 16
	RecordHeaderSize        = 13

	DefaultChunkSize      uint32 = 1024 * 1024
	MinChunkSize          uint32 = 4 * 1024
	MaxChunkSize          uint32 = 16 * 1024 * 1024
	MaxPlaintextPerObject        = uint64(1 << 30)
	MaxChunksPerObject           = uint64(1 << 18)
	MaxObjectsPerKeyID           = uint64(1 << 32)
	MaxSnapshotID                = 128
	MaxReleaseID                 = 128
	MaxKeyID                     = 128
	MaxLogicalPath               = 4096
	MaxHeaderSize                = 16 * 1024
)

var (
	formatMagic = [8]byte{'P', 'G', 'W', 'S', 'N', 'A', 'P', 0}
	aadDomain   = []byte("PGW-SNAPSHOT-CHUNK-AAD-V2\x00")
	kdfDomain   = []byte("PGW-SNAPSHOT-OBJECT-KEY-V2\x00")

	ErrAuthentication = errors.New("snapshot authentication failed")
	ErrInvalidFormat  = errors.New("invalid snapshot format")
	ErrInvalidKey     = errors.New("snapshot key must contain exactly 32 bytes")
	ErrUnsafePath     = errors.New("unsafe snapshot path")
	ErrSourceChanged  = errors.New("plaintext source changed during encryption")
	ErrUnsupported    = errors.New("secure snapshot publication is supported only on Linux")
)

const (
	fieldSnapshotID uint16 = iota + 1
	fieldReleaseID
	fieldKeyID
	fieldKeyObjectSequence
	fieldLogicalPath
	fieldUID
	fieldGID
	fieldMode
	fieldSourceDevice
	fieldSourceInode
	fieldPlaintextLength
	fieldSourceMTimeNS
	fieldSourceCTimeNS
	fieldChunkSize
	fieldSalt
	fieldCount = fieldSalt
)

// Metadata is authenticated for every encrypted chunk. LogicalPath is an
// identifier only and is never interpreted as a publication destination.
type Metadata struct {
	FormatVersion     uint16 `json:"format_version"`
	SnapshotID        string `json:"snapshot_id"`
	ReleaseID         string `json:"release_id"`
	KeyID             string `json:"key_id"`
	KeyObjectSequence uint64 `json:"key_object_sequence"`
	LogicalPath       string `json:"logical_path"`
	UID               uint32 `json:"uid"`
	GID               uint32 `json:"gid"`
	Mode              uint32 `json:"mode"`
	SourceDevice      uint64 `json:"source_device"`
	SourceInode       uint64 `json:"source_inode"`
	PlaintextLength   uint64 `json:"plaintext_length"`
	SourceMTimeNS     int64  `json:"source_mtime_ns"`
	SourceCTimeNS     int64  `json:"source_ctime_ns"`
	ChunkSize         uint32 `json:"chunk_size"`
}

// ExpectedMetadata must come from an independently authenticated manifest.
// Every field is compared before publication.
type ExpectedMetadata = Metadata

type decodedHeader struct {
	metadata Metadata
	salt     [SaltSize]byte
	encoded  []byte
}

func validateMetadata(metadata Metadata) error {
	if metadata.FormatVersion != FormatVersion {
		return fmt.Errorf("%w: unsupported version", ErrInvalidFormat)
	}
	if !validIdentifier(metadata.SnapshotID, MaxSnapshotID) {
		return fmt.Errorf("%w: invalid snapshot id", ErrInvalidFormat)
	}
	if !validIdentifier(metadata.ReleaseID, MaxReleaseID) {
		return fmt.Errorf("%w: invalid release id", ErrInvalidFormat)
	}
	if !validIdentifier(metadata.KeyID, MaxKeyID) {
		return fmt.Errorf("%w: invalid key id", ErrInvalidFormat)
	}
	if metadata.KeyObjectSequence >= MaxObjectsPerKeyID {
		return fmt.Errorf("%w: master-key object limit exceeded; rotate key id", ErrInvalidFormat)
	}
	if !validLogicalPath(metadata.LogicalPath) {
		return fmt.Errorf("%w: invalid logical path", ErrInvalidFormat)
	}
	if metadata.Mode > 0o7777 {
		return fmt.Errorf("%w: invalid mode", ErrInvalidFormat)
	}
	if metadata.ChunkSize < MinChunkSize || metadata.ChunkSize > MaxChunkSize {
		return fmt.Errorf("%w: invalid chunk size", ErrInvalidFormat)
	}
	if metadata.PlaintextLength > MaxPlaintextPerObject {
		return fmt.Errorf("%w: plaintext exceeds 1 GiB per-object limit", ErrInvalidFormat)
	}
	if _, err := chunkCount(metadata.PlaintextLength, metadata.ChunkSize); err != nil {
		return err
	}
	return nil
}

func validIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validLogicalPath(value string) bool {
	if len(value) == 0 || len(value) > MaxLogicalPath || !utf8.ValidString(value) || strings.Contains(value, "\\") {
		return false
	}
	if value == "." || value == "/" || path.Clean(value) != value {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
		for _, character := range component {
			if character < 0x20 || character == 0x7f {
				return false
			}
		}
	}
	return true
}

func chunkCount(total uint64, chunkSize uint32) (uint64, error) {
	if chunkSize == 0 {
		return 0, fmt.Errorf("%w: zero chunk size", ErrInvalidFormat)
	}
	if total == 0 {
		return 1, nil
	}
	count := (total-1)/uint64(chunkSize) + 1
	if count > MaxChunksPerObject {
		return 0, fmt.Errorf("%w: per-object derived-key chunk limit exceeded", ErrInvalidFormat)
	}
	return count, nil
}

func buildHeader(metadata Metadata, salt [SaltSize]byte) ([]byte, error) {
	if err := validateMetadata(metadata); err != nil {
		return nil, err
	}
	payload := bytes.NewBuffer(make([]byte, 0, 640+len(metadata.LogicalPath)))
	writeField(payload, fieldSnapshotID, []byte(metadata.SnapshotID))
	writeField(payload, fieldReleaseID, []byte(metadata.ReleaseID))
	writeField(payload, fieldKeyID, []byte(metadata.KeyID))
	writeUint64Field(payload, fieldKeyObjectSequence, metadata.KeyObjectSequence)
	writeField(payload, fieldLogicalPath, []byte(metadata.LogicalPath))
	writeUint32Field(payload, fieldUID, metadata.UID)
	writeUint32Field(payload, fieldGID, metadata.GID)
	writeUint32Field(payload, fieldMode, metadata.Mode)
	writeUint64Field(payload, fieldSourceDevice, metadata.SourceDevice)
	writeUint64Field(payload, fieldSourceInode, metadata.SourceInode)
	writeUint64Field(payload, fieldPlaintextLength, metadata.PlaintextLength)
	writeUint64Field(payload, fieldSourceMTimeNS, uint64(metadata.SourceMTimeNS))
	writeUint64Field(payload, fieldSourceCTimeNS, uint64(metadata.SourceCTimeNS))
	writeUint32Field(payload, fieldChunkSize, metadata.ChunkSize)
	writeField(payload, fieldSalt, salt[:])
	if payload.Len() > MaxHeaderSize-16 {
		return nil, fmt.Errorf("%w: header exceeds limit", ErrInvalidFormat)
	}

	header := bytes.NewBuffer(make([]byte, 0, 16+payload.Len()))
	header.Write(formatMagic[:])
	_ = binary.Write(header, binary.BigEndian, FormatVersion)
	_ = binary.Write(header, binary.BigEndian, uint16(fieldCount))
	_ = binary.Write(header, binary.BigEndian, uint32(payload.Len()))
	header.Write(payload.Bytes())
	return header.Bytes(), nil
}

func writeField(destination *bytes.Buffer, identifier uint16, value []byte) {
	_ = binary.Write(destination, binary.BigEndian, identifier)
	_ = binary.Write(destination, binary.BigEndian, uint32(len(value)))
	destination.Write(value)
}

func writeUint32Field(destination *bytes.Buffer, identifier uint16, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	writeField(destination, identifier, encoded[:])
}

func writeUint64Field(destination *bytes.Buffer, identifier uint16, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeField(destination, identifier, encoded[:])
}
