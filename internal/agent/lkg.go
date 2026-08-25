package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	lkgRulesFile = "lkg.nft"
	lkgMetaFile  = "lkg.meta.json"
	maxLKGBytes  = 4 << 20
)

type FileLKGStore struct{ Directory string }

func (s FileLKGStore) Load() (LKG, error) {
	if err := validateStoreDirectory(s.Directory, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return LKG{}, ErrLKGNotFound
		}
		return LKG{}, err
	}
	rules, err := readRegularBounded(filepath.Join(s.Directory, lkgRulesFile), maxLKGBytes)
	if errors.Is(err, os.ErrNotExist) {
		return LKG{}, ErrLKGNotFound
	}
	if err != nil {
		return LKG{}, fmt.Errorf("agent: read LKG rules: %w", err)
	}
	metadataBytes, err := readRegularBounded(filepath.Join(s.Directory, lkgMetaFile), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return LKG{}, ErrLKGNotFound
	}
	if err != nil {
		return LKG{}, fmt.Errorf("agent: read LKG metadata: %w", err)
	}
	var metadata LKGMetadata
	decoder := json.NewDecoder(strings.NewReader(string(metadataBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return LKG{}, fmt.Errorf("agent: decode LKG metadata: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return LKG{}, fmt.Errorf("agent: decode LKG metadata: %w", err)
	}
	lkg := LKG{Rules: strings.ReplaceAll(string(rules), "\r\n", "\n"), Metadata: metadata}
	if err := validateLKG(lkg); err != nil {
		return LKG{}, err
	}
	return lkg, nil
}

func (s FileLKGStore) Save(lkg LKG) error {
	lkg.Rules = strings.ReplaceAll(lkg.Rules, "\r\n", "\n")
	lkg.Metadata.Version = lkgVersion
	lkg.Metadata.RulesSHA256 = scriptHash(lkg.Rules)
	sortRuntimeRecords(lkg.Metadata.Runtimes)
	sortRuntimeRecords(lkg.Metadata.PendingStops)
	if err := validateLKG(lkg); err != nil {
		return err
	}
	if err := ensureStoreDirectory(s.Directory); err != nil {
		return err
	}
	metadata, err := json.MarshalIndent(lkg.Metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encode LKG metadata: %w", err)
	}
	metadata = append(metadata, '\n')

	// Metadata is published last and integrity-binds the rules bytes. Both
	// writes are descriptor-bound, individually atomic, and fsync their dirfd;
	// a crash between them is detected and remains fail-close.
	if err := secureWriteFileAtomic(s.Directory, lkgRulesFile, []byte(lkg.Rules), 0o640); err != nil {
		return fmt.Errorf("agent: publish LKG rules: %w", err)
	}
	if err := secureWriteFileAtomic(s.Directory, lkgMetaFile, metadata, 0o640); err != nil {
		return fmt.Errorf("agent: publish LKG metadata: %w", err)
	}
	return nil
}

func validateLKG(lkg LKG) error {
	if lkg.Metadata.Version != lkgVersion {
		return fmt.Errorf("agent: unsupported LKG metadata version %d", lkg.Metadata.Version)
	}
	if strings.TrimSpace(lkg.Rules) == "" || !strings.Contains(lkg.Rules, "add table inet pgw_dynamic") {
		return fmt.Errorf("agent: LKG does not contain pgw_dynamic")
	}
	if strings.Contains(lkg.Rules, "pgw_base") || strings.Contains(lkg.Rules, "flush ruleset") {
		return fmt.Errorf("agent: LKG attempts to own static firewall state")
	}
	hash := sha256.Sum256([]byte(lkg.Rules))
	if lkg.Metadata.RulesSHA256 != hex.EncodeToString(hash[:]) {
		return fmt.Errorf("agent: LKG rules integrity mismatch")
	}
	for _, records := range [][]RuntimeRecord{lkg.Metadata.Runtimes, lkg.Metadata.PendingStops} {
		seen := map[int]struct{}{}
		for _, record := range records {
			if record.MappingID == "" || record.Port < 1 || record.Port > 65535 || len(record.SpecHash) != 64 {
				return fmt.Errorf("agent: invalid LKG runtime record")
			}
			if _, exists := seen[record.Port]; exists {
				return fmt.Errorf("agent: duplicate LKG runtime port %d", record.Port)
			}
			seen[record.Port] = struct{}{}
		}
	}
	return nil
}

func ensureStoreDirectory(directory string) error {
	if strings.TrimSpace(directory) == "" {
		return fmt.Errorf("agent: LKG directory is required")
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return fmt.Errorf("agent: LKG directory must be an absolute clean path")
	}
	if err := secureEnsureDirectory(directory, 0o750); err != nil {
		return fmt.Errorf("agent: create LKG directory: %w", err)
	}
	return nil
}

func validateStoreDirectory(directory string, mustExist bool) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return fmt.Errorf("agent: LKG directory must be an absolute clean path")
	}
	_ = mustExist
	return secureValidateDirectory(directory)
}

func readRegularBounded(path string, limit int64) ([]byte, error) {
	return secureReadRegular(path, limit)
}

func rejectSymlink(path string) error {
	return secureValidateExisting(path)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON")
		}
		return err
	}
	return nil
}

func sortRuntimeRecords(records []RuntimeRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Port != records[j].Port {
			return records[i].Port < records[j].Port
		}
		return records[i].MappingID < records[j].MappingID
	})
}
