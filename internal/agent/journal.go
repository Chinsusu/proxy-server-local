package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	transitionJournalFile    = "runtime-transition.json"
	transitionJournalVersion = 1
	maxTransitionBytes       = maxLKGBytes + (1 << 20)
)

type TransitionPhase string

const (
	TransitionPrepared          TransitionPhase = "PREPARED"
	TransitionRedirectsRemoved  TransitionPhase = "REDIRECTS_REMOVED"
	TransitionForwardersChanged TransitionPhase = "FORWARDERS_CHANGED"
	TransitionNFTApplied        TransitionPhase = "NFT_APPLIED"
	TransitionLKGStored         TransitionPhase = "LKG_STORED"
	TransitionRestored          TransitionPhase = "RESTORED"
)

type RuntimeTransitionEntry struct {
	MappingID        string `json:"mapping_id"`
	Port             int    `json:"port"`
	OldMappingID     string `json:"old_mapping_id,omitempty"`
	OldSpecHash      string `json:"old_spec_hash,omitempty"`
	NewSpecHash      string `json:"new_spec_hash"`
	RestorePath      string `json:"restore_path,omitempty"`
	RestoreIntegrity string `json:"restore_integrity,omitempty"`
}

type RuntimeTransitionJournal struct {
	Version             int                      `json:"version"`
	DesiredGeneration   int64                    `json:"desired_generation"`
	PreviousGeneration  int64                    `json:"previous_generation"`
	PreviousDesiredHash string                   `json:"previous_desired_hash"`
	PreviousAppliedHash string                   `json:"previous_applied_hash"`
	PreviousRulesSHA256 string                   `json:"previous_rules_sha256"`
	PreviousLKG         LKG                      `json:"previous_lkg"`
	Entries             []RuntimeTransitionEntry `json:"entries"`
	Phase               TransitionPhase          `json:"phase"`
	Checksum            string                   `json:"checksum"`
}

type transitionChecksumInput struct {
	Version             int                      `json:"version"`
	DesiredGeneration   int64                    `json:"desired_generation"`
	PreviousGeneration  int64                    `json:"previous_generation"`
	PreviousDesiredHash string                   `json:"previous_desired_hash"`
	PreviousAppliedHash string                   `json:"previous_applied_hash"`
	PreviousRulesSHA256 string                   `json:"previous_rules_sha256"`
	PreviousLKG         LKG                      `json:"previous_lkg"`
	Entries             []RuntimeTransitionEntry `json:"entries"`
	Phase               TransitionPhase          `json:"phase"`
}

func newTransitionJournal(generation int64, previous LKG, entries []RuntimeTransitionEntry) RuntimeTransitionJournal {
	journal := RuntimeTransitionJournal{
		Version: transitionJournalVersion, DesiredGeneration: generation,
		PreviousGeneration: previous.Metadata.Generation, PreviousDesiredHash: previous.Metadata.DesiredHash,
		PreviousAppliedHash: previous.Metadata.AppliedHash, PreviousRulesSHA256: previous.Metadata.RulesSHA256,
		PreviousLKG: previous, Entries: append([]RuntimeTransitionEntry(nil), entries...), Phase: TransitionPrepared,
	}
	sealTransition(&journal)
	return journal
}

func (s FileLKGStore) LoadTransition() (RuntimeTransitionJournal, error) {
	if err := validateStoreDirectory(s.Directory, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RuntimeTransitionJournal{}, ErrTransitionNotFound
		}
		return RuntimeTransitionJournal{}, err
	}
	data, err := readRegularBounded(filepath.Join(s.Directory, transitionJournalFile), maxTransitionBytes)
	if errors.Is(err, os.ErrNotExist) {
		return RuntimeTransitionJournal{}, ErrTransitionNotFound
	}
	if err != nil {
		return RuntimeTransitionJournal{}, fmt.Errorf("agent: read runtime transition journal: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal RuntimeTransitionJournal
	if err := decoder.Decode(&journal); err != nil {
		return RuntimeTransitionJournal{}, fmt.Errorf("agent: decode runtime transition journal: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return RuntimeTransitionJournal{}, fmt.Errorf("agent: decode runtime transition journal: %w", err)
	}
	if err := validateTransition(journal); err != nil {
		return RuntimeTransitionJournal{}, err
	}
	return journal, nil
}

func (s FileLKGStore) SaveTransition(journal RuntimeTransitionJournal) error {
	if err := ensureStoreDirectory(s.Directory); err != nil {
		return err
	}
	journal.Version = transitionJournalVersion
	sort.Slice(journal.Entries, func(i, j int) bool {
		if journal.Entries[i].Port != journal.Entries[j].Port {
			return journal.Entries[i].Port < journal.Entries[j].Port
		}
		return journal.Entries[i].MappingID < journal.Entries[j].MappingID
	})
	sealTransition(&journal)
	if err := validateTransition(journal); err != nil {
		return err
	}
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: encode runtime transition journal: %w", err)
	}
	data = append(data, '\n')
	if err := secureWriteFileAtomic(s.Directory, transitionJournalFile, data, 0o600); err != nil {
		return fmt.Errorf("agent: publish runtime transition journal: %w", err)
	}
	return nil
}

func (s FileLKGStore) ClearTransition() error {
	if err := validateStoreDirectory(s.Directory, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := secureRemoveFile(s.Directory, transitionJournalFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("agent: clear runtime transition journal: %w", err)
	}
	return nil
}

func validateTransition(journal RuntimeTransitionJournal) error {
	if journal.Version != transitionJournalVersion {
		return fmt.Errorf("agent: unsupported runtime transition journal version %d", journal.Version)
	}
	switch journal.Phase {
	case TransitionPrepared, TransitionRedirectsRemoved, TransitionForwardersChanged, TransitionNFTApplied, TransitionLKGStored, TransitionRestored:
	default:
		return fmt.Errorf("agent: invalid runtime transition phase")
	}
	if journal.DesiredGeneration < 0 || len(journal.Entries) == 0 {
		return fmt.Errorf("agent: invalid runtime transition identity")
	}
	if err := validateLKG(journal.PreviousLKG); err != nil {
		return fmt.Errorf("agent: invalid previous LKG in runtime transition: %w", err)
	}
	metadata := journal.PreviousLKG.Metadata
	if journal.PreviousGeneration != metadata.Generation || journal.PreviousDesiredHash != metadata.DesiredHash ||
		journal.PreviousAppliedHash != metadata.AppliedHash || journal.PreviousRulesSHA256 != metadata.RulesSHA256 {
		return fmt.Errorf("agent: runtime transition previous LKG binding mismatch")
	}
	seenPorts := make(map[int]struct{}, len(journal.Entries))
	previousByPort := recordsByPort(journal.PreviousLKG.Metadata.Runtimes)
	for _, entry := range journal.Entries {
		if !safeMappingID.MatchString(entry.MappingID) || entry.Port < 1 || entry.Port > 65535 || !isSHA256(entry.NewSpecHash) {
			return fmt.Errorf("agent: invalid runtime transition entry")
		}
		if _, exists := seenPorts[entry.Port]; exists {
			return fmt.Errorf("agent: duplicate runtime transition port %d", entry.Port)
		}
		seenPorts[entry.Port] = struct{}{}
		if entry.RestorePath == "" {
			if entry.OldMappingID != "" || entry.OldSpecHash != "" || entry.RestoreIntegrity != "" {
				return fmt.Errorf("agent: incomplete added-runtime transition entry")
			}
			if _, represented := previousByPort[entry.Port]; represented {
				return fmt.Errorf("agent: new-runtime transition port is already represented by previous LKG")
			}
			continue
		}
		if !safeMappingID.MatchString(entry.OldMappingID) || !filepath.IsAbs(entry.RestorePath) || !isSHA256(entry.OldSpecHash) || !isSHA256(entry.RestoreIntegrity) {
			return fmt.Errorf("agent: invalid restore-point transition entry")
		}
		previous, represented := previousByPort[entry.Port]
		if !represented || previous.MappingID != entry.OldMappingID || previous.SpecHash != entry.OldSpecHash {
			return fmt.Errorf("agent: restore-point transition does not match previous LKG runtime")
		}
	}
	want := transitionChecksum(journal)
	if journal.Checksum == "" || journal.Checksum != want {
		return fmt.Errorf("agent: runtime transition journal checksum mismatch")
	}
	return nil
}

func sealTransition(journal *RuntimeTransitionJournal) {
	journal.Checksum = transitionChecksum(*journal)
}

func transitionChecksum(journal RuntimeTransitionJournal) string {
	payload := transitionChecksumInput{
		Version: journal.Version, DesiredGeneration: journal.DesiredGeneration,
		PreviousGeneration: journal.PreviousGeneration, PreviousDesiredHash: journal.PreviousDesiredHash,
		PreviousAppliedHash: journal.PreviousAppliedHash, PreviousRulesSHA256: journal.PreviousRulesSHA256,
		PreviousLKG: journal.PreviousLKG, Entries: journal.Entries, Phase: journal.Phase,
	}
	encoded, _ := json.Marshal(payload)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
