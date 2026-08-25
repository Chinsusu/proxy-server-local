package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileLKGStoreRoundTripAndIntegrity(t *testing.T) {
	store := FileLKGStore{Directory: filepath.Join(t.TempDir(), "rules")}
	if _, err := store.Load(); !errors.Is(err, ErrLKGNotFound) {
		t.Fatalf("initial Load error = %v", err)
	}
	lkg := emptyLKG(t)
	lkg.Metadata.Generation = 12
	lkg.Metadata.Runtimes = []RuntimeRecord{{MappingID: "m1", Port: 15001, SpecHash: strings.Repeat("a", 64)}}
	if err := store.Save(lkg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Metadata.Generation != 12 || loaded.Rules != lkg.Rules {
		t.Fatalf("loaded LKG mismatch: %+v", loaded.Metadata)
	}
	if err := os.WriteFile(filepath.Join(store.Directory, lkgRulesFile), []byte(lkg.Rules+"# tampered\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("tampered LKG error = %v", err)
	}
}

func TestFileLKGStoreRejectsBaseOwnership(t *testing.T) {
	store := FileLKGStore{Directory: filepath.Join(t.TempDir(), "rules")}
	lkg := emptyLKG(t)
	lkg.Rules += "delete table inet pgw_base\n"
	lkg.Metadata.RulesSHA256 = scriptHash(lkg.Rules)
	if err := store.Save(lkg); err == nil {
		t.Fatal("unsafe base-table LKG was accepted")
	}
}
