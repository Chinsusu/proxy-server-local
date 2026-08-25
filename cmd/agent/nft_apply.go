package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Chinsusu/proxy-server-local/pkg/nft"
)

func replaceDynamicRules(cfg cfgAgent, candidate string) error {
	present, err := listOwnedTables(cfg.NftBinary)
	if err != nil {
		return err
	}

	lastKnownGood := map[string]string{}
	for _, table := range dynamicTables {
		key := table.family + ":" + table.name
		if !present[key] {
			continue
		}
		output, err := runNFTOutput(cfg.NftBinary, "-s", "list", "table", table.family, table.name)
		if err != nil {
			return fmt.Errorf("snapshot dynamic LKG table %s: %w; output=%s", key, err, string(output))
		}
		lastKnownGood[key] = string(output)
	}

	transaction := buildDynamicTransaction(present, candidate)
	if output, err := runNFTInput(cfg.NftBinary, []string{"-c", "-f", "-"}, transaction); err != nil {
		return fmt.Errorf("validate candidate transaction: %w; output=%s", err, string(output))
	}
	if output, err := runNFTInput(cfg.NftBinary, []string{"-f", "-"}, transaction); err != nil {
		return fmt.Errorf("apply candidate transaction: %w; output=%s", err, string(output))
	}

	if err := verifyDynamicFirewall(cfg.NftBinary, cfg, candidate); err != nil {
		rollback := fmt.Sprintf("delete table inet %s\n", nft.DynamicTableName)
		for _, table := range dynamicTables {
			rollback += lastKnownGood[table.family+":"+table.name]
		}
		if output, checkErr := runNFTInput(cfg.NftBinary, []string{"-c", "-f", "-"}, rollback); checkErr != nil {
			return fmt.Errorf("post-apply verify: %v; validate LKG rollback: %w; output=%s", err, checkErr, string(output))
		}
		if output, rollbackErr := runNFTInput(cfg.NftBinary, []string{"-f", "-"}, rollback); rollbackErr != nil {
			return fmt.Errorf("post-apply verify: %v; restore LKG: %w; output=%s", err, rollbackErr, string(output))
		}
		return fmt.Errorf("post-apply verify failed; restored prior dynamic LKG: %w", err)
	}
	return nil
}

// applyDynamicWithLKG validates and applies one pgw-owned transaction. Any
// apply or exact read-back failure triggers a checked rollback to the durable
// add-only LKG script. Neither transaction can mention inet pgw_base.
func applyDynamicWithLKG(cfg cfgAgent, candidate, lkg string) (string, bool, error) {
	present, err := listOwnedTables(cfg.NftBinary)
	if err != nil {
		return "", false, err
	}
	transaction := buildDynamicTransaction(present, candidate)
	if output, checkErr := runNFTInput(cfg.NftBinary, []string{"-c", "-f", "-"}, transaction); checkErr != nil {
		return "", false, fmt.Errorf("validate candidate transaction: %w; output=%s", checkErr, string(output))
	}
	if output, applyErr := runNFTInput(cfg.NftBinary, []string{"-f", "-"}, transaction); applyErr != nil {
		rollbackErr := rollbackDynamicWithLKG(cfg, lkg)
		return "", rollbackErr == nil, errors.Join(fmt.Errorf("apply candidate transaction: %w; output=%s", applyErr, string(output)), rollbackErr)
	}
	hash, verifyErr := dynamicSemanticHash(cfg.NftBinary, cfg, candidate)
	if verifyErr != nil {
		rollbackErr := rollbackDynamicWithLKG(cfg, lkg)
		return "", rollbackErr == nil, errors.Join(fmt.Errorf("post-apply semantic verification: %w", verifyErr), rollbackErr)
	}
	return hash, false, nil
}

func applyDynamicWithLKGContext(ctx context.Context, cfg cfgAgent, candidate, lkg string) (string, bool, error) {
	present, err := listOwnedTablesContext(ctx, cfg.NftBinary)
	if err != nil {
		return "", false, err
	}
	transaction := buildDynamicTransaction(present, candidate)
	if output, checkErr := runNFTInputContext(ctx, cfg.NftBinary, []string{"-c", "-f", "-"}, transaction); checkErr != nil {
		return "", false, fmt.Errorf("validate candidate transaction: %w; output=%s", checkErr, string(output))
	}
	if output, applyErr := runNFTInputContext(ctx, cfg.NftBinary, []string{"-f", "-"}, transaction); applyErr != nil {
		rollbackCtx, cancelRollback := context.WithTimeout(context.WithoutCancel(ctx), nftCommandTimeout(cfg))
		defer cancelRollback()
		rollbackErr := rollbackDynamicWithLKGContext(rollbackCtx, cfg, lkg)
		return "", rollbackErr == nil, errors.Join(fmt.Errorf("apply candidate transaction: %w; output=%s", applyErr, string(output)), rollbackErr)
	}
	hash, verifyErr := dynamicSemanticHashContext(ctx, cfg.NftBinary, cfg, candidate)
	if verifyErr != nil {
		rollbackCtx, cancelRollback := context.WithTimeout(context.WithoutCancel(ctx), nftCommandTimeout(cfg))
		defer cancelRollback()
		rollbackErr := rollbackDynamicWithLKGContext(rollbackCtx, cfg, lkg)
		return "", rollbackErr == nil, errors.Join(fmt.Errorf("post-apply semantic verification: %w", verifyErr), rollbackErr)
	}
	return hash, false, nil
}

func checkDynamicCandidate(cfg cfgAgent, candidate string) error {
	if err := validateDynamicCandidateScript(candidate); err != nil {
		return err
	}
	present, err := listOwnedTables(cfg.NftBinary)
	if err != nil {
		return err
	}
	transaction := buildDynamicTransaction(present, candidate)
	if output, err := runNFTInput(cfg.NftBinary, []string{"-c", "-f", "-"}, transaction); err != nil {
		return fmt.Errorf("validate candidate transaction: %w; output=%s", err, string(output))
	}
	return nil
}

func checkDynamicCandidateContext(ctx context.Context, cfg cfgAgent, candidate string) error {
	if err := validateDynamicCandidateScript(candidate); err != nil {
		return err
	}
	present, err := listOwnedTablesContext(ctx, cfg.NftBinary)
	if err != nil {
		return err
	}
	transaction := buildDynamicTransaction(present, candidate)
	if output, err := runNFTInputContext(ctx, cfg.NftBinary, []string{"-c", "-f", "-"}, transaction); err != nil {
		return fmt.Errorf("validate candidate transaction: %w; output=%s", err, string(output))
	}
	return nil
}

func rollbackDynamicWithLKG(cfg cfgAgent, lkg string) error {
	if strings.Contains(lkg, "pgw_base") || strings.Contains(lkg, "flush ruleset") {
		return fmt.Errorf("refuse unsafe LKG rollback")
	}
	if err := validateDynamicCandidateScript(lkg); err != nil {
		return fmt.Errorf("refuse invalid LKG rollback: %w", err)
	}
	present, err := listOwnedTables(cfg.NftBinary)
	if err != nil {
		return err
	}
	transaction := buildDynamicTransaction(present, lkg)
	if output, err := runNFTInput(cfg.NftBinary, []string{"-c", "-f", "-"}, transaction); err != nil {
		return fmt.Errorf("validate LKG rollback: %w; output=%s", err, string(output))
	}
	if output, err := runNFTInput(cfg.NftBinary, []string{"-f", "-"}, transaction); err != nil {
		return fmt.Errorf("apply LKG rollback: %w; output=%s", err, string(output))
	}
	if _, err := dynamicSemanticHash(cfg.NftBinary, cfg, lkg); err != nil {
		return fmt.Errorf("verify LKG rollback: %w", err)
	}
	return nil
}

func rollbackDynamicWithLKGContext(ctx context.Context, cfg cfgAgent, lkg string) error {
	if strings.Contains(lkg, "pgw_base") || strings.Contains(lkg, "flush ruleset") {
		return fmt.Errorf("refuse unsafe LKG rollback")
	}
	if err := validateDynamicCandidateScript(lkg); err != nil {
		return fmt.Errorf("refuse invalid LKG rollback: %w", err)
	}
	present, err := listOwnedTablesContext(ctx, cfg.NftBinary)
	if err != nil {
		return err
	}
	transaction := buildDynamicTransaction(present, lkg)
	if output, err := runNFTInputContext(ctx, cfg.NftBinary, []string{"-c", "-f", "-"}, transaction); err != nil {
		return fmt.Errorf("validate LKG rollback: %w; output=%s", err, string(output))
	}
	if output, err := runNFTInputContext(ctx, cfg.NftBinary, []string{"-f", "-"}, transaction); err != nil {
		return fmt.Errorf("apply LKG rollback: %w; output=%s", err, string(output))
	}
	if _, err := dynamicSemanticHashContext(ctx, cfg.NftBinary, cfg, lkg); err != nil {
		return fmt.Errorf("verify LKG rollback: %w", err)
	}
	return nil
}

func listOwnedTables(bin string) (map[string]bool, error) {
	output, err := runNFTOutput(bin, "-j", "list", "tables")
	if err != nil {
		return nil, fmt.Errorf("list nft tables before dynamic transaction: %w; output=%s", err, string(output))
	}
	return decodeOwnedTables(output)
}

func listOwnedTablesContext(ctx context.Context, bin string) (map[string]bool, error) {
	output, err := runNFTOutputContext(ctx, bin, "-j", "list", "tables")
	if err != nil {
		return nil, fmt.Errorf("list nft tables before dynamic transaction: %w; output=%s", err, string(output))
	}
	return decodeOwnedTables(output)
}

func decodeOwnedTables(output []byte) (map[string]bool, error) {
	var document nftDocument
	if err := json.Unmarshal(output, &document); err != nil {
		return nil, fmt.Errorf("parse nft table list: %w", err)
	}
	owned := map[string]bool{}
	for _, entry := range document.NFTables {
		raw := entry["table"]
		if raw == nil {
			continue
		}
		var table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		if err := json.Unmarshal(raw, &table); err != nil {
			return nil, fmt.Errorf("parse nft table object: %w", err)
		}
		for _, allowed := range dynamicTables {
			if table.Family == allowed.family && table.Name == allowed.name {
				owned[table.Family+":"+table.Name] = true
			}
		}
	}
	return owned, nil
}

func buildDynamicTransaction(present map[string]bool, candidate string) string {
	var transaction strings.Builder
	for _, table := range dynamicTables {
		if present[table.family+":"+table.name] {
			fmt.Fprintf(&transaction, "delete table %s %s\n", table.family, table.name)
		}
	}
	transaction.WriteString(candidate)
	return transaction.String()
}
