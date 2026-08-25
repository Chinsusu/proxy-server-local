package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	agentcore "github.com/Chinsusu/proxy-server-local/internal/agent"
)

type nftDataPlane struct {
	config    cfgAgent
	telemetry *agentcore.Telemetry
}

func (n nftDataPlane) VerifyBase(ctx context.Context) error {
	commandCtx, cancel := context.WithTimeout(ctx, nftCommandTimeout(n.config))
	defer cancel()
	return verifyBaseFirewallContext(commandCtx, n.config.NftBinary, n.config)
}

func (n nftDataPlane) Check(ctx context.Context, candidate string) error {
	commandCtx, cancel := context.WithTimeout(ctx, nftCommandTimeout(n.config))
	defer cancel()
	return checkDynamicCandidateContext(commandCtx, n.config, candidate)
}

func (n nftDataPlane) Apply(ctx context.Context, candidate, lkg string) (string, bool, error) {
	commandCtx, cancel := context.WithTimeout(ctx, nftCommandTimeout(n.config))
	defer cancel()
	hash, rolledBack, err := applyDynamicWithLKGContext(commandCtx, n.config, candidate, lkg)
	if n.telemetry != nil {
		outcome := "success"
		if err != nil {
			outcome = "failure"
		}
		n.telemetry.Metrics.ObserveNFT("readback", outcome)
	}
	return hash, rolledBack, err
}

func (n nftDataPlane) Rollback(ctx context.Context, lkg string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, nftCommandTimeout(n.config))
	defer cancel()
	if err := rollbackDynamicWithLKGContext(commandCtx, n.config, lkg); err != nil {
		return "", err
	}
	return dynamicSemanticHashContext(commandCtx, n.config.NftBinary, n.config, lkg)
}

func nftCommandTimeout(config cfgAgent) time.Duration {
	if config.NftTimeout <= 0 {
		return 5 * time.Second
	}
	return config.NftTimeout
}

type systemdCommander struct{ binary string }

func (s systemdCommander) Start(ctx context.Context, unit string) error {
	return s.run(ctx, "start", unit)
}

func (s systemdCommander) Restart(ctx context.Context, unit string) error {
	return s.run(ctx, "restart", unit)
}

func (s systemdCommander) Stop(ctx context.Context, unit string) error {
	return s.run(ctx, "stop", unit)
}

func (s systemdCommander) State(ctx context.Context, unit string) (string, string, error) {
	output, err := exec.CommandContext(ctx, s.binary, "show", unit, "--property=ActiveState", "--property=SubState", "--no-pager").CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("systemd show failed: %w", err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			values[key] = value
		}
	}
	if values["ActiveState"] == "" || values["SubState"] == "" {
		return "", "", fmt.Errorf("systemd returned incomplete unit state")
	}
	return values["ActiveState"], values["SubState"], nil
}

func (s systemdCommander) run(ctx context.Context, verb, unit string) error {
	output, err := exec.CommandContext(ctx, s.binary, verb, unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd %s failed: %w; output=%s", verb, err, strings.TrimSpace(string(output)))
	}
	return nil
}

var _ agentcore.DataPlane = nftDataPlane{}
var _ agentcore.Systemd = systemdCommander{}
