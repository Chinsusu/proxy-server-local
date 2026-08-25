package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/nft"
	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

func TestRenderRulesDelegatesToDynamicRenderer(t *testing.T) {
	t.Parallel()

	wantBytes, err := os.ReadFile("../../pkg/nft/testdata/dynamic_web_only.golden.nft")
	if err != nil {
		t.Fatalf("read legacy golden ruleset: %v", err)
	}
	want := strings.ReplaceAll(string(wantBytes), "\r\n", "\n")

	got, err := renderRules(cfgAgent{LANIF: "lan0", WANIF: "wan0"}, []types.MappingView{
		mappingForRenderTest("client-130", "192.168.2.130/32", "APPLIED", 15002),
		mappingForRenderTest("client-101", "192.168.2.101/32", "applied", 15001),
		mappingForRenderTest("subnet", "192.168.2.128/25", "PENDING", 15002),
		mappingForRenderTest("duplicate-subnet", "192.168.2.128/25", "APPLIED", 15002),
	})
	if err != nil {
		t.Fatalf("renderRules: %v", err)
	}
	if got != want {
		t.Fatalf("agent renderer seam changed dynamic output\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestRenderBaseCommand(t *testing.T) {
	t.Parallel()

	wantBytes, err := os.ReadFile("../../pkg/nft/testdata/base_default.golden.nft")
	if err != nil {
		t.Fatalf("read base golden ruleset: %v", err)
	}
	want := strings.ReplaceAll(string(wantBytes), "\r\n", "\n")
	var output bytes.Buffer
	handled, err := renderBaseCommand([]string{
		"render-base",
		"--lan", "lan0",
		"--wan", "wan0",
		"--management-ports", "8081,8080,8081",
	}, &output)
	if err != nil {
		t.Fatalf("renderBaseCommand: %v", err)
	}
	if !handled {
		t.Fatal("render-base command was not handled")
	}
	if output.String() != want {
		t.Fatalf("render-base output mismatch\nwant:\n%s\ngot:\n%s", want, output.String())
	}
}

func TestRenderBaseCommandRejectsLANAgentPort(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	handled, err := renderBaseCommand([]string{
		"render-base", "--lan", "lan0", "--wan", "wan0", "--management-ports", "8080,9090",
	}, &output)
	if !handled || err == nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
}

func TestVerifyBaseFirewallRejectsMissingObject(t *testing.T) {
	originalRunNFTOutput := runNFTOutput
	t.Cleanup(func() { runNFTOutput = originalRunNFTOutput })
	runNFTOutput = func(string, ...string) ([]byte, error) {
		return baseFirewallJSON(t, "chain:input_guard"), nil
	}

	if err := verifyBaseFirewall("nft", testAgentConfig()); err == nil || !strings.Contains(err.Error(), "input_guard") {
		t.Fatalf("verifyBaseFirewall error = %v, want missing input_guard", err)
	}
}

func TestVerifyBaseFirewallAcceptsAllEgressLANIPv6Drop(t *testing.T) {
	originalRunNFTOutput := runNFTOutput
	t.Cleanup(func() { runNFTOutput = originalRunNFTOutput })
	runNFTOutput = func(string, ...string) ([]byte, error) {
		return baseFirewallJSON(t, ""), nil
	}

	if err := verifyBaseFirewall("nft", testAgentConfig()); err != nil {
		t.Fatalf("verifyBaseFirewall: %v", err)
	}
}

func TestVerifyBaseFirewallRejectsWANScopedIPv6Drop(t *testing.T) {
	document := baseFirewallJSON(t, "", "wan-scoped-ipv6")

	err := verifyBaseFirewallDocument(document, testAgentConfig())
	if err == nil || !strings.Contains(err.Error(), "base forward policy mismatch") {
		t.Fatalf("verifyBaseFirewallDocument error = %v, want WAN-scoped IPv6 rule rejection", err)
	}
}

func TestVerifyBaseFirewallRejectsUnavailableTable(t *testing.T) {
	originalRunNFTOutput := runNFTOutput
	t.Cleanup(func() { runNFTOutput = originalRunNFTOutput })
	runNFTOutput = func(string, ...string) ([]byte, error) {
		return []byte("No such file or directory"), errors.New("exit status 1")
	}

	if err := verifyBaseFirewall("nft", testAgentConfig()); err == nil || !strings.Contains(err.Error(), "ruleset") {
		t.Fatalf("verifyBaseFirewall error = %v, want unavailable ruleset", err)
	}
}

func TestVerifyBaseFirewallRejectsUnsafeRuleSemantics(t *testing.T) {
	for _, mutation := range []string{"remove-final-drop", "accept-final", "log-prefix-drop", "wrong-interface", "wrong-hook", "extra-chain", "extra-counter", "extra-set"} {
		t.Run(mutation, func(t *testing.T) {
			originalRunNFTOutput := runNFTOutput
			t.Cleanup(func() { runNFTOutput = originalRunNFTOutput })
			runNFTOutput = func(string, ...string) ([]byte, error) {
				return baseFirewallJSON(t, "", mutation), nil
			}
			if err := verifyBaseFirewall("nft", testAgentConfig()); err == nil {
				t.Fatalf("verifyBaseFirewall accepted unsafe mutation %q", mutation)
			}
		})
	}
}

func TestVerifyBootBaseFirewallRejectsPersistedDynamicTable(t *testing.T) {
	originalRunNFTOutput := runNFTOutput
	t.Cleanup(func() { runNFTOutput = originalRunNFTOutput })
	runNFTOutput = func(_ string, args ...string) ([]byte, error) {
		if strings.Join(args, " ") != "-j list ruleset" {
			t.Fatalf("unexpected nft args: %v", args)
		}
		return baseFirewallJSON(t, "", "dynamic-table"), nil
	}
	if err := verifyBootBaseFirewall("/usr/sbin/nft", testAgentConfig()); err == nil {
		t.Fatalf("verifyBootBaseFirewall accepted persisted dynamic table: %v", err)
	}
}

func TestVerifyLiveBaseFirewallAllowsSeparateDynamicTable(t *testing.T) {
	originalRunNFTOutput := runNFTOutput
	t.Cleanup(func() { runNFTOutput = originalRunNFTOutput })
	runNFTOutput = func(_ string, args ...string) ([]byte, error) {
		if strings.Join(args, " ") != "-j list ruleset" {
			t.Fatalf("unexpected nft args: %v", args)
		}
		return mergeNFTDocuments(t, baseFirewallJSON(t, ""), dynamicFirewallJSON(t, false)), nil
	}
	if err := verifyBaseFirewall("/usr/sbin/nft", testAgentConfig()); err != nil {
		t.Fatalf("live base verification rejected a separate Agent-owned dynamic table: %v", err)
	}
}

func TestFullRulesetVerifiersRejectUnallowlistedObjects(t *testing.T) {
	mutations := []map[string]any{
		{"table": map[string]any{"family": "ip", "name": "unrelated"}},
		{"table": map[string]any{"family": "inet", "name": "renamed_legacy"}},
		{"flowtable": map[string]any{"family": "inet", "table": nft.BaseTableName, "name": "bypass", "hook": "ingress"}},
		{"chain": map[string]any{"family": "inet", "table": nft.DynamicTableName, "name": "output_bypass", "type": "filter", "hook": "output", "prio": -200, "policy": "accept"}},
	}
	for index, mutation := range mutations {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			document := appendNFTEntry(t, mergeNFTDocuments(t, baseFirewallJSON(t, ""), dynamicFirewallJSON(t, false)), mutation)
			if err := verifyLiveFirewallDocument(document, testAgentConfig()); err == nil {
				t.Fatalf("live verifier accepted unallowlisted object %#v", mutation)
			}
			if err := verifyBootFirewallDocument(document, testAgentConfig()); err == nil {
				t.Fatalf("boot verifier accepted unallowlisted object %#v", mutation)
			}
		})
	}
}

func TestExpressionTokensRejectsVerdictWordsOutsideExactVerdictKeys(t *testing.T) {
	for _, raw := range []string{
		`{"log":{"prefix":"drop"}}`,
		`{"comment":"accept"}`,
		`{"immediate":{"right":"drop"}}`,
	} {
		if tokens, err := expressionTokens([]json.RawMessage{json.RawMessage(raw)}); err == nil {
			t.Fatalf("expressionTokens(%s) = %v, want rejection", raw, tokens)
		}
	}
}

func TestDynamicTableOwnershipNeverIncludesBase(t *testing.T) {
	t.Parallel()

	for _, table := range dynamicTables {
		if table.family == "inet" && table.name == "pgw_base" {
			t.Fatal("dynamic reconciliation owns pgw_base")
		}
	}
}

func TestReplaceDynamicRulesChecksAndAppliesOneAtomicTransaction(t *testing.T) {
	originalOutput, originalInput := runNFTOutput, runNFTInput
	t.Cleanup(func() { runNFTOutput, runNFTInput = originalOutput, originalInput })

	candidate, err := renderRules(testAgentConfig(), []types.MappingView{
		mappingForRenderTest("mapped", "192.168.2.101/32", "APPLIED", 15001),
	})
	if err != nil {
		t.Fatalf("render candidate: %v", err)
	}
	runNFTOutput = func(_ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "-j list tables":
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"pgw_base"}},{"table":{"family":"inet","name":"pgw_dynamic"}}]}`), nil
		case "-s list table inet pgw_dynamic":
			return []byte("table inet pgw_dynamic { }\n"), nil
		case "-j list table inet pgw_dynamic":
			return dynamicFirewallJSON(t, false), nil
		default:
			t.Fatalf("unexpected nft output call: %s", joined)
			return nil, nil
		}
	}
	type inputCall struct {
		args   []string
		script string
	}
	var calls []inputCall
	runNFTInput = func(_ string, args []string, script string) ([]byte, error) {
		calls = append(calls, inputCall{args: append([]string(nil), args...), script: script})
		return nil, nil
	}

	if err := replaceDynamicRules(testAgentConfig(), candidate); err != nil {
		t.Fatalf("replaceDynamicRules: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("nft input calls = %d, want check+apply", len(calls))
	}
	if strings.Join(calls[0].args, " ") != "-c -f -" || strings.Join(calls[1].args, " ") != "-f -" {
		t.Fatalf("unexpected nft calls: %+v", calls)
	}
	if calls[0].script != calls[1].script || !strings.Contains(calls[0].script, "delete table inet pgw_dynamic\nadd table inet pgw_dynamic") {
		t.Fatalf("candidate was not checked and applied as the same transaction:\n%s", calls[0].script)
	}
	if strings.Contains(calls[0].script, "delete table inet pgw_base") {
		t.Fatal("atomic dynamic transaction owns pgw_base")
	}
}

func TestApplyDynamicWithLKGReturnsVerifiedSemanticHash(t *testing.T) {
	originalOutput, originalInput := runNFTOutput, runNFTInput
	t.Cleanup(func() { runNFTOutput, runNFTInput = originalOutput, originalInput })
	candidate, err := renderRules(testAgentConfig(), []types.MappingView{
		mappingForRenderTest("mapped", "192.168.2.101/32", "APPLIED", 15001),
	})
	if err != nil {
		t.Fatal(err)
	}
	runNFTOutput = func(_ string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "-j list tables":
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"pgw_base"}}]}`), nil
		case "-j list table inet pgw_dynamic":
			return dynamicFirewallJSON(t, false), nil
		default:
			t.Fatalf("unexpected nft output call: %s", strings.Join(args, " "))
			return nil, nil
		}
	}
	var scripts []string
	runNFTInput = func(_ string, _ []string, script string) ([]byte, error) {
		scripts = append(scripts, script)
		return nil, nil
	}
	hash, rolledBack, err := applyDynamicWithLKG(testAgentConfig(), candidate, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 64 || rolledBack {
		t.Fatalf("hash length=%d rolledBack=%t", len(hash), rolledBack)
	}
	if len(scripts) != 2 || scripts[0] != scripts[1] {
		t.Fatalf("candidate check/apply scripts = %d", len(scripts))
	}
	if strings.Contains(scripts[0], "pgw_base") {
		t.Fatal("dynamic apply attempted to own base table")
	}
}

func TestVerifyDynamicFirewallRejectsGenericEstablishedAccept(t *testing.T) {
	originalOutput := runNFTOutput
	t.Cleanup(func() { runNFTOutput = originalOutput })
	runNFTOutput = func(string, ...string) ([]byte, error) { return dynamicFirewallJSON(t, true), nil }
	candidate, err := renderRules(testAgentConfig(), []types.MappingView{
		mappingForRenderTest("mapped", "192.168.2.101/32", "APPLIED", 15001),
	})
	if err != nil {
		t.Fatalf("render candidate: %v", err)
	}
	if err := verifyDynamicFirewall("nft", testAgentConfig(), candidate); err == nil {
		t.Fatal("verifyDynamicFirewall accepted a generic established allow")
	}
}

func TestDynamicCandidateValidatorRejectsUnknownOrMismatchedStatements(t *testing.T) {
	candidate, err := renderRules(testAgentConfig(), []types.MappingView{
		mappingForRenderTest("mapped", "192.168.2.101/32", "APPLIED", 15001),
	})
	if err != nil {
		t.Fatal(err)
	}
	allow := "add rule inet pgw_dynamic input_guard iifname \"lan0\" ip saddr 192.168.2.101/32 tcp dport 15001 counter name forwarder_input_accept_total accept\n"
	for name, mutation := range map[string]string{
		"unknown accept": candidate + "add rule inet pgw_dynamic input_guard accept\n",
		"base ownership": candidate + "delete table inet pgw_base\n",
		"missing allow":  strings.Replace(candidate, allow, "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateDynamicCandidateScript(mutation); err == nil {
				t.Fatal("unsafe candidate was accepted")
			}
		})
	}
}

func TestReplaceDynamicRulesRestoresLKGWhenReadBackFails(t *testing.T) {
	originalOutput, originalInput := runNFTOutput, runNFTInput
	t.Cleanup(func() { runNFTOutput, runNFTInput = originalOutput, originalInput })
	candidate, err := renderRules(testAgentConfig(), []types.MappingView{
		mappingForRenderTest("mapped", "192.168.2.101/32", "APPLIED", 15001),
	})
	if err != nil {
		t.Fatalf("render candidate: %v", err)
	}
	const lkg = "table inet pgw_dynamic { counter lkg_marker { packets 0 bytes 0 } }\n"
	runNFTOutput = func(_ string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "-j list tables":
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"pgw_dynamic"}}]}`), nil
		case "-s list table inet pgw_dynamic":
			return []byte(lkg), nil
		case "-j list table inet pgw_dynamic":
			return dynamicFirewallJSON(t, true), nil
		default:
			t.Fatalf("unexpected nft output call: %s", strings.Join(args, " "))
			return nil, nil
		}
	}
	var scripts []string
	runNFTInput = func(_ string, _ []string, script string) ([]byte, error) {
		scripts = append(scripts, script)
		return nil, nil
	}
	err = replaceDynamicRules(testAgentConfig(), candidate)
	if err == nil || !strings.Contains(err.Error(), "restored prior dynamic LKG") {
		t.Fatalf("replaceDynamicRules error = %v, want verified rollback", err)
	}
	if len(scripts) != 4 {
		t.Fatalf("nft transactions = %d, want candidate check/apply and rollback check/apply", len(scripts))
	}
	if scripts[2] != scripts[3] || !strings.Contains(scripts[2], "delete table inet pgw_dynamic\n"+lkg) {
		t.Fatalf("rollback did not restore captured LKG:\n%s", scripts[2])
	}
}

func TestNFTDataPlaneVerifyBaseCancelsHungCommand(t *testing.T) {
	original := runNFTOutputContext
	t.Cleanup(func() { runNFTOutputContext = original })
	runNFTOutputContext = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	config := testAgentConfig()
	config.NftTimeout = 20 * time.Millisecond
	started := time.Now()
	err := (nftDataPlane{config: config}).VerifyBase(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("VerifyBase error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("hung nft command was not bounded: %s", elapsed)
	}
}

func TestNFTDataPlaneApplyRollsBackAfterCommandTimeout(t *testing.T) {
	originalOutput, originalInput := runNFTOutputContext, runNFTInputContext
	t.Cleanup(func() { runNFTOutputContext, runNFTInputContext = originalOutput, originalInput })

	config := testAgentConfig()
	config.NftTimeout = 20 * time.Millisecond
	candidate, err := renderRules(config, []types.MappingView{
		mappingForRenderTest("mapped", "192.168.2.101/32", "APPLIED", 15001),
	})
	if err != nil {
		t.Fatal(err)
	}
	runNFTOutputContext = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "-j list tables":
			return []byte(`{"nftables":[]}`), nil
		case "-j list table inet pgw_dynamic":
			return dynamicFirewallJSON(t, false), nil
		default:
			t.Fatalf("unexpected nft output call: %s", strings.Join(args, " "))
			return nil, nil
		}
	}
	inputCalls := 0
	runNFTInputContext = func(ctx context.Context, _ string, _ []string, _ string) ([]byte, error) {
		inputCalls++
		if inputCalls == 2 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, nil
	}

	started := time.Now()
	_, rolledBack, err := (nftDataPlane{config: config}).Apply(context.Background(), candidate, candidate)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Apply error = %v, want deadline exceeded", err)
	}
	if !rolledBack {
		t.Fatal("Apply did not complete checked LKG rollback after command timeout")
	}
	if inputCalls != 4 {
		t.Fatalf("nft input calls = %d, want candidate check/apply and rollback check/apply", inputCalls)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("hung nft apply was not bounded: %s", elapsed)
	}
}

func baseFirewallJSON(t *testing.T, omittedObject string, mutations ...string) []byte {
	t.Helper()
	mutation := ""
	if len(mutations) > 0 {
		mutation = mutations[0]
	}
	entries := []map[string]any{
		{"table": map[string]string{"family": "inet", "name": nft.BaseTableName}},
	}
	for _, object := range nft.RequiredBaseObjects() {
		if object.Kind+":"+object.Name == omittedObject {
			continue
		}
		if object.Kind == "counter" {
			entries = append(entries, map[string]any{"counter": map[string]any{"family": "inet", "table": nft.BaseTableName, "name": object.Name, "packets": 0, "bytes": 0}})
		}
	}
	forwardHook := "forward"
	if mutation == "wrong-hook" {
		forwardHook = "input"
	}
	if omittedObject != "chain:forward_guard" {
		entries = append(entries, map[string]any{"chain": map[string]any{"family": "inet", "table": nft.BaseTableName, "name": "forward_guard", "type": "filter", "hook": forwardHook, "prio": -10, "policy": "accept"}})
	}
	if omittedObject != "chain:input_guard" {
		entries = append(entries, map[string]any{"chain": map[string]any{"family": "inet", "table": nft.BaseTableName, "name": "input_guard", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}})
	}
	if mutation == "extra-chain" {
		entries = append(entries, map[string]any{"chain": map[string]any{"family": "inet", "table": nft.BaseTableName, "name": "weakening", "type": "filter"}})
	}
	if mutation == "extra-counter" {
		entries = append(entries, map[string]any{"counter": map[string]any{"family": "inet", "table": nft.BaseTableName, "name": "unexpected"}})
	}
	if mutation == "extra-set" {
		entries = append(entries, map[string]any{"set": map[string]any{"family": "inet", "table": nft.BaseTableName, "name": "unexpected"}})
	}
	if mutation == "dynamic-table" {
		entries = append(entries, map[string]any{"table": map[string]any{"family": "inet", "name": nft.DynamicTableName}})
	}
	lan := "lan0"
	if mutation == "wrong-interface" {
		lan = "other0"
	}
	forwardRules := [][]any{
		{jMatchMeta("iifname", "wan0"), jMatchMeta("oifname", "lan0"), jMatchCTState(), jCounter("wan_lan_established_accept_total"), jVerdict("accept")},
		{jMatchMeta("iifname", lan), jMatchMeta("nfproto", "ipv6"), jCounter("ipv6_policy_drop_total"), jVerdict("drop")},
		{jMatchMeta("iifname", "lan0"), jMatchMeta("oifname", "wan0"), jMatchMeta("l4proto", "udp"), jCounter("udp_policy_drop_total"), jVerdict("drop")},
		{jMatchMeta("iifname", "lan0"), jMatchMeta("oifname", "wan0"), jCounter("lan_wan_direct_drop_total"), jVerdict("drop")},
	}
	if mutation == "wan-scoped-ipv6" {
		forwardRules[1] = []any{
			jMatchMeta("iifname", "lan0"), jMatchMeta("oifname", "wan0"), jMatchMeta("nfproto", "ipv6"),
			jCounter("ipv6_policy_drop_total"), jVerdict("drop"),
		}
	}
	if mutation == "remove-final-drop" {
		forwardRules = forwardRules[:3]
	} else if mutation == "accept-final" {
		forwardRules[3][len(forwardRules[3])-1] = jVerdict("accept")
	} else if mutation == "log-prefix-drop" {
		forwardRules[3][len(forwardRules[3])-1] = map[string]any{"log": map[string]string{"prefix": "drop"}}
	}
	for _, expressions := range forwardRules {
		entries = append(entries, jRule("forward_guard", expressions))
	}
	for _, expressions := range [][]any{
		{jMatchMeta("iifname", "lan0"), jMatchPayload("udp", "dport", 53), jCounter("dns_input_accept_total"), jVerdict("accept")},
		{jMatchMeta("iifname", "lan0"), jMatchPayload("tcp", "dport", 53), jCounter("dns_input_accept_total"), jVerdict("accept")},
		{jMatchMeta("nfproto", "ipv6"), jMatchPayload("tcp", "dport", map[string]any{"set": []int{8080, 8081}}), jCounter("management_input_drop_total"), jVerdict("drop")},
		{jMatchMeta("nfproto", "ipv4"), jMatchMeta("iifname", "lan0"), jMatchPayload("tcp", "dport", map[string]any{"set": []int{8080, 8081}}), jCounter("management_input_accept_total"), jVerdict("accept")},
		{jMatchMeta("nfproto", "ipv4"), jMatchMeta("iifname", "lo"), jMatchPayload("tcp", "dport", map[string]any{"set": []int{8080, 8081}}), jVerdict("accept")},
		{jMatchMeta("nfproto", "ipv4"), jMatchMetaOp("!=", "iifname", "lan0"), jMatchPayload("tcp", "dport", map[string]any{"set": []int{8080, 8081}}), jCounter("management_input_drop_total"), jVerdict("drop")},
	} {
		entries = append(entries, jRule("input_guard", expressions))
	}
	document, err := json.Marshal(map[string]any{"nftables": entries})
	if err != nil {
		t.Fatalf("marshal base firewall JSON: %v", err)
	}
	return document
}

func testAgentConfig() cfgAgent {
	return cfgAgent{LANIF: "lan0", WANIF: "wan0", FwdBase: 15001, FwdMax: 15999, ManagementPorts: []uint16{8080, 8081}}
}

func jRule(chain string, expressions []any) map[string]any {
	return map[string]any{"rule": map[string]any{"family": "inet", "table": nft.BaseTableName, "chain": chain, "expr": expressions}}
}

func jMatchMeta(key string, right any) map[string]any {
	return jMatchMetaOp("==", key, right)
}

func jMatchMetaOp(op, key string, right any) map[string]any {
	return map[string]any{"match": map[string]any{"op": op, "left": map[string]any{"meta": map[string]string{"key": key}}, "right": right}}
}

func jMatchCTState() map[string]any {
	return map[string]any{"match": map[string]any{"op": "in", "left": map[string]any{"ct": map[string]string{"key": "state"}}, "right": []string{"established", "related"}}}
}

func jMatchPayload(protocol, field string, right any) map[string]any {
	return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]string{"protocol": protocol, "field": field}}, "right": right}}
}

func jCounter(name string) map[string]any    { return map[string]any{"counter": name} }
func jVerdict(verdict string) map[string]any { return map[string]any{verdict: nil} }

func dynamicFirewallJSON(t *testing.T, established bool) []byte {
	t.Helper()
	entries := []map[string]any{
		{"table": map[string]any{"family": "inet", "name": nft.DynamicTableName}},
		{"counter": map[string]any{"family": "inet", "table": nft.DynamicTableName, "name": "web_redirect_total"}},
		{"counter": map[string]any{"family": "inet", "table": nft.DynamicTableName, "name": "forwarder_input_accept_total"}},
		{"counter": map[string]any{"family": "inet", "table": nft.DynamicTableName, "name": "forwarder_input_drop_total"}},
		{"chain": map[string]any{"family": "inet", "table": nft.DynamicTableName, "name": "prerouting", "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}},
		{"chain": map[string]any{"family": "inet", "table": nft.DynamicTableName, "name": "input_guard", "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}},
		{"rule": map[string]any{"family": "inet", "table": nft.DynamicTableName, "chain": "prerouting", "expr": []any{
			jMatchMeta("iifname", "lan0"),
			jMatchPayload("ip", "saddr", "192.168.2.101"),
			jMatchPayload("tcp", "dport", map[string]any{"set": []int{80, 443}}),
			jCounter("web_redirect_total"),
			map[string]any{"redirect": map[string]any{"port": 15001}},
		}}},
	}
	if established {
		entries = append(entries, map[string]any{"rule": map[string]any{"family": "inet", "table": nft.DynamicTableName, "chain": "input_guard", "expr": []any{jMatchCTState(), jVerdict("accept")}}})
	}
	entries = append(entries,
		map[string]any{"rule": map[string]any{"family": "inet", "table": nft.DynamicTableName, "chain": "input_guard", "expr": []any{
			jMatchMeta("iifname", "lan0"), jMatchPayload("ip", "saddr", "192.168.2.101"), jMatchPayload("tcp", "dport", 15001), jCounter("forwarder_input_accept_total"), jVerdict("accept"),
		}}},
		map[string]any{"rule": map[string]any{"family": "inet", "table": nft.DynamicTableName, "chain": "input_guard", "expr": []any{
			jMatchMeta("iifname", "lan0"), jMatchPayload("tcp", "dport", map[string]any{"range": []int{15001, 15999}}), jCounter("forwarder_input_drop_total"), jVerdict("drop"),
		}}},
	)
	document, err := json.Marshal(map[string]any{"nftables": entries})
	if err != nil {
		t.Fatalf("marshal dynamic firewall JSON: %v", err)
	}
	return document
}

func mergeNFTDocuments(t *testing.T, documents ...[]byte) []byte {
	t.Helper()
	merged := map[string]any{"nftables": []any{}}
	entries := []any{}
	for _, raw := range documents {
		var document map[string][]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, document["nftables"]...)
	}
	merged["nftables"] = entries
	encoded, err := json.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func appendNFTEntry(t *testing.T, raw []byte, entry map[string]any) []byte {
	t.Helper()
	var document map[string][]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["nftables"] = append(document["nftables"], entry)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mappingForRenderTest(id, cidr, state string, port int) types.MappingView {
	return types.MappingView{
		ID: id,
		Client: types.Client{
			ID:     "client-" + id,
			IPCidr: cidr,
		},
		State:             state,
		LocalRedirectPort: port,
	}
}
