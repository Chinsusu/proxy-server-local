package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Chinsusu/proxy-server-local/pkg/nft"
)

type nftDocument struct {
	NFTables []map[string]json.RawMessage `json:"nftables"`
}

type nftChainJSON struct {
	Family string          `json:"family"`
	Table  string          `json:"table"`
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Hook   string          `json:"hook"`
	Prio   json.RawMessage `json:"prio"`
	Policy string          `json:"policy"`
}

type nftRuleJSON struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Chain  string            `json:"chain"`
	Expr   []json.RawMessage `json:"expr"`
}

type nftSemanticState struct {
	tables   map[string]bool
	chains   map[string]nftChainJSON
	counters map[string]bool
	rules    map[string][][]string
	counts   map[string]int
	unsafe   []string
}

func verifyBaseFirewall(bin string, cfg cfgAgent) error {
	output, err := runNFTOutput(bin, "-j", "list", "ruleset")
	if err != nil {
		return fmt.Errorf("live nftables ruleset is unavailable: %w; output=%s", err, string(output))
	}
	return verifyLiveFirewallDocument(output, cfg)
}

func verifyBaseFirewallContext(ctx context.Context, bin string, cfg cfgAgent) error {
	output, err := runNFTOutputContext(ctx, bin, "-j", "list", "ruleset")
	if err != nil {
		return fmt.Errorf("live nftables ruleset is unavailable: %w; output=%s", err, string(output))
	}
	return verifyLiveFirewallDocument(output, cfg)
}

func verifyBaseFirewallDocument(output []byte, cfg cfgAgent) error {
	state, err := decodeNFTSemantics(output)
	if err != nil {
		return fmt.Errorf("parse required base firewall %s: %w", nft.BaseTableName, err)
	}
	return verifyBaseFirewallState(state, cfg)
}

func verifyBootBaseFirewall(bin string, cfg cfgAgent) error {
	output, err := runNFTOutput(bin, "-j", "list", "ruleset")
	if err != nil {
		return fmt.Errorf("list boot nftables ruleset: %w; output=%s", err, string(output))
	}
	return verifyBootFirewallDocument(output, cfg)
}

func verifyBootFirewallDocument(output []byte, cfg cfgAgent) error {
	state, err := decodeNFTSemantics(output)
	if err != nil {
		return fmt.Errorf("parse boot nftables ruleset: %w", err)
	}
	if err := verifyRulesetObjects(state, false); err != nil {
		return fmt.Errorf("boot ruleset allowlist: %w", err)
	}
	return verifyBaseFirewallState(state, cfg)
}

func verifyLiveFirewallDocument(output []byte, cfg cfgAgent) error {
	state, err := decodeNFTSemantics(output)
	if err != nil {
		return fmt.Errorf("parse live nftables ruleset: %w", err)
	}
	if err := verifyRulesetObjects(state, true); err != nil {
		return fmt.Errorf("live ruleset allowlist: %w", err)
	}
	if err := verifyBaseFirewallState(state, cfg); err != nil {
		return err
	}
	if state.tables["inet:"+nft.DynamicTableName] {
		if err := verifyGenericDynamicState(state, cfg); err != nil {
			return fmt.Errorf("live dynamic firewall mismatch: %w", err)
		}
	}
	return nil
}

func verifyRulesetObjects(state nftSemanticState, allowDynamic bool) error {
	allowedTables := map[string]bool{"inet:" + nft.BaseTableName: true}
	if allowDynamic {
		allowedTables["inet:"+nft.DynamicTableName] = true
	}
	if len(state.unsafe) != 0 {
		return fmt.Errorf("unsupported nftables objects: %s", strings.Join(state.unsafe, ","))
	}
	for table := range state.tables {
		if !allowedTables[table] {
			return fmt.Errorf("unexpected table %s", table)
		}
		if state.counts["table:"+table] != 1 {
			return fmt.Errorf("table %s occurs %d times", table, state.counts["table:"+table])
		}
	}
	if !state.tables["inet:"+nft.BaseTableName] {
		return fmt.Errorf("required table inet:%s is missing", nft.BaseTableName)
	}
	for key, count := range state.counts {
		if count != 1 && !strings.HasPrefix(key, "rule:") {
			return fmt.Errorf("object %s occurs %d times", key, count)
		}
	}
	for key := range state.chains {
		parts := strings.SplitN(key, ":", 3)
		if len(parts) != 3 || !allowedTables[parts[0]+":"+parts[1]] {
			return fmt.Errorf("chain outside allowed tables: %s", key)
		}
	}
	for key := range state.counters {
		parts := strings.SplitN(key, ":", 3)
		if len(parts) != 3 || !allowedTables[parts[0]+":"+parts[1]] {
			return fmt.Errorf("counter outside allowed tables: %s", key)
		}
	}
	for key := range state.rules {
		parts := strings.SplitN(key, ":", 3)
		if len(parts) != 3 || !allowedTables[parts[0]+":"+parts[1]] {
			return fmt.Errorf("rule outside allowed table or family: %s", key)
		}
		allowedChain := (parts[1] == nft.BaseTableName && (parts[2] == "forward_guard" || parts[2] == "input_guard")) ||
			(parts[1] == nft.DynamicTableName && (parts[2] == "prerouting" || parts[2] == "input_guard"))
		if !allowedChain {
			return fmt.Errorf("rule in unexpected chain: %s", key)
		}
	}
	return nil
}

func verifyGenericDynamicState(state nftSemanticState, cfg cfgAgent) error {
	tableKey := "inet:" + nft.DynamicTableName
	if state.counts["table:"+tableKey] != 1 {
		return fmt.Errorf("dynamic table occurs %d times", state.counts["table:"+tableKey])
	}
	wantedChains := map[string]bool{"prerouting": true, "input_guard": true}
	for name := range wantedChains {
		if _, ok := state.chains[tableKey+":"+name]; !ok {
			return fmt.Errorf("dynamic firewall is missing chain %s", name)
		}
	}
	for key := range state.chains {
		if strings.HasPrefix(key, tableKey+":") && !wantedChains[strings.TrimPrefix(key, tableKey+":")] {
			return fmt.Errorf("dynamic firewall contains extra chain %s", key)
		}
	}
	wantedCounters := map[string]bool{
		"web_redirect_total": true, "forwarder_input_accept_total": true, "forwarder_input_drop_total": true,
	}
	for name := range wantedCounters {
		if !state.counters[tableKey+":"+name] {
			return fmt.Errorf("dynamic firewall is missing counter %s", name)
		}
	}
	for key := range state.counters {
		if strings.HasPrefix(key, tableKey+":") && !wantedCounters[strings.TrimPrefix(key, tableKey+":")] {
			return fmt.Errorf("dynamic firewall contains extra counter %s", key)
		}
	}
	if err := verifyChain(state, nft.DynamicTableName, "prerouting", "nat", "prerouting", -100, "accept"); err != nil {
		return err
	}
	if err := verifyChain(state, nft.DynamicTableName, "input_guard", "filter", "input", 0, "accept"); err != nil {
		return err
	}
	redirects := map[string]bool{}
	for index, tokens := range state.rules[ruleKey(nft.DynamicTableName, "prerouting")] {
		if len(tokens) != 5 || tokens[0] != matchMeta("iifname", cfg.LANIF) ||
			tokens[2] != matchPayload("tcp", "dport", setToken(scalarToken(80), scalarToken(443))) ||
			tokens[3] != counterToken("web_redirect_total") || !strings.HasPrefix(tokens[1], "match:payload:ip:saddr:s:") ||
			!strings.HasPrefix(tokens[4], "redirect:n:") {
			return fmt.Errorf("dynamic prerouting rule %d is outside web-only contract", index)
		}
		address := strings.TrimPrefix(tokens[1], "match:payload:ip:saddr:s:")
		if !isCanonicalIPv4Source(address) {
			return fmt.Errorf("dynamic prerouting rule %d has invalid client prefix", index)
		}
		port, err := strconv.Atoi(strings.TrimPrefix(tokens[4], "redirect:n:"))
		if err != nil || port < cfg.FwdBase || port > cfg.FwdMax {
			return fmt.Errorf("dynamic prerouting rule %d has invalid redirect port", index)
		}
		key := address + "|" + strconv.Itoa(port)
		if redirects[key] {
			return fmt.Errorf("duplicate dynamic redirect %s", key)
		}
		redirects[key] = true
	}
	input := state.rules[ruleKey(nft.DynamicTableName, "input_guard")]
	if len(input) == 0 {
		return fmt.Errorf("dynamic input policy is missing terminal drop")
	}
	final := []string{
		matchMeta("iifname", cfg.LANIF), matchPayload("tcp", "dport", rangeToken(cfg.FwdBase, cfg.FwdMax)),
		counterToken("forwarder_input_drop_total"), "drop",
	}
	if !equalTokens(input[len(input)-1], final) {
		return fmt.Errorf("dynamic input policy terminal drop mismatch")
	}
	allows := map[string]bool{}
	for index, tokens := range input[:len(input)-1] {
		if len(tokens) != 5 || tokens[0] != matchMeta("iifname", cfg.LANIF) ||
			!strings.HasPrefix(tokens[1], "match:payload:ip:saddr:s:") ||
			!strings.HasPrefix(tokens[2], "match:payload:tcp:dport:n:") ||
			tokens[3] != counterToken("forwarder_input_accept_total") || tokens[4] != "accept" {
			return fmt.Errorf("dynamic input rule %d is outside forwarder allow contract", index)
		}
		address := strings.TrimPrefix(tokens[1], "match:payload:ip:saddr:s:")
		port, portErr := strconv.Atoi(strings.TrimPrefix(tokens[2], "match:payload:tcp:dport:n:"))
		if !isCanonicalIPv4Source(address) || portErr != nil || port < cfg.FwdBase || port > cfg.FwdMax {
			return fmt.Errorf("dynamic input rule %d has invalid client or port", index)
		}
		key := address + "|" + strconv.Itoa(port)
		if allows[key] {
			return fmt.Errorf("duplicate dynamic input allow %s", key)
		}
		allows[key] = true
	}
	if len(allows) != len(redirects) {
		return fmt.Errorf("dynamic redirect/allow cardinality mismatch")
	}
	for key := range redirects {
		if !allows[key] {
			return fmt.Errorf("dynamic redirect lacks exact input allow: %s", key)
		}
	}
	return nil
}

func isCanonicalIPv4Source(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Is4() && address.String() == value
	}
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix.Addr().Is4() && prefix == prefix.Masked()
}

func verifyBaseFirewallState(state nftSemanticState, cfg cfgAgent) error {
	baseTableKey := "inet:" + nft.BaseTableName
	if !state.tables[baseTableKey] || state.counts["table:"+baseTableKey] != 1 {
		return fmt.Errorf("required base firewall %s table object is missing", nft.BaseTableName)
	}
	if len(state.unsafe) != 0 {
		return fmt.Errorf("base firewall contains unsupported objects: %s", strings.Join(state.unsafe, ","))
	}
	wantedChains := map[string]bool{"forward_guard": true, "input_guard": true}
	wantedCounters := map[string]bool{}
	for _, object := range nft.RequiredBaseObjects() {
		key := "inet:" + nft.BaseTableName + ":" + object.Name
		switch object.Kind {
		case "chain":
			wantedChains[object.Name] = true
			if _, ok := state.chains[key]; !ok {
				return fmt.Errorf("required base firewall %s is missing chain %s", nft.BaseTableName, object.Name)
			}
		case "counter":
			wantedCounters[object.Name] = true
			if !state.counters[key] {
				return fmt.Errorf("required base firewall %s is missing counter %s", nft.BaseTableName, object.Name)
			}
		}
	}
	for key := range state.chains {
		if strings.HasPrefix(key, baseTableKey+":") && !wantedChains[strings.TrimPrefix(key, baseTableKey+":")] {
			return fmt.Errorf("base firewall contains extra chain %s", key)
		}
	}
	for key := range state.counters {
		if strings.HasPrefix(key, baseTableKey+":") && !wantedCounters[strings.TrimPrefix(key, baseTableKey+":")] {
			return fmt.Errorf("base firewall contains extra counter %s", key)
		}
	}
	if err := verifyChain(state, nft.BaseTableName, "forward_guard", "filter", "forward", -10, "accept"); err != nil {
		return err
	}
	if err := verifyChain(state, nft.BaseTableName, "input_guard", "filter", "input", -10, "accept"); err != nil {
		return err
	}

	managementPorts := append([]uint16(nil), cfg.ManagementPorts...)
	sort.Slice(managementPorts, func(i, j int) bool { return managementPorts[i] < managementPorts[j] })
	managementPorts = compactPorts(managementPorts)
	expectedForward := [][]string{
		{matchMeta("iifname", cfg.WANIF), matchMeta("oifname", cfg.LANIF), matchCTState(), counterToken("wan_lan_established_accept_total"), "accept"},
		{matchMeta("iifname", cfg.LANIF), matchMeta("nfproto", "ipv6"), counterToken("ipv6_policy_drop_total"), "drop"},
		{matchMeta("iifname", cfg.LANIF), matchMeta("oifname", cfg.WANIF), matchMeta("l4proto", "udp"), counterToken("udp_policy_drop_total"), "drop"},
		{matchMeta("iifname", cfg.LANIF), matchMeta("oifname", cfg.WANIF), counterToken("lan_wan_direct_drop_total"), "drop"},
	}
	expectedInput := [][]string{
		{matchMeta("iifname", cfg.LANIF), matchPayload("udp", "dport", scalarToken(53)), counterToken("dns_input_accept_total"), "accept"},
		{matchMeta("iifname", cfg.LANIF), matchPayload("tcp", "dport", scalarToken(53)), counterToken("dns_input_accept_total"), "accept"},
	}
	if len(managementPorts) > 0 {
		values := make([]string, 0, len(managementPorts))
		for _, port := range managementPorts {
			values = append(values, scalarToken(int(port)))
		}
		managementValue := setToken(values...)
		if len(values) == 1 {
			managementValue = values[0]
		}
		expectedInput = append(expectedInput,
			[]string{matchMeta("nfproto", "ipv6"), matchPayload("tcp", "dport", managementValue), counterToken("management_input_drop_total"), "drop"},
			[]string{matchMeta("nfproto", "ipv4"), matchMeta("iifname", cfg.LANIF), matchPayload("tcp", "dport", managementValue), counterToken("management_input_accept_total"), "accept"},
			[]string{matchMeta("nfproto", "ipv4"), matchMeta("iifname", "lo"), matchPayload("tcp", "dport", managementValue), "accept"},
			[]string{matchMeta("nfproto", "ipv4"), matchMetaNot("iifname", cfg.LANIF), matchPayload("tcp", "dport", managementValue), counterToken("management_input_drop_total"), "drop"},
		)
	}
	if err := requireExactRules(state, nft.BaseTableName, "forward_guard", expectedForward); err != nil {
		return fmt.Errorf("base forward policy mismatch: %w", err)
	}
	if err := requireExactRules(state, nft.BaseTableName, "input_guard", expectedInput); err != nil {
		return fmt.Errorf("base input policy mismatch: %w", err)
	}
	return nil
}

func verifyDynamicFirewall(bin string, cfg cfgAgent, candidate string) error {
	_, err := dynamicSemanticHash(bin, cfg, candidate)
	return err
}

func dynamicSemanticHash(bin string, cfg cfgAgent, candidate string) (string, error) {
	if err := validateDynamicCandidateScript(candidate); err != nil {
		return "", err
	}
	output, err := runNFTOutput(bin, "-j", "list", "table", "inet", nft.DynamicTableName)
	if err != nil {
		return "", fmt.Errorf("dynamic firewall %s is unavailable: %w; output=%s", nft.DynamicTableName, err, string(output))
	}
	return dynamicSemanticHashDocument(output, cfg, candidate)
}

func dynamicSemanticHashContext(ctx context.Context, bin string, cfg cfgAgent, candidate string) (string, error) {
	if err := validateDynamicCandidateScript(candidate); err != nil {
		return "", err
	}
	output, err := runNFTOutputContext(ctx, bin, "-j", "list", "table", "inet", nft.DynamicTableName)
	if err != nil {
		return "", fmt.Errorf("dynamic firewall %s is unavailable: %w; output=%s", nft.DynamicTableName, err, string(output))
	}
	return dynamicSemanticHashDocument(output, cfg, candidate)
}

func dynamicSemanticHashDocument(output []byte, cfg cfgAgent, candidate string) (string, error) {
	state, err := decodeNFTSemantics(output)
	if err != nil {
		return "", fmt.Errorf("parse dynamic firewall %s: %w", nft.DynamicTableName, err)
	}
	if !state.tables["inet:"+nft.DynamicTableName] {
		return "", fmt.Errorf("dynamic firewall %s table object is missing", nft.DynamicTableName)
	}
	for _, name := range []string{"web_redirect_total", "forwarder_input_accept_total", "forwarder_input_drop_total"} {
		if !state.counters["inet:"+nft.DynamicTableName+":"+name] {
			return "", fmt.Errorf("dynamic firewall is missing counter %s", name)
		}
	}
	if err := verifyChain(state, nft.DynamicTableName, "prerouting", "nat", "prerouting", -100, "accept"); err != nil {
		return "", err
	}
	if err := verifyChain(state, nft.DynamicTableName, "input_guard", "filter", "input", 0, "accept"); err != nil {
		return "", err
	}
	wantPrerouting, wantInput, err := expectedDynamicRules(candidate)
	if err != nil {
		return "", fmt.Errorf("derive dynamic read-back contract: %w", err)
	}
	if err := requireExactRules(state, nft.DynamicTableName, "prerouting", wantPrerouting); err != nil {
		return "", fmt.Errorf("dynamic redirect policy mismatch: %w", err)
	}
	if err := requireExactRules(state, nft.DynamicTableName, "input_guard", wantInput); err != nil {
		return "", fmt.Errorf("dynamic input policy mismatch: %w", err)
	}
	canonical := struct {
		Table      string     `json:"table"`
		Prerouting [][]string `json:"prerouting"`
		Input      [][]string `json:"input"`
	}{Table: "inet:" + nft.DynamicTableName, Prerouting: wantPrerouting, Input: wantInput}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("encode dynamic semantic state: %w", err)
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]), nil
}

var (
	dynamicRedirectPattern = regexp.MustCompile(`^add rule inet pgw_dynamic prerouting iifname "([^"]+)" ip saddr ([^ ]+) tcp dport \{ 80, 443 \} counter name web_redirect_total redirect to :([0-9]+)$`)
	dynamicAllowPattern    = regexp.MustCompile(`^add rule inet pgw_dynamic input_guard iifname "([^"]+)" ip saddr ([^ ]+) tcp dport ([0-9]+) counter name forwarder_input_accept_total accept$`)
	dynamicDropPattern     = regexp.MustCompile(`^add rule inet pgw_dynamic input_guard iifname "([^"]+)" tcp dport ([0-9]+)-([0-9]+) counter name forwarder_input_drop_total drop$`)
)

func expectedDynamicRules(candidate string) ([][]string, [][]string, error) {
	var redirects, input [][]string
	for _, line := range strings.Split(strings.TrimSpace(candidate), "\n") {
		switch {
		case dynamicRedirectPattern.MatchString(line):
			parts := dynamicRedirectPattern.FindStringSubmatch(line)
			address, err := canonicalNFTPrefix(parts[2])
			if err != nil {
				return nil, nil, err
			}
			port, _ := strconv.Atoi(parts[3])
			redirects = append(redirects, []string{
				matchMeta("iifname", parts[1]), matchPayload("ip", "saddr", "s:"+address),
				matchPayload("tcp", "dport", setToken(scalarToken(80), scalarToken(443))),
				counterToken("web_redirect_total"), "redirect:" + scalarToken(port),
			})
		case dynamicAllowPattern.MatchString(line):
			parts := dynamicAllowPattern.FindStringSubmatch(line)
			address, err := canonicalNFTPrefix(parts[2])
			if err != nil {
				return nil, nil, err
			}
			port, _ := strconv.Atoi(parts[3])
			input = append(input, []string{
				matchMeta("iifname", parts[1]), matchPayload("ip", "saddr", "s:"+address),
				matchPayload("tcp", "dport", scalarToken(port)), counterToken("forwarder_input_accept_total"), "accept",
			})
		case dynamicDropPattern.MatchString(line):
			parts := dynamicDropPattern.FindStringSubmatch(line)
			start, _ := strconv.Atoi(parts[2])
			end, _ := strconv.Atoi(parts[3])
			input = append(input, []string{
				matchMeta("iifname", parts[1]), matchPayload("tcp", "dport", rangeToken(start, end)),
				counterToken("forwarder_input_drop_total"), "drop",
			})
		case isFixedDynamicLine(line):
		default:
			return nil, nil, fmt.Errorf("unsupported dynamic nft statement %q", line)
		}
	}
	if len(input) == 0 || !containsAll(input[len(input)-1], counterToken("forwarder_input_drop_total"), "drop") {
		return nil, nil, fmt.Errorf("candidate is missing final protected-port drop")
	}
	return redirects, input, nil
}

func validateDynamicCandidateScript(candidate string) error {
	required := map[string]int{
		"add table inet pgw_dynamic":                                                                         1,
		"add counter inet pgw_dynamic web_redirect_total":                                                    1,
		"add counter inet pgw_dynamic forwarder_input_accept_total":                                          1,
		"add counter inet pgw_dynamic forwarder_input_drop_total":                                            1,
		"add chain inet pgw_dynamic prerouting { type nat hook prerouting priority dstnat; policy accept; }": 1,
		"add chain inet pgw_dynamic input_guard { type filter hook input priority 0; policy accept; }":       1,
	}
	seenFixed := map[string]int{}
	redirects := map[string]struct{}{}
	allows := map[string]struct{}{}
	drops := 0
	for _, raw := range strings.Split(strings.TrimSpace(candidate), "\n") {
		line := strings.TrimSpace(raw)
		if _, ok := required[line]; ok {
			seenFixed[line]++
			continue
		}
		switch {
		case dynamicRedirectPattern.MatchString(line):
			parts := dynamicRedirectPattern.FindStringSubmatch(line)
			redirects[strings.Join(parts[1:], "|")] = struct{}{}
		case dynamicAllowPattern.MatchString(line):
			parts := dynamicAllowPattern.FindStringSubmatch(line)
			allows[strings.Join(parts[1:], "|")] = struct{}{}
		case dynamicDropPattern.MatchString(line):
			drops++
		default:
			return fmt.Errorf("unsupported dynamic nft statement %q", line)
		}
	}
	for line, count := range required {
		if seenFixed[line] != count {
			return fmt.Errorf("dynamic nft fixed statement count for %q is %d, want %d", line, seenFixed[line], count)
		}
	}
	if drops != 1 {
		return fmt.Errorf("dynamic nft terminal input drop count is %d, want 1", drops)
	}
	if len(redirects) != len(allows) {
		return fmt.Errorf("dynamic nft redirect/allow cardinality mismatch")
	}
	for key := range redirects {
		if _, ok := allows[key]; !ok {
			return fmt.Errorf("dynamic nft redirect has no exact forwarder input allow")
		}
	}
	return nil
}

func isFixedDynamicLine(line string) bool {
	switch line {
	case "add table inet pgw_dynamic",
		"add counter inet pgw_dynamic web_redirect_total",
		"add counter inet pgw_dynamic forwarder_input_accept_total",
		"add counter inet pgw_dynamic forwarder_input_drop_total",
		"add chain inet pgw_dynamic prerouting { type nat hook prerouting priority dstnat; policy accept; }",
		"add chain inet pgw_dynamic input_guard { type filter hook input priority 0; policy accept; }":
		return true
	default:
		return false
	}
}

func canonicalNFTPrefix(value string) (string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", fmt.Errorf("invalid rendered prefix %q: %w", value, err)
	}
	prefix = prefix.Masked()
	if prefix.Bits() == 32 {
		return prefix.Addr().String(), nil
	}
	return prefix.String(), nil
}

func decodeNFTSemantics(output []byte) (nftSemanticState, error) {
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.UseNumber()
	var document nftDocument
	if err := decoder.Decode(&document); err != nil {
		return nftSemanticState{}, err
	}
	state := nftSemanticState{tables: map[string]bool{}, chains: map[string]nftChainJSON{}, counters: map[string]bool{}, rules: map[string][][]string{}, counts: map[string]int{}}
	for _, entry := range document.NFTables {
		for kind, raw := range entry {
			switch kind {
			case "metainfo":
				continue
			case "table":
				var object struct{ Family, Name string }
				if err := json.Unmarshal(raw, &object); err != nil || object.Family == "" || object.Name == "" {
					return state, fmt.Errorf("invalid table object")
				}
				key := object.Family + ":" + object.Name
				state.tables[key] = true
				state.counts["table:"+key]++
			case "chain":
				var chain nftChainJSON
				if err := json.Unmarshal(raw, &chain); err != nil || chain.Family == "" || chain.Table == "" || chain.Name == "" {
					return state, fmt.Errorf("invalid chain object")
				}
				key := chain.Family + ":" + chain.Table + ":" + chain.Name
				state.chains[key] = chain
				state.counts["chain:"+key]++
			case "counter":
				var object struct{ Family, Table, Name string }
				if err := json.Unmarshal(raw, &object); err != nil || object.Family == "" || object.Table == "" || object.Name == "" {
					return state, fmt.Errorf("invalid counter object")
				}
				key := object.Family + ":" + object.Table + ":" + object.Name
				state.counters[key] = true
				state.counts["counter:"+key]++
			case "rule":
				var rule nftRuleJSON
				if err := json.Unmarshal(raw, &rule); err != nil || rule.Family == "" || rule.Table == "" || rule.Chain == "" {
					return state, fmt.Errorf("invalid rule object")
				}
				tokens, err := expressionTokens(rule.Expr)
				if err != nil {
					return state, fmt.Errorf("decode %s rule: %w", rule.Chain, err)
				}
				key := ruleObjectKey(rule.Family, rule.Table, rule.Chain)
				state.rules[key] = append(state.rules[key], tokens)
				state.counts["rule:"+rule.Family+":"+rule.Table+":"+rule.Chain]++
			default:
				var object struct{ Family, Table, Name string }
				_ = json.Unmarshal(raw, &object)
				state.unsafe = append(state.unsafe, kind+":"+object.Family+":"+object.Table+":"+object.Name)
			}
		}
	}
	return state, nil
}

func expressionTokens(expressions []json.RawMessage) ([]string, error) {
	tokens := make([]string, 0, len(expressions))
	for _, raw := range expressions {
		var expression map[string]json.RawMessage
		if err := json.Unmarshal(raw, &expression); err != nil {
			return nil, err
		}
		if len(expression) != 1 {
			return nil, fmt.Errorf("expression must contain exactly one operation: %s", raw)
		}
		_, hasAccept := expression["accept"]
		_, hasDrop := expression["drop"]
		switch {
		case expression["match"] != nil:
			var match struct {
				Op    string          `json:"op"`
				Left  json.RawMessage `json:"left"`
				Right json.RawMessage `json:"right"`
			}
			if err := json.Unmarshal(expression["match"], &match); err != nil || (match.Op != "==" && match.Op != "in" && match.Op != "!=") {
				return nil, fmt.Errorf("unsupported match expression: %s", raw)
			}
			left, err := normalizeLeft(match.Left)
			if err != nil {
				return nil, err
			}
			right, err := normalizeValue(match.Right)
			if err != nil {
				return nil, err
			}
			prefix := "match:"
			if match.Op == "!=" {
				prefix = "match-not:"
			}
			tokens = append(tokens, prefix+left+":"+right)
		case expression["counter"] != nil:
			var counterName string
			if err := json.Unmarshal(expression["counter"], &counterName); err != nil {
				var counter struct {
					Name string `json:"name"`
				}
				if objectErr := json.Unmarshal(expression["counter"], &counter); objectErr != nil {
					return nil, fmt.Errorf("invalid counter expression: %s", raw)
				}
				counterName = counter.Name
			}
			if counterName == "" {
				return nil, fmt.Errorf("anonymous counter expression: %s", raw)
			}
			tokens = append(tokens, counterToken(counterName))
		case hasAccept:
			tokens = append(tokens, "accept")
		case hasDrop:
			tokens = append(tokens, "drop")
		case expression["redirect"] != nil:
			var redirect struct {
				Port json.Number `json:"port"`
			}
			if err := json.Unmarshal(expression["redirect"], &redirect); err != nil || redirect.Port.String() == "" {
				return nil, fmt.Errorf("invalid redirect expression: %s", raw)
			}
			tokens = append(tokens, "redirect:n:"+redirect.Port.String())
		default:
			return nil, fmt.Errorf("unsupported expression: %s", raw)
		}
	}
	return tokens, nil
}

func normalizeLeft(raw json.RawMessage) (string, error) {
	var left map[string]json.RawMessage
	if err := json.Unmarshal(raw, &left); err != nil {
		return "", err
	}
	for _, kind := range []string{"meta", "ct"} {
		if value := left[kind]; value != nil {
			var object struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal(value, &object); err != nil || object.Key == "" {
				return "", fmt.Errorf("invalid %s expression: %s", kind, raw)
			}
			return kind + ":" + object.Key, nil
		}
	}
	if value := left["payload"]; value != nil {
		var object struct{ Protocol, Field string }
		if err := json.Unmarshal(value, &object); err != nil || object.Protocol == "" || object.Field == "" {
			return "", fmt.Errorf("invalid payload expression: %s", raw)
		}
		return "payload:" + object.Protocol + ":" + object.Field, nil
	}
	return "", fmt.Errorf("unsupported match left side: %s", raw)
}

func normalizeValue(raw json.RawMessage) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	switch typed := value.(type) {
	case string:
		return "s:" + typed, nil
	case json.Number:
		return "n:" + typed.String(), nil
	case []any:
		return normalizeValues("set", typed)
	case map[string]any:
		for _, kind := range []string{"set", "range"} {
			if nested, ok := typed[kind].([]any); ok {
				return normalizeValues(kind, nested)
			}
		}
	}
	return "", fmt.Errorf("unsupported match value: %s", raw)
}

func normalizeValues(kind string, values []any) (string, error) {
	tokens := make([]string, 0, len(values))
	for _, value := range values {
		raw, _ := json.Marshal(value)
		token, err := normalizeValue(raw)
		if err != nil {
			return "", err
		}
		tokens = append(tokens, token)
	}
	if kind == "set" {
		sort.Strings(tokens)
	}
	if kind == "set" && len(tokens) == 1 {
		return tokens[0], nil
	}
	return kind + "[" + strings.Join(tokens, ",") + "]", nil
}

func verifyChain(state nftSemanticState, table, name, chainType, hook string, priority int, policy string) error {
	chain, ok := state.chains["inet:"+table+":"+name]
	if !ok {
		return fmt.Errorf("required chain %s is missing", name)
	}
	prio := strings.Trim(string(chain.Prio), `"`)
	if chain.Type != chainType || chain.Hook != hook || prio != strconv.Itoa(priority) || chain.Policy != policy {
		return fmt.Errorf("chain %s semantics mismatch: type=%q hook=%q priority=%q policy=%q", name, chain.Type, chain.Hook, prio, chain.Policy)
	}
	return nil
}

func requireExactRules(state nftSemanticState, table, chain string, want [][]string) error {
	got := state.rules[ruleKey(table, chain)]
	if len(got) != len(want) {
		return fmt.Errorf("chain %s has %d rules, want %d", chain, len(got), len(want))
	}
	for index := range want {
		if !equalTokens(got[index], want[index]) {
			return fmt.Errorf("chain %s rule %d mismatch: got=%v want=%v", chain, index, got[index], want[index])
		}
	}
	return nil
}

func ruleKey(table, chain string) string { return ruleObjectKey("inet", table, chain) }
func ruleObjectKey(family, table, chain string) string {
	return family + ":" + table + ":" + chain
}
func matchMeta(key, value string) string    { return "match:meta:" + key + ":s:" + value }
func matchMetaNot(key, value string) string { return "match-not:meta:" + key + ":s:" + value }
func matchPayload(protocol, field, value string) string {
	return "match:payload:" + protocol + ":" + field + ":" + value
}
func matchCTState() string            { return "match:ct:state:" + setToken("s:established", "s:related") }
func counterToken(name string) string { return "counter:" + name }
func scalarToken(value int) string    { return "n:" + strconv.Itoa(value) }
func setToken(values ...string) string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	return "set[" + strings.Join(values, ",") + "]"
}
func rangeToken(start, end int) string {
	return "range[" + scalarToken(start) + "," + scalarToken(end) + "]"
}

func equalTokens(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
func containsAll(tokens []string, wanted ...string) bool {
	for _, want := range wanted {
		found := false
		for _, token := range tokens {
			if token == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func compactPorts(ports []uint16) []uint16 {
	if len(ports) == 0 {
		return ports
	}
	result := ports[:1]
	for _, port := range ports[1:] {
		if port != result[len(result)-1] {
			result = append(result, port)
		}
	}
	return result
}
