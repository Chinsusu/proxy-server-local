package nft

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

const (
	BaseTableName             = "pgw_base"
	DynamicTableName          = "pgw_dynamic"
	DefaultForwarderPortStart = 15001
	DefaultForwarderPortEnd   = 15999
)

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

// BaseObject identifies an installer-owned nftables object required by the
// dynamic Agent safety precondition.
type BaseObject struct {
	Kind string
	Name string
}

var requiredBaseObjects = []BaseObject{
	{Kind: "chain", Name: "forward_guard"},
	{Kind: "chain", Name: "input_guard"},
	{Kind: "counter", Name: "wan_lan_established_accept_total"},
	{Kind: "counter", Name: "ipv6_policy_drop_total"},
	{Kind: "counter", Name: "udp_policy_drop_total"},
	{Kind: "counter", Name: "lan_wan_direct_drop_total"},
	{Kind: "counter", Name: "dns_input_accept_total"},
	{Kind: "counter", Name: "management_input_accept_total"},
	{Kind: "counter", Name: "management_input_drop_total"},
}

// BaseConfig defines the static, installer-owned fail-close firewall layer.
type BaseConfig struct {
	LANInterface       string
	WANInterface       string
	ManagementTCPPorts []uint16
}

// DefaultManagementTCPPorts returns only LAN-exposed management ports. The
// privileged Agent control listener is loopback-only and must never be opened
// through the LAN firewall.
func DefaultManagementTCPPorts() []uint16 {
	return []uint16{8080, 8081}
}

// RequiredBaseObjects returns a copy of the base firewall object contract.
func RequiredBaseObjects() []BaseObject {
	return slices.Clone(requiredBaseObjects)
}

// RenderBase renders the static base kill-switch. The Agent must never apply,
// flush, or delete this table during dynamic reconciliation.
func RenderBase(cfg BaseConfig) (string, error) {
	if err := validateInterfacePair(cfg.LANInterface, cfg.WANInterface); err != nil {
		return "", err
	}

	managementPorts := slices.Clone(cfg.ManagementTCPPorts)
	slices.Sort(managementPorts)
	managementPorts = slices.Compact(managementPorts)
	if len(managementPorts) > 0 && managementPorts[0] == 0 {
		return "", fmt.Errorf("management TCP port must be greater than zero")
	}

	var ruleset strings.Builder
	fmt.Fprintf(&ruleset, "add table inet %s\n", BaseTableName)
	for _, object := range requiredBaseObjects {
		if object.Kind == "counter" {
			fmt.Fprintf(&ruleset, "add counter inet %s %s\n", BaseTableName, object.Name)
		}
	}

	fmt.Fprintf(&ruleset, "add chain inet %s forward_guard { type filter hook forward priority -10; policy accept; }\n", BaseTableName)
	fmt.Fprintf(&ruleset, "add rule inet %s forward_guard iifname \"%s\" oifname \"%s\" ct state established,related counter name wan_lan_established_accept_total accept\n", BaseTableName, cfg.WANInterface, cfg.LANInterface)
	// IPv6 is unsupported by the proxy path, so fail closed for every packet
	// forwarded from the LAN. Do not constrain this rule to the configured WAN:
	// alternate routes or later-added egress interfaces must not bypass it.
	fmt.Fprintf(&ruleset, "add rule inet %s forward_guard iifname \"%s\" meta nfproto ipv6 counter name ipv6_policy_drop_total drop\n", BaseTableName, cfg.LANInterface)
	fmt.Fprintf(&ruleset, "add rule inet %s forward_guard iifname \"%s\" oifname \"%s\" meta l4proto udp counter name udp_policy_drop_total drop\n", BaseTableName, cfg.LANInterface, cfg.WANInterface)
	fmt.Fprintf(&ruleset, "add rule inet %s forward_guard iifname \"%s\" oifname \"%s\" counter name lan_wan_direct_drop_total drop\n", BaseTableName, cfg.LANInterface, cfg.WANInterface)

	fmt.Fprintf(&ruleset, "add chain inet %s input_guard { type filter hook input priority -10; policy accept; }\n", BaseTableName)
	fmt.Fprintf(&ruleset, "add rule inet %s input_guard iifname \"%s\" udp dport 53 counter name dns_input_accept_total accept\n", BaseTableName, cfg.LANInterface)
	fmt.Fprintf(&ruleset, "add rule inet %s input_guard iifname \"%s\" tcp dport 53 counter name dns_input_accept_total accept\n", BaseTableName, cfg.LANInterface)
	if len(managementPorts) > 0 {
		ports := make([]string, 0, len(managementPorts))
		for _, port := range managementPorts {
			ports = append(ports, fmt.Sprintf("%d", port))
		}
		// Keep the API/UI reachable only from the named management LAN and local
		// loopback. The explicit IPv4 and IPv6 drops are required even though the
		// UI binds its LAN address: a future bind regression must remain blocked
		// by the immutable base table. IPv6 is dropped before any management
		// accept, and every accept is explicitly constrained to IPv4.
		fmt.Fprintf(&ruleset, "add rule inet %s input_guard meta nfproto ipv6 tcp dport { %s } counter name management_input_drop_total drop\n", BaseTableName, strings.Join(ports, ", "))
		fmt.Fprintf(&ruleset, "add rule inet %s input_guard meta nfproto ipv4 iifname \"%s\" tcp dport { %s } counter name management_input_accept_total accept\n", BaseTableName, cfg.LANInterface, strings.Join(ports, ", "))
		fmt.Fprintf(&ruleset, "add rule inet %s input_guard meta nfproto ipv4 iifname \"lo\" tcp dport { %s } accept\n", BaseTableName, strings.Join(ports, ", "))
		fmt.Fprintf(&ruleset, "add rule inet %s input_guard meta nfproto ipv4 iifname != \"%s\" tcp dport { %s } counter name management_input_drop_total drop\n", BaseTableName, cfg.LANInterface, strings.Join(ports, ", "))
	}

	return ruleset.String(), nil
}

// RenderDynamic renders only mapping-owned web redirects and local forwarder
// input protection. It intentionally has no forwarding rules; fail-close
// forwarding belongs exclusively to pgw_base.
func RenderDynamic(cfg RenderConfig, mappings []types.MappingView) (string, error) {
	if err := validateInterfacePair(cfg.LANInterface, cfg.WANInterface); err != nil {
		return "", err
	}
	forwarderPortStart := cfg.ForwarderPortStart
	forwarderPortEnd := cfg.ForwarderPortEnd
	if forwarderPortStart == 0 && forwarderPortEnd == 0 {
		forwarderPortStart = DefaultForwarderPortStart
		forwarderPortEnd = DefaultForwarderPortEnd
	}
	if forwarderPortStart < 1 || forwarderPortEnd > 65535 || forwarderPortStart > forwarderPortEnd {
		return "", fmt.Errorf("invalid forwarder port range %d-%d", forwarderPortStart, forwarderPortEnd)
	}

	seen := map[string]bool{}
	all := []rule{}
	for _, mapping := range mappings {
		state := strings.ToUpper(mapping.State)
		if state != "APPLIED" && state != "PENDING" {
			continue
		}
		prefix, bits, ok := parseIPv4Prefix(mapping.Client.IPCidr)
		if !ok {
			return "", fmt.Errorf("mapping %q has invalid IPv4 CIDR %q", mapping.ID, mapping.Client.IPCidr)
		}
		if mapping.LocalRedirectPort < forwarderPortStart || mapping.LocalRedirectPort > forwarderPortEnd {
			return "", fmt.Errorf("mapping %q local redirect port %d is outside protected range %d-%d", mapping.ID, mapping.LocalRedirectPort, forwarderPortStart, forwarderPortEnd)
		}
		key := fmt.Sprintf("%s|%d", prefix, mapping.LocalRedirectPort)
		if !seen[key] {
			seen[key] = true
			all = append(all, rule{prefix: prefix, bits: bits, port: mapping.LocalRedirectPort})
		}
	}

	grouped := map[int][]rule{}
	for _, candidate := range all {
		grouped[candidate.port] = append(grouped[candidate.port], candidate)
	}

	pruned := []rule{}
	for _, candidates := range grouped {
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].bits != candidates[j].bits {
				return candidates[i].bits < candidates[j].bits
			}
			return candidates[i].prefix < candidates[j].prefix
		})
		kept := []string{}
		for _, candidate := range candidates {
			covered := false
			candidatePrefix, _ := netip.ParsePrefix(candidate.prefix)
			for _, existing := range kept {
				existingPrefix, _ := netip.ParsePrefix(existing)
				if existingPrefix.Bits() <= candidatePrefix.Bits() && existingPrefix.Contains(candidatePrefix.Addr()) {
					covered = true
					break
				}
			}
			if !covered {
				kept = append(kept, candidate.prefix)
				pruned = append(pruned, candidate)
			}
		}
	}

	sort.Slice(pruned, func(i, j int) bool {
		if pruned[i].port != pruned[j].port {
			return pruned[i].port < pruned[j].port
		}
		if pruned[i].bits != pruned[j].bits {
			return pruned[i].bits > pruned[j].bits
		}
		return pruned[i].prefix < pruned[j].prefix
	})

	var ruleset strings.Builder
	fmt.Fprintf(&ruleset, "add table inet %s\n", DynamicTableName)
	for _, counter := range []string{
		"web_redirect_total",
		"forwarder_input_accept_total",
		"forwarder_input_drop_total",
	} {
		fmt.Fprintf(&ruleset, "add counter inet %s %s\n", DynamicTableName, counter)
	}
	fmt.Fprintf(&ruleset, "add chain inet %s prerouting { type nat hook prerouting priority dstnat; policy accept; }\n", DynamicTableName)
	for _, candidate := range pruned {
		fmt.Fprintf(&ruleset, "add rule inet %s prerouting iifname \"%s\" ip saddr %s tcp dport { 80, 443 } counter name web_redirect_total redirect to :%d\n", DynamicTableName, cfg.LANInterface, candidate.prefix, candidate.port)
	}
	fmt.Fprintf(&ruleset, "add chain inet %s input_guard { type filter hook input priority 0; policy accept; }\n", DynamicTableName)
	for _, candidate := range pruned {
		fmt.Fprintf(&ruleset, "add rule inet %s input_guard iifname \"%s\" ip saddr %s tcp dport %d counter name forwarder_input_accept_total accept\n", DynamicTableName, cfg.LANInterface, candidate.prefix, candidate.port)
	}
	fmt.Fprintf(&ruleset, "add rule inet %s input_guard iifname \"%s\" tcp dport %d-%d counter name forwarder_input_drop_total drop\n", DynamicTableName, cfg.LANInterface, forwarderPortStart, forwarderPortEnd)

	return ruleset.String(), nil
}

func validateInterfacePair(lanInterface, wanInterface string) error {
	if !interfaceNamePattern.MatchString(lanInterface) {
		return fmt.Errorf("invalid LAN interface name %q", lanInterface)
	}
	if !interfaceNamePattern.MatchString(wanInterface) {
		return fmt.Errorf("invalid WAN interface name %q", wanInterface)
	}
	if lanInterface == wanInterface {
		return fmt.Errorf("LAN and WAN interfaces must differ")
	}
	return nil
}
