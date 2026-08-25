// Package nft renders the legacy PGW nftables ruleset.
//
// The renderer is intentionally side-effect free. Applying, checking, and
// verifying a ruleset remain the agent's responsibility.
package nft

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

// RenderConfig contains the interface names used by the legacy ruleset.
type RenderConfig struct {
	LANInterface       string
	WANInterface       string
	ForwarderPortStart int
	ForwarderPortEnd   int
}

type rule struct {
	prefix string
	bits   int
	port   int
}

// RenderLegacy renders the current v1 web-only ruleset deterministically.
//
// This function is retained only as a characterization fixture and is not
// called by the production Agent. It does not implement the v2 base
// kill-switch or atomic generation/LKG contract; production fail-close policy
// is rendered by RenderBase.
func RenderLegacy(cfg RenderConfig, mappings []types.MappingView) string {
	seen := map[string]bool{}
	all := []rule{}
	for _, mapping := range mappings {
		state := strings.ToUpper(mapping.State)
		if state != "APPLIED" && state != "PENDING" {
			continue
		}
		prefix, bits, ok := parseIPv4Prefix(mapping.Client.IPCidr)
		if !ok || mapping.LocalRedirectPort <= 0 {
			continue
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
	for port, candidates := range grouped {
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].bits != candidates[j].bits {
				return candidates[i].bits < candidates[j].bits
			}
			return candidates[i].prefix < candidates[j].prefix
		})

		kept := []netip.Prefix{}
		for _, candidate := range candidates {
			prefix, _ := netip.ParsePrefix(candidate.prefix)
			covered := false
			for _, existing := range kept {
				if existing.Bits() <= prefix.Bits() && existing.Contains(prefix.Addr()) {
					covered = true
					break
				}
			}
			if !covered {
				kept = append(kept, prefix)
				pruned = append(pruned, rule{prefix: candidate.prefix, bits: candidate.bits, port: port})
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

	fmt.Fprintln(&ruleset, "add table ip pgw")
	fmt.Fprintln(&ruleset, "add chain ip pgw prerouting { type nat hook prerouting priority dstnat; policy accept; }")
	for _, candidate := range pruned {
		fmt.Fprintf(&ruleset, "add rule ip pgw prerouting iifname \"%s\" ip saddr %s tcp dport {80,443} redirect to :%d\n", cfg.LANInterface, candidate.prefix, candidate.port)
	}

	fmt.Fprintln(&ruleset, "add table inet pgw_filter")
	fmt.Fprintln(&ruleset, "add chain inet pgw_filter forward { type filter hook forward priority 0; policy accept; }")
	fmt.Fprintln(&ruleset, "add rule inet pgw_filter forward ct state established,related accept")
	fmt.Fprintf(&ruleset, "add rule inet pgw_filter forward iifname \"%s\" oifname \"%s\" meta nfproto ipv6 drop\n", cfg.LANInterface, cfg.WANInterface)
	for _, candidate := range pruned {
		fmt.Fprintf(&ruleset, "add rule inet pgw_filter forward ip saddr %s oifname \"%s\" drop\n", candidate.prefix, cfg.WANInterface)
		fmt.Fprintf(&ruleset, "add rule inet pgw_filter forward ip saddr %s meta l4proto udp drop\n", candidate.prefix)
	}
	fmt.Fprintln(&ruleset, "add chain inet pgw_filter input { type filter hook input priority 0; policy accept; }")
	fmt.Fprintln(&ruleset, "add rule inet pgw_filter input ct state established,related accept")
	for _, candidate := range pruned {
		fmt.Fprintf(&ruleset, "add rule inet pgw_filter input iifname \"%s\" ip saddr %s udp dport 53 accept\n", cfg.LANInterface, candidate.prefix)
		fmt.Fprintf(&ruleset, "add rule inet pgw_filter input iifname \"%s\" ip saddr %s tcp dport 53 accept\n", cfg.LANInterface, candidate.prefix)
		fmt.Fprintf(&ruleset, "add rule inet pgw_filter input iifname \"%s\" ip saddr %s tcp dport %d accept\n", cfg.LANInterface, candidate.prefix, candidate.port)
	}

	fmt.Fprintf(&ruleset, "add rule inet pgw_filter input iifname \"%s\" tcp dport 15001-15999 drop\n", cfg.LANInterface)

	return ruleset.String()
}

func parseIPv4Prefix(cidr string) (string, int, bool) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return "", 0, false
	}
	prefix = prefix.Masked()
	return prefix.String(), prefix.Bits(), true
}
