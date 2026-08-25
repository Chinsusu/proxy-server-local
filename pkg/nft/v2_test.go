package nft

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

func TestRenderBaseGoldenAndDeterministicManagementPorts(t *testing.T) {
	t.Parallel()

	want := readGolden(t, "testdata/base_default.golden.nft")
	got, err := RenderBase(BaseConfig{
		LANInterface:       "lan0",
		WANInterface:       "wan0",
		ManagementTCPPorts: []uint16{8081, 8080, 8081},
	})
	if err != nil {
		t.Fatalf("RenderBase: %v", err)
	}
	if got != want {
		t.Fatalf("base ruleset changed (-want +got):\n%s", lineDiff(want, got))
	}
}

func TestRenderBaseDropsLANIPv6OnEveryEgressAndHasNamedPolicyCounters(t *testing.T) {
	t.Parallel()

	got, err := RenderBase(BaseConfig{
		LANInterface:       "lan0",
		WANInterface:       "wan0",
		ManagementTCPPorts: DefaultManagementTCPPorts(),
	})
	if err != nil {
		t.Fatalf("RenderBase: %v", err)
	}
	for _, fragment := range []string{
		"iifname \"lan0\" meta nfproto ipv6 counter name ipv6_policy_drop_total drop",
		"iifname \"lan0\" oifname \"wan0\" meta l4proto udp counter name udp_policy_drop_total drop",
		"iifname \"lan0\" oifname \"wan0\" counter name lan_wan_direct_drop_total drop",
		"udp dport 53 counter name dns_input_accept_total accept",
		"meta nfproto ipv4 iifname \"lan0\" tcp dport { 8080, 8081 } counter name management_input_accept_total accept",
		"meta nfproto ipv4 iifname \"lo\" tcp dport { 8080, 8081 } accept",
		"meta nfproto ipv4 iifname != \"lan0\" tcp dport { 8080, 8081 } counter name management_input_drop_total drop",
		"meta nfproto ipv6 tcp dport { 8080, 8081 } counter name management_input_drop_total drop",
	} {
		if !strings.Contains(got, fragment) {
			t.Errorf("base ruleset missing %q", fragment)
		}
	}
	if strings.Contains(got, "iifname \"lan0\" oifname \"wan0\" meta nfproto ipv6") {
		t.Fatal("LAN IPv6 fail-close rule must not be scoped to the configured WAN")
	}
	ipv6Drop := strings.Index(got, "meta nfproto ipv6 tcp dport")
	firstManagementAccept := strings.Index(got, "counter name management_input_accept_total accept")
	if ipv6Drop < 0 || firstManagementAccept < 0 || ipv6Drop > firstManagementAccept {
		t.Fatal("IPv6 management drop must precede every management accept")
	}
	if strings.Contains(got, "ip saddr") {
		t.Fatal("base kill-switch must not depend on mapped source addresses")
	}
}

func TestRenderBaseRejectsUnsafeInterfaceConfiguration(t *testing.T) {
	t.Parallel()

	for _, cfg := range []BaseConfig{
		{LANInterface: `lan0\" drop`, WANInterface: "wan0"},
		{LANInterface: "lan0", WANInterface: "lan0"},
		{LANInterface: "", WANInterface: "wan0"},
	} {
		if _, err := RenderBase(cfg); err == nil {
			t.Fatalf("RenderBase(%+v) unexpectedly succeeded", cfg)
		}
	}
}

func TestRenderDynamicGolden(t *testing.T) {
	t.Parallel()

	want := readGolden(t, "testdata/dynamic_web_only.golden.nft")
	got, err := RenderDynamic(testRenderConfig(), legacyFixtureMappings())
	if err != nil {
		t.Fatalf("RenderDynamic: %v", err)
	}
	if got != want {
		t.Fatalf("dynamic ruleset changed (-want +got):\n%s", lineDiff(want, got))
	}
}

func TestRenderDynamicIsDeterministicAcrossInputOrder(t *testing.T) {
	t.Parallel()

	mappings := legacyFixtureMappings()
	want, err := RenderDynamic(testRenderConfig(), mappings)
	if err != nil {
		t.Fatalf("RenderDynamic: %v", err)
	}
	slices.Reverse(mappings)
	got, err := RenderDynamic(testRenderConfig(), mappings)
	if err != nil {
		t.Fatalf("RenderDynamic reversed: %v", err)
	}
	if got != want {
		t.Fatalf("input order changed dynamic ruleset (-want +got):\n%s", lineDiff(want, got))
	}
}

func TestRenderDynamicContainsNoBaseForwardingPolicy(t *testing.T) {
	t.Parallel()

	got, err := RenderDynamic(testRenderConfig(), legacyFixtureMappings())
	if err != nil {
		t.Fatalf("RenderDynamic: %v", err)
	}
	for _, forbidden := range []string{"pgw_base", "hook forward", "oifname \"wan0\"", "meta nfproto ipv6"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("dynamic renderer contains base-owned fragment %q", forbidden)
		}
	}
	for _, required := range []string{"tcp dport { 80, 443 }", "forwarder_input_accept_total", "forwarder_input_drop_total"} {
		if !strings.Contains(got, required) {
			t.Errorf("dynamic renderer missing %q", required)
		}
	}
}

func TestRenderDynamicDoesNotGrandfatherUnmappedEstablishedConnections(t *testing.T) {
	t.Parallel()

	got, err := RenderDynamic(testRenderConfig(), nil)
	if err != nil {
		t.Fatalf("RenderDynamic: %v", err)
	}
	if strings.Contains(got, "ct state established,related accept") {
		t.Fatal("generic established accept can grandfather an unauthorized forwarder connection")
	}
}

func TestRenderDynamicRejectsInvalidActiveMapping(t *testing.T) {
	t.Parallel()

	for _, mapping := range []types.MappingView{
		mappingView("invalid-cidr", "not-a-cidr", "APPLIED", 15001),
		mappingView("ipv6", "2001:db8::1/128", "PENDING", 15001),
		mappingView("zero-port", "192.0.2.1/32", "APPLIED", 0),
		mappingView("low-port", "192.0.2.1/32", "APPLIED", 15000),
		mappingView("above-protected-range", "192.0.2.1/32", "APPLIED", 16000),
		mappingView("high-port", "192.0.2.1/32", "APPLIED", 65536),
	} {
		if _, err := RenderDynamic(testRenderConfig(), []types.MappingView{mapping}); err == nil {
			t.Fatalf("invalid active mapping %+v unexpectedly rendered", mapping)
		}
	}
}

func TestRenderDynamicIgnoresInactiveMapping(t *testing.T) {
	t.Parallel()

	got, err := RenderDynamic(testRenderConfig(), []types.MappingView{
		mappingView("failed-invalid", "not-a-cidr", "FAILED", 70000),
	})
	if err != nil {
		t.Fatalf("inactive mapping affected candidate: %v", err)
	}
	want, err := RenderDynamic(testRenderConfig(), nil)
	if err != nil {
		t.Fatalf("empty candidate: %v", err)
	}
	if got != want {
		t.Fatalf("inactive mapping changed candidate (-want +got):\n%s", lineDiff(want, got))
	}
}

func readGolden(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	return strings.ReplaceAll(string(contents), "\r\n", "\n")
}
