package nft

import (
	"crypto/sha256"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

func TestRenderLegacyGolden(t *testing.T) {
	t.Parallel()

	wantBytes, err := os.ReadFile("testdata/legacy_web_only.golden.nft")
	if err != nil {
		t.Fatalf("read golden ruleset: %v", err)
	}
	want := strings.ReplaceAll(string(wantBytes), "\r\n", "\n")

	got := RenderLegacy(testRenderConfig(), legacyFixtureMappings())
	if got != want {
		t.Fatalf("legacy ruleset changed (-want +got):\n%s", lineDiff(want, got))
	}

	const wantSHA256 = "c0f7c9cbe9e3daa0dc32f57c69d9e4ef7a057b3b9f7a171fba4f7896a1d9980d"
	gotSHA256 := fmt.Sprintf("%x", sha256.Sum256([]byte(got)))
	if gotSHA256 != wantSHA256 {
		t.Fatalf("legacy ruleset hash changed: got %s, want %s", gotSHA256, wantSHA256)
	}
}

func TestRenderLegacyIsDeterministicAcrossInputOrder(t *testing.T) {
	t.Parallel()

	mappings := legacyFixtureMappings()
	want := RenderLegacy(testRenderConfig(), mappings)

	slices.Reverse(mappings)
	got := RenderLegacy(testRenderConfig(), mappings)
	if got != want {
		t.Fatalf("input order changed rendered ruleset (-want +got):\n%s", lineDiff(want, got))
	}
}

func TestRenderLegacyOmitsUnsupportedMappings(t *testing.T) {
	t.Parallel()

	mappings := []types.MappingView{
		mappingView("failed", "192.0.2.10/32", "FAILED", 15001),
		mappingView("active-v2", "192.0.2.11/32", "ACTIVE", 15001),
		mappingView("invalid-cidr", "not-a-cidr", "APPLIED", 15001),
		mappingView("ipv6", "2001:db8::10/128", "APPLIED", 15001),
		mappingView("zero-port", "192.0.2.12/32", "PENDING", 0),
		mappingView("negative-port", "192.0.2.13/32", "PENDING", -1),
	}

	got := RenderLegacy(testRenderConfig(), mappings)
	want := RenderLegacy(testRenderConfig(), nil)
	if got != want {
		t.Fatalf("unsupported mappings affected legacy ruleset (-want +got):\n%s", lineDiff(want, got))
	}
}

func TestRenderLegacyWebOnlyDenyRules(t *testing.T) {
	t.Parallel()

	got := RenderLegacy(testRenderConfig(), legacyFixtureMappings())
	required := []string{
		"tcp dport {80,443} redirect",
		"meta nfproto ipv6 drop",
		"ip saddr 192.168.2.101/32 oifname \"wan0\" drop",
		"ip saddr 192.168.2.101/32 meta l4proto udp drop",
	}
	for _, fragment := range required {
		if !strings.Contains(got, fragment) {
			t.Errorf("legacy ruleset missing %q", fragment)
		}
	}

	if strings.Contains(got, "tcp dport 8443 redirect") {
		t.Fatal("legacy web-only ruleset unexpectedly redirects TCP 8443")
	}
}

func TestRenderLegacyCharacterizesMissingBaseIPv4KillSwitch(t *testing.T) {
	t.Parallel()

	got := RenderLegacy(testRenderConfig(), nil)
	if !strings.Contains(got, "policy accept") {
		t.Fatal("legacy empty ruleset no longer uses accept-policy chains")
	}
	if strings.Contains(got, "ip saddr") {
		t.Fatal("legacy empty ruleset unexpectedly contains a managed-client IPv4 rule")
	}
}

func TestRenderLegacyCharacterizesMissingUpperPortValidation(t *testing.T) {
	t.Parallel()

	got := RenderLegacy(testRenderConfig(), []types.MappingView{
		mappingView("out-of-range-port", "192.0.2.20/32", "APPLIED", 65536),
	})
	if !strings.Contains(got, "redirect to :65536") {
		t.Fatal("legacy renderer no longer emits an out-of-range positive port")
	}
}

func legacyFixtureMappings() []types.MappingView {
	return []types.MappingView{
		mappingView("client-130", "192.168.2.130/32", "APPLIED", 15002),
		mappingView("client-101", "192.168.2.101/32", "applied", 15001),
		mappingView("subnet", "192.168.2.128/25", "PENDING", 15002),
		mappingView("duplicate-subnet", "192.168.2.128/25", "APPLIED", 15002),
	}
}

func mappingView(id, cidr, state string, port int) types.MappingView {
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

func testRenderConfig() RenderConfig {
	return RenderConfig{
		LANInterface: "lan0",
		WANInterface: "wan0",
	}
}

func lineDiff(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")
	maxLines := len(wantLines)
	if len(gotLines) > maxLines {
		maxLines = len(gotLines)
	}

	var diff strings.Builder
	for i := 0; i < maxLines; i++ {
		var wantLine, gotLine string
		if i < len(wantLines) {
			wantLine = wantLines[i]
		}
		if i < len(gotLines) {
			gotLine = gotLines[i]
		}
		if wantLine == gotLine {
			continue
		}
		fmt.Fprintf(&diff, "line %d:\n-want %s\n+got  %s\n", i+1, wantLine, gotLine)
	}
	return diff.String()
}
