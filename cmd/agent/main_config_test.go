package main

import "testing"

func TestLoadCfgRequiresExplicitValidLANAddress(t *testing.T) {
	t.Setenv("PGW_AGENT_ADDR", "127.0.0.1:9090")
	for _, value := range []string{"", "0.0.0.0", "127.0.0.1", "::1", "not-an-ip"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("PGW_LAN_ADDRESS", value)
			if _, err := loadCfg(); err == nil {
				t.Fatalf("loadCfg accepted PGW_LAN_ADDRESS=%q", value)
			}
		})
	}
}

func TestLoadCfgUsesExactExplicitLANAddress(t *testing.T) {
	t.Setenv("PGW_AGENT_ADDR", "127.0.0.1:9090")
	t.Setenv("PGW_LAN_ADDRESS", "192.168.2.1")
	cfg, err := loadCfg()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LANAddress != "192.168.2.1" {
		t.Fatalf("LANAddress=%q", cfg.LANAddress)
	}
}
