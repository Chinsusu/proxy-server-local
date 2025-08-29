
package config

import (
	"os"
	"time"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" { return v }
	return def
}

type API struct { Addr, JWTSecret string }
type UI struct { Addr string }
type Health struct { Interval time.Duration }
type Agent struct { Addr, WANIF, LANIF string }
type Fwd struct { Addr string }

func LoadAPI() API {
	return API{ Addr: getenv("PGW_API_ADDR", ":8080"), JWTSecret: getenv("PGW_JWT_SECRET", "dev-change-me") }
}
func LoadUI() UI { return UI{ Addr: getenv("PGW_UI_ADDR", ":8443") } }
func LoadHealth() Health {
	iv := getenv("PGW_HEALTH_INTERVAL", "30s")
	d, _ := time.ParseDuration(iv); if d == 0 { d = 30 * time.Second }
	return Health{ Interval: d }
}
func LoadAgent() Agent {
	return Agent{ Addr: getenv("PGW_AGENT_ADDR", ":9090"), WANIF: getenv("PGW_WAN_IFACE","eth0"), LANIF: getenv("PGW_LAN_IFACE","ens19") }
}
func LoadFwd() Fwd { return Fwd{ Addr: getenv("PGW_FWD_ADDR", ":15000") } }
