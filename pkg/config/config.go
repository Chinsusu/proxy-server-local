
package config

import (
	"fmt"
	"log"
	"os"
	"time"
)

const defaultJWTSecret = "dev-change-me"
const minJWTSecretLen = 32

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" { return v }
	return def
}

type API struct { Addr, JWTSecret string }
type UI struct { Addr, JWTSecret string }
type Health struct { Interval time.Duration }
type Agent struct { Addr, WANIF, LANIF string }
type Fwd struct { Addr string }

func LoadAPI() API {
	return API{ Addr: getenv("PGW_API_ADDR", ":8080"), JWTSecret: getenv("PGW_JWT_SECRET", defaultJWTSecret) }
}
func LoadUI() UI { return UI{ Addr: getenv("PGW_UI_ADDR", ":8081"), JWTSecret: getenv("PGW_JWT_SECRET", defaultJWTSecret) } }
func LoadHealth() Health {
	iv := getenv("PGW_HEALTH_INTERVAL", "30s")
	d, _ := time.ParseDuration(iv); if d == 0 { d = 30 * time.Second }
	return Health{ Interval: d }
}
func LoadAgent() Agent {
	return Agent{ Addr: getenv("PGW_AGENT_ADDR", ":9090"), WANIF: getenv("PGW_WAN_IFACE","eth0"), LANIF: getenv("PGW_LAN_IFACE","ens19") }
}
func LoadFwd() Fwd { return Fwd{ Addr: getenv("PGW_FWD_ADDR", ":15000") } }

// ValidateJWTSecret checks that the JWT secret is not the insecure default
// and meets minimum length requirements. Returns an error describing the issue,
// or nil if valid. When PGW_JWT_STRICT is not "false", this will log.Fatal on failure.
func ValidateJWTSecret(secret string) error {
	strict := getenv("PGW_JWT_STRICT", "true") != "false"

	if secret == defaultJWTSecret {
		msg := fmt.Sprintf("JWT secret is the insecure default (%q). Set PGW_JWT_SECRET to a random string of at least %d characters", defaultJWTSecret, minJWTSecretLen)
		if strict {
			log.Fatalf("[FATAL] %s", msg)
		}
		log.Printf("[WARNING] %s (ignored because PGW_JWT_STRICT=false)", msg)
		return fmt.Errorf(msg)
	}

	if len(secret) < minJWTSecretLen {
		msg := fmt.Sprintf("JWT secret is too short (%d chars). Minimum is %d characters", len(secret), minJWTSecretLen)
		if strict {
			log.Fatalf("[FATAL] %s", msg)
		}
		log.Printf("[WARNING] %s (ignored because PGW_JWT_STRICT=false)", msg)
		return fmt.Errorf(msg)
	}

	return nil
}
