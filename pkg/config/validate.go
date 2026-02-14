package config

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ValidationResult holds the result of a single config check.
type ValidationResult struct {
	Component string
	Check     string
	OK        bool
	Message   string
}

// ValidateStartup runs all startup config validations and returns results.
// It checks network interfaces, nft binary, and port ranges.
func ValidateStartup() []ValidationResult {
	var results []ValidationResult

	// 1. Check WAN interface
	wanIF := getenv("PGW_WAN_IFACE", "eth0")
	if _, err := net.InterfaceByName(wanIF); err != nil {
		results = append(results, ValidationResult{
			Component: "network",
			Check:     "WAN interface",
			OK:        false,
			Message:   fmt.Sprintf("PGW_WAN_IFACE=%q not found: %v", wanIF, err),
		})
	} else {
		results = append(results, ValidationResult{
			Component: "network",
			Check:     "WAN interface",
			OK:        true,
			Message:   fmt.Sprintf("PGW_WAN_IFACE=%q exists", wanIF),
		})
	}

	// 2. Check LAN interface
	lanIF := getenv("PGW_LAN_IFACE", "ens19")
	if _, err := net.InterfaceByName(lanIF); err != nil {
		results = append(results, ValidationResult{
			Component: "network",
			Check:     "LAN interface",
			OK:        false,
			Message:   fmt.Sprintf("PGW_LAN_IFACE=%q not found: %v", lanIF, err),
		})
	} else {
		results = append(results, ValidationResult{
			Component: "network",
			Check:     "LAN interface",
			OK:        true,
			Message:   fmt.Sprintf("PGW_LAN_IFACE=%q exists", lanIF),
		})
	}

	// 3. Check nft binary
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		// also check /usr/sbin/nft directly
		if _, err2 := os.Stat("/usr/sbin/nft"); err2 != nil {
			results = append(results, ValidationResult{
				Component: "system",
				Check:     "nft binary",
				OK:        false,
				Message:   "nft binary not found in PATH or /usr/sbin/nft",
			})
		} else {
			results = append(results, ValidationResult{
				Component: "system",
				Check:     "nft binary",
				OK:        true,
				Message:   "nft found at /usr/sbin/nft",
			})
		}
	} else {
		results = append(results, ValidationResult{
			Component: "system",
			Check:     "nft binary",
			OK:        true,
			Message:   fmt.Sprintf("nft found at %s", nftPath),
		})
	}

	// 4. Check port range
	basePort := 15001
	maxPort := 15999
	if v := os.Getenv("PGW_FWD_BASE_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			basePort = n
		}
	}
	if v := os.Getenv("PGW_FWD_MAX_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxPort = n
		}
	}
	if basePort >= maxPort {
		results = append(results, ValidationResult{
			Component: "config",
			Check:     "port range",
			OK:        false,
			Message:   fmt.Sprintf("PGW_FWD_BASE_PORT(%d) >= PGW_FWD_MAX_PORT(%d)", basePort, maxPort),
		})
	} else {
		results = append(results, ValidationResult{
			Component: "config",
			Check:     "port range",
			OK:        true,
			Message:   fmt.Sprintf("forwarder port range %d-%d (%d ports)", basePort, maxPort, maxPort-basePort),
		})
	}

	// 5. Check data directory
	storePath := getenv("PGW_STORE_PATH", "/var/lib/pgw/state.json")
	dir := storePath
	if idx := strings.LastIndex(dir, "/"); idx >= 0 {
		dir = dir[:idx]
	}
	if info, err := os.Stat(dir); err != nil {
		results = append(results, ValidationResult{
			Component: "storage",
			Check:     "data directory",
			OK:        false,
			Message:   fmt.Sprintf("data directory %q does not exist: %v", dir, err),
		})
	} else if !info.IsDir() {
		results = append(results, ValidationResult{
			Component: "storage",
			Check:     "data directory",
			OK:        false,
			Message:   fmt.Sprintf("%q is not a directory", dir),
		})
	} else {
		results = append(results, ValidationResult{
			Component: "storage",
			Check:     "data directory",
			OK:        true,
			Message:   fmt.Sprintf("data directory %q exists", dir),
		})
	}

	return results
}
