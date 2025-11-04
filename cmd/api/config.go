package main

import (
	"os"
	"strconv"
)

// getEnvBool reads a boolean environment variable with a default value
func getEnvBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// EnforceHealth determines whether /v1/mappings/active filters by proxy health.
// Default false: traffic stays always-on, only health telemetry updates.
var EnforceHealth = getEnvBool("PGW_ENFORCE_HEALTH", false)
