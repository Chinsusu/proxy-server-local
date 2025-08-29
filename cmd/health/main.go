
package main

import (
	"time"
	"os"
	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"github.com/Chinsusu/proxy-server-local/pkg/logging"
)

func main() {
	cfg := config.LoadHealth()
	logging.Info.Printf("pgw-health starting, interval=%s\n", cfg.Interval)
	for {
		logging.Info.Println("health tick (skeleton) — implement real checker per TECHNICAL_DESIGN")
		time.Sleep(cfg.Interval)
	}
}
