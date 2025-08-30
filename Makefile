SHELL := /bin/bash
export PATH := /usr/local/go/bin:/snap/bin:$(PATH)


BIN_DIR=bin
CMDS=api ui agent health fwd

build: $(CMDS)

$(CMDS):
	@echo "Building $@"
	@go build -o $(BIN_DIR)/pgw-$@ ./cmd/$@

run-api:
	PGW_API_ADDR=:8080 go run ./cmd/api

run-ui:
	PGW_UI_ADDR=:8081 go run ./cmd/ui

run-health:
	PGW_HEALTH_INTERVAL=30s go run ./cmd/health

run-agent:
	PGW_AGENT_ADDR=:9090 PGW_WAN_IFACE=eth0 PGW_LAN_IFACE=ens19 go run ./cmd/agent

run-fwd:
	PGW_FWD_ADDR=:15000 go run ./cmd/fwd
