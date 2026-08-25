package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentcore "github.com/Chinsusu/proxy-server-local/internal/agent"
	"github.com/Chinsusu/proxy-server-local/pkg/config"
	"github.com/Chinsusu/proxy-server-local/pkg/nft"
	"github.com/Chinsusu/proxy-server-local/pkg/observability"
	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

type cfgAgent struct {
	APIBase          string
	LANIF            string
	WANIF            string
	FwdBase          int
	FwdMax           int
	ManagementPorts  []uint16
	Interval         time.Duration
	NftBinary        string
	NftTimeout       time.Duration
	SystemctlBinary  string
	Addr             string
	CredentialSocket string
	TokenFile        string
	RuntimeRoot      string
	LKGDirectory     string
	LANAddress       string
	ReadyTimeout     time.Duration
	DrainTimeout     time.Duration
}

func loadCfg() (cfgAgent, error) {
	ag := config.LoadAgent()
	if err := config.ValidatePrivateAgentAddr(ag.Addr); err != nil {
		return cfgAgent{}, err
	}
	interval := 15 * time.Second
	if v := os.Getenv("PGW_AGENT_RECONCILE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		}
	}
	// The URL is only a logical HTTP request target. The transport below is
	// unconditionally the protected Unix socket; internal Agent API traffic is
	// never sent to TCP, regardless of legacy PGW_API_BASE settings.
	apiBase := "http://pgw.internal"
	nftBinary := "/usr/sbin/nft"
	if _, err := os.Stat(nftBinary); err != nil {
		nftBinary = "nft"
	}
	managementPorts, managementPortsErr := parseManagementPorts(envString("PGW_MANAGEMENT_TCP_PORTS", "8080,8081"))
	if managementPortsErr != nil {
		managementPorts = []uint16{0}
	}
	credentialDirectory := os.Getenv("CREDENTIALS_DIRECTORY")
	tokenFile := strings.TrimSpace(os.Getenv("PGW_AGENT_TOKEN_FILE"))
	if tokenFile == "" && credentialDirectory != "" {
		tokenFile = filepath.Join(credentialDirectory, "agent_service_token")
	}
	if tokenFile == "" {
		tokenFile = "/run/pgw/agent_service_token"
	}
	lanAddress := strings.TrimSpace(os.Getenv("PGW_LAN_ADDRESS"))
	parsedLANAddress, lanAddressErr := netip.ParseAddr(lanAddress)
	if lanAddressErr != nil || !parsedLANAddress.Is4() || parsedLANAddress.IsUnspecified() || parsedLANAddress.IsLoopback() || parsedLANAddress.IsMulticast() {
		return cfgAgent{}, fmt.Errorf("PGW_LAN_ADDRESS must be a non-loopback unicast IPv4 address")
	}
	return cfgAgent{
		APIBase:          strings.TrimRight(apiBase, "/"),
		LANIF:            ag.LANIF,
		WANIF:            ag.WANIF,
		FwdBase:          envPort("PGW_FWD_BASE_PORT", nft.DefaultForwarderPortStart),
		FwdMax:           envPort("PGW_FWD_MAX_PORT", nft.DefaultForwarderPortEnd),
		ManagementPorts:  managementPorts,
		Interval:         interval,
		NftBinary:        nftBinary,
		NftTimeout:       envDuration("PGW_NFT_TIMEOUT", 5*time.Second),
		SystemctlBinary:  envString("PGW_SYSTEMCTL_BINARY", "systemctl"),
		Addr:             ag.Addr,
		CredentialSocket: envString("PGW_AGENT_SOCKET", "/run/pgw/api-agent.sock"),
		TokenFile:        tokenFile,
		RuntimeRoot:      envString("PGW_FORWARDER_RUNTIME_ROOT", "/run/pgw/forwarders"),
		LKGDirectory:     envString("PGW_LKG_DIRECTORY", "/var/lib/pgw/rules"),
		LANAddress:       parsedLANAddress.String(),
		ReadyTimeout:     envDuration("PGW_FWD_READY_TIMEOUT", 15*time.Second),
		DrainTimeout:     envDuration("PGW_FWD_DRAIN_TIMEOUT", 30*time.Second),
	}, nil
}

func main() {
	if handled, err := localCommand(os.Args[1:], os.Stdout); handled {
		if err != nil {
			observability.New("pgw-agent", os.Stderr).Logger.Log(context.Background(), "error", "agent_local_command_failed", map[string]any{"reason_code": "invalid_configuration"})
			os.Exit(2)
		}
		return
	}
	observer := observability.New("pgw-agent", os.Stdout)
	telemetry := agentcore.NewTelemetry(observer)

	cfg, err := loadCfg()
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "agent_startup_failed", map[string]any{"reason_code": "invalid_configuration"})
		os.Exit(1)
	}
	control, err := agentcore.NewHTTPControl(agentcore.HTTPControlConfig{
		APIBase: cfg.APIBase, CredentialSocket: cfg.CredentialSocket, TokenFile: cfg.TokenFile,
	})
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "agent_startup_failed", map[string]any{"reason_code": "control_initialization_failed"})
		os.Exit(1)
	}
	forwarders, err := agentcore.NewRuntimeManager(agentcore.RuntimeConfig{
		Root: cfg.RuntimeRoot, ListenHost: cfg.LANAddress, PortStart: cfg.FwdBase, PortEnd: cfg.FwdMax,
		ReadyTimeout: cfg.ReadyTimeout, Telemetry: telemetry,
	}, systemdCommander{binary: cfg.SystemctlBinary})
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "agent_startup_failed", map[string]any{"reason_code": "runtime_initialization_failed"})
		os.Exit(1)
	}
	reconciler, err := agentcore.NewReconciler(agentcore.Config{
		LANInterface: cfg.LANIF, WANInterface: cfg.WANIF,
		ForwarderPortStart: cfg.FwdBase, ForwarderPortEnd: cfg.FwdMax, DrainTimeout: cfg.DrainTimeout, Telemetry: telemetry,
	}, control, nftDataPlane{config: cfg, telemetry: telemetry}, forwarders, agentcore.FileLKGStore{Directory: cfg.LKGDirectory})
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "agent_startup_failed", map[string]any{"reason_code": "reconciler_initialization_failed"})
		os.Exit(1)
	}
	startupContext, cancelStartup := context.WithTimeout(context.Background(), 90*time.Second)
	if err := reconciler.StartupRecover(startupContext); err != nil {
		cancelStartup()
		observer.Logger.Log(context.Background(), "error", "agent_startup_failed", map[string]any{"reason_code": "startup_recovery_failed"})
		os.Exit(1)
	}
	cancelStartup()
	authorizer, err := agentcore.NewBearerAuthenticator(cfg.TokenFile)
	if err != nil {
		observer.Logger.Log(context.Background(), "error", "agent_startup_failed", map[string]any{"reason_code": "trigger_auth_initialization_failed"})
		os.Exit(1)
	}

	rootContext, cancelRoot := context.WithCancel(context.Background())
	defer cancelRoot()
	queue := agentcore.NewGenerationQueue(reconciler.Reconcile, func(generation int64, _ error) {
		observer.Logger.Log(context.Background(), "error", "reconcile_worker_failed", map[string]any{"generation": generation, "reason_code": "reconcile_failed"})
	}, telemetry)
	go queue.Run(rootContext)
	fetchLatest := func(ctx context.Context) error {
		snapshot, err := control.FetchLatest(ctx)
		if err != nil {
			return err
		}
		return queue.Enqueue(snapshot.Generation)
	}
	triggerGate := newReconcileTriggerGate(500*time.Millisecond, telemetry)
	go triggerGate.Run(rootContext, fetchLatest, func(_ error) {
		observer.Logger.Log(context.Background(), "error", "reconcile_trigger_failed", map[string]any{"reason_code": "snapshot_fetch_failed"})
	})
	mux := newAgentHandler(authorizer, triggerGate, telemetry)

	go func() {
		t := time.NewTicker(cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-rootContext.Done():
				return
			case <-t.C:
				triggerGate.Force()
			}
		}
	}()
	triggerGate.Force()

	observer.Logger.Log(context.Background(), "info", "agent_listening", map[string]any{"state": "ready"})

	server := &http.Server{Addr: cfg.Addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: maxAgentHeaderBytes}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh
		observer.Logger.Log(context.Background(), "info", "agent_shutdown_started", map[string]any{"reason_code": "signal", "state": sig.String()})
		cancelRoot()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			observer.Logger.Log(context.Background(), "error", "agent_shutdown_failed", map[string]any{"reason_code": "http_shutdown_failed"})
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		observer.Logger.Log(context.Background(), "error", "agent_listener_failed", map[string]any{"reason_code": "http_listener_failed"})
		os.Exit(1)
	}
}

func localCommand(args []string, output io.Writer) (bool, error) {
	if handled, err := renderBaseCommand(args, output); handled {
		return true, err
	}
	if len(args) == 0 || (args[0] != "verify-base" && args[0] != "verify-boot-base") {
		return false, nil
	}
	if len(args) != 1 {
		return true, fmt.Errorf("%s accepts no arguments", args[0])
	}
	ag := config.LoadAgent()
	managementPorts, err := parseManagementPorts(envString("PGW_MANAGEMENT_TCP_PORTS", "8080,8081"))
	if err != nil {
		return true, err
	}
	cfg := cfgAgent{LANIF: ag.LANIF, WANIF: ag.WANIF, ManagementPorts: managementPorts}
	verify := verifyBaseFirewall
	message := "verified exact fail-close nftables base table"
	if args[0] == "verify-boot-base" {
		verify = verifyBootBaseFirewall
		message = "verified exact fail-close boot nftables ruleset"
	}
	if err := verify("/usr/sbin/nft", cfg); err != nil {
		return true, err
	}
	_, err = fmt.Fprintln(output, message)
	return true, err
}

type nftTable struct {
	family string
	name   string
}

var dynamicTables = []nftTable{
	{family: "ip", name: "pgw"},          // v1 legacy NAT table
	{family: "inet", name: "pgw_filter"}, // v1 legacy filter table
	{family: "inet", name: nft.DynamicTableName},
}

var runNFTOutput = func(bin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return runNFTOutputContext(ctx, bin, args...)
}

var runNFTInput = func(bin string, args []string, script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return runNFTInputContext(ctx, bin, args, script)
}

var runNFTOutputContext = func(ctx context.Context, bin string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, bin, args...).CombinedOutput()
}

var runNFTInputContext = func(ctx context.Context, bin string, args []string, script string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(script)
	return cmd.CombinedOutput()
}

// renderRules delegates to the side-effect-free dynamic renderer. Base
// isolation is a separate installer-owned lifecycle and is never rendered here.
func renderRules(cfg cfgAgent, mvs []types.MappingView) (string, error) {
	return nft.RenderDynamic(nft.RenderConfig{
		LANInterface:       cfg.LANIF,
		WANInterface:       cfg.WANIF,
		ForwarderPortStart: cfg.FwdBase,
		ForwarderPortEnd:   cfg.FwdMax,
	}, mvs)
}

func envPort(name string, defaultValue int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	port, err := strconv.Atoi(value)
	if err != nil {
		return -1
	}
	return port
}

func envString(name, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	return value
}

func envDuration(name string, defaultValue time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return -1
	}
	return duration
}

func renderBaseCommand(args []string, output io.Writer) (bool, error) {
	if len(args) == 0 || args[0] != "render-base" {
		return false, nil
	}
	flags := flag.NewFlagSet("render-base", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	lanInterface := flags.String("lan", "", "LAN interface")
	wanInterface := flags.String("wan", "", "WAN interface")
	managementPortsValue := flags.String("management-ports", "8080,8081", "comma-separated management TCP ports")
	if err := flags.Parse(args[1:]); err != nil {
		return true, err
	}
	if flags.NArg() != 0 {
		return true, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	managementPorts, err := parseManagementPorts(*managementPortsValue)
	if err != nil {
		return true, err
	}
	ruleset, err := nft.RenderBase(nft.BaseConfig{
		LANInterface:       *lanInterface,
		WANInterface:       *wanInterface,
		ManagementTCPPorts: managementPorts,
	})
	if err != nil {
		return true, err
	}
	_, err = io.WriteString(output, ruleset)
	return true, err
}

func parseManagementPorts(value string) ([]uint16, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	ports := make([]uint16, 0, len(parts))
	for _, part := range parts {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid management TCP port %q", part)
		}
		if port == 9090 {
			return nil, fmt.Errorf("management TCP port 9090 is reserved for loopback-only Agent control")
		}
		ports = append(ports, uint16(port))
	}
	return ports, nil
}
