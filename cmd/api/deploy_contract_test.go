package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readDeploymentFile(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func TestAdminHashCredentialIsAPIOnly(t *testing.T) {
	apiUnit := readDeploymentFile(t, "systemd/pgw-api.service")
	if !strings.Contains(apiUnit, "LoadCredential=admin_pass_hash:/etc/pgw/admin_pass_hash") {
		t.Fatal("API unit does not load the dedicated admin password hash credential")
	}
	for _, unit := range []string{"systemd/pgw-agent.service", "systemd/pgw-fwd@.service", "systemd/pgw-ui.service"} {
		if strings.Contains(readDeploymentFile(t, unit), "admin_pass_hash") {
			t.Fatalf("%s must not receive the API-only admin password hash credential", unit)
		}
	}
	installer := readDeploymentFile(t, "install-pgw.sh")
	if strings.Contains(installer, "PGW_ADMIN_PASS=") || strings.Contains(installer, "PGW_ADMIN_PASS_HASH=") {
		t.Fatal("installer persists a legacy plaintext or hash environment variable")
	}
	if strings.Contains(installer, "< \"$password_file\"") || strings.Contains(installer, "stat -c '%u:%a' -- \"$password_file\"") {
		t.Fatal("installer must not inspect or open the password file before pgw-api securely opens it")
	}
	if !strings.Contains(installer, "PGW_ADMIN_PASS_FILE") {
		t.Fatal("installer must explicitly reject the legacy caller-selected admin password environment")
	}
	for _, required := range []string{"password_file=/etc/pgw/credential-inbox/admin_password", "hash-admin-password --file \"${password_file}\"", "/etc/pgw/admin_pass_hash"} {
		if !strings.Contains(installer, required) {
			t.Fatalf("installer is missing secure admin bootstrap contract %q", required)
		}
	}
}

func TestInstallerKeepsAgentAndFirewallPortPrivate(t *testing.T) {
	installer := readDeploymentFile(t, "install-pgw.sh")
	if !strings.Contains(installer, "PGW_AGENT_ADDR=127.0.0.1:9090") || !strings.Contains(installer, "PGW_MANAGEMENT_TCP_PORTS:-8080,8081") || !strings.Contains(installer, "PGW_IPV6_POLICY=deny") {
		t.Fatal("installer does not keep Agent private and IPv6 explicitly deny-only")
	}
	baseInstaller := readDeploymentFile(t, "install-pgw-base.sh")
	if !strings.Contains(baseInstaller, "PGW_MANAGEMENT_TCP_PORTS:-8080,8081") || !strings.Contains(baseInstaller, "loopback-only and must not be opened") {
		t.Fatal("base firewall installer can expose Agent port 9090 by default")
	}
}

func TestInstallerDefersLegacyImportUntilRollbackCaptureAndCredentials(t *testing.T) {
	installer := readDeploymentFile(t, "install-pgw.sh")
	for _, required := range []string{
		"preflight_legacy_state", "import-legacy-state --file \"${state}\" --dry-run",
		"after_credentials after_legacy_import after_units", "capture_state\n    run_install_transaction",
		"O_CREAT|os.O_EXCL|os.O_NOFOLLOW", "--state-fd", "--key-fd", "--report-fd",
		"sealed_stage=\"$(host_path \"/run/pgw/legacy-sealed.$(basename -- \"${backup_dir}\")\")\"", "report[\"checksum\"] != sys.argv[2]",
		"cleanup_legacy_import_runtime", "${BACKUP_ROOT}/legacy-import-report.$(basename -- \"${backup_dir}\").json",
	} {
		if !strings.Contains(installer, required) {
			t.Fatalf("installer is missing legacy migration safety contract %q", required)
		}
	}
	if strings.Contains(installer, "legacy state.json exists but SQLite migration has not been created") {
		t.Fatal("installer still rejects a state.json-only v1 host before migration")
	}
	if strings.Contains(installer, "report=\"${backup_dir}/legacy-import-report") {
		t.Fatal("legacy report must not mutate an already sealed snapshot tree")
	}
}
