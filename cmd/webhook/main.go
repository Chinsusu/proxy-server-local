package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	webhookSecret  string
	deployScript   string
	deploymentLock sync.Mutex
	isDeploying    bool
)

type GitHubWebhook struct {
	Ref        string `json:"ref"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	HeadCommit struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		Author  struct {
			Name string `json:"name"`
		} `json:"author"`
	} `json:"head_commit"`
}

func main() {
	// Load configuration from environment
	webhookSecret = os.Getenv("PGW_WEBHOOK_SECRET")
	if webhookSecret == "" {
		log.Fatal("[FATAL] PGW_WEBHOOK_SECRET not set")
	}

	deployScript = os.Getenv("PGW_WEBHOOK_DEPLOY_SCRIPT")
	if deployScript == "" {
		deployScript = "/usr/local/bin/update-pgw.sh"
	}

	port := os.Getenv("PGW_WEBHOOK_PORT")
	if port == "" {
		port = "9091"
	}

	http.HandleFunc("/webhook", handleWebhook)
	http.HandleFunc("/health", handleHealth)

	addr := ":" + port
	log.Printf("[INFO] PGW Webhook service starting on %s", addr)
	log.Printf("[INFO] Deploy script: %s", deployScript)
	
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("[FATAL] Server failed: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "healthy"
	if isDeploying {
		status = "deploying"
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     status,
		"service":    "pgw-webhook",
		"version":    "1.0.0",
		"timestamp":  time.Now().Format(time.RFC3339),
	})
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read body: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Validate signature
	signature := r.Header.Get("X-Hub-Signature-256")
	if !validateSignature(body, signature) {
		log.Printf("[WARN] Invalid signature from %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse webhook payload
	var webhook GitHubWebhook
	if err := json.Unmarshal(body, &webhook); err != nil {
		log.Printf("[ERROR] Failed to parse webhook: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Filter: only deploy on push to main branch
	if !strings.HasSuffix(webhook.Ref, "/main") {
		log.Printf("[INFO] Ignoring push to %s (not main branch)", webhook.Ref)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Ignored: not main branch\n")
		return
	}

	log.Printf("[INFO] Webhook received: %s push to %s", 
		webhook.Repository.FullName, webhook.Ref)
	log.Printf("[INFO] Commit: %s by %s - %s",
		webhook.HeadCommit.ID[:7],
		webhook.HeadCommit.Author.Name,
		webhook.HeadCommit.Message)

	// Trigger deployment asynchronously
	go triggerDeployment(webhook)

	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintf(w, "Deployment triggered\n")
}

func validateSignature(body []byte, signature string) bool {
	if signature == "" {
		return false
	}

	// Remove "sha256=" prefix
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	signature = strings.TrimPrefix(signature, "sha256=")

	// Compute HMAC
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(body)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

func triggerDeployment(webhook GitHubWebhook) {
	// Prevent concurrent deployments
	deploymentLock.Lock()
	if isDeploying {
		log.Printf("[WARN] Deployment already in progress, skipping")
		deploymentLock.Unlock()
		return
	}
	isDeploying = true
	deploymentLock.Unlock()

	defer func() {
		deploymentLock.Lock()
		isDeploying = false
		deploymentLock.Unlock()
	}()

	log.Printf("[DEPLOY] Starting deployment for commit %s", webhook.HeadCommit.ID[:7])

	// Execute deployment script
	cmd := exec.Command(deployScript)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("GIT_COMMIT=%s", webhook.HeadCommit.ID),
		fmt.Sprintf("GIT_AUTHOR=%s", webhook.HeadCommit.Author.Name),
		fmt.Sprintf("GIT_MESSAGE=%s", webhook.HeadCommit.Message),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[ERROR] Deployment failed: %v\nOutput:\n%s", err, string(output))
		return
	}

	log.Printf("[DEPLOY] Deployment successful\nOutput:\n%s", string(output))
}
