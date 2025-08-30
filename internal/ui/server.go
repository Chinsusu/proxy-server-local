package ui

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Run starts the UI server.
// Env: PGW_UI_ADDR (default :8081), PGW_API_BASE (default http://127.0.0.1:8080),
//      PGW_AGENT_BASE (default http://127.0.0.1:9090)
func Run() error {
	addr := getenv("PGW_UI_ADDR", ":8081")
	apiBase := getenv("PGW_API_BASE", "http://127.0.0.1:8080")
	agentBase := getenv("PGW_AGENT_BASE", "http://127.0.0.1:9090")

	mux := http.NewServeMux()

	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/styles.css", serveStyles)
	mux.HandleFunc("/app.js", serveAppJS)

	// reverse-proxy shim -> tránh CORS cho UI
	mux.Handle("/api/", http.StripPrefix("/api", proxyTo(apiBase)))
	mux.Handle("/agent/", http.StripPrefix("/agent", proxyTo(agentBase)))

	s := &http.Server{
		Addr:              addr,
		Handler:           logRequest(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("pgw-ui listening on %s (API=%s, AGENT=%s)\n", addr, apiBase, agentBase)
	return s.ListenAndServe()
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, _ := assetsFS.ReadFile("assets/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func serveStyles(w http.ResponseWriter, r *http.Request) {
	b, _ := assetsFS.ReadFile("assets/styles.css")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func serveAppJS(w http.ResponseWriter, r *http.Request) {
	b, _ := assetsFS.ReadFile("assets/app.js")
	w.Header().Set("Content-Type", "application/javascript")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func proxyTo(base string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := strings.TrimRight(base, "/") + r.URL.Path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		body, _ := io.ReadAll(r.Body)
		req, _ := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
		for k, v := range r.Header {
			for _, vv := range v {
				req.Header.Add(k, vv)
			}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &lrw{ResponseWriter: w, status: 200}
		next.ServeHTTP(lrw, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Truncate(time.Millisecond))
	})
}

type lrw struct {
	http.ResponseWriter
	status int
}

func (w *lrw) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
