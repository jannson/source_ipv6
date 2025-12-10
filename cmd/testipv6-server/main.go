package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/falling-sky/source/pkg/ipv6test"
)

type server struct {
	opts   ipv6test.Options
	runner *ipv6test.Runner
	store  struct {
		sync.RWMutex
		data map[string]ipv6test.RunResult
	}
}

func main() {
	addr := env("TESTIPV6_ADDR", ":8080")
	domain := env("TESTIPV6_DOMAIN", "test-ipv6.com")
	timeout := envDuration("TESTIPV6_TIMEOUT", 15*time.Second)
	slow := envDuration("TESTIPV6_SLOW", 5*time.Second)
	packetSize := envInt("TESTIPV6_PACKET_SIZE", 1600)

	opts := ipv6test.DefaultOptions()
	opts.Domain = domain
	opts.Endpoints = ipv6test.DefaultEndpoints(domain, packetSize)
	opts.Timeout = timeout
	opts.SlowThreshold = slow
	opts.PacketSize = packetSize

	s := &server{
		opts:   opts,
		runner: ipv6test.NewRunner(opts),
	}
	s.store.data = make(map[string]ipv6test.RunResult)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/v1/tests/catalog", s.handleCatalog)
	mux.HandleFunc("/api/v1/tests/run", s.handleRun)
	mux.HandleFunc("/api/v1/tests/", s.handleGetRun) // /api/v1/tests/{id}

	log.Printf("testipv6-server listening on %s (domain=%s)", addr, domain)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := map[string]any{
		"tests": ipv6test.Catalog(s.opts),
	}
	writeJSON(w, http.StatusOK, resp)
}

type runRequest struct {
	Tests           []ipv6test.TestName `json:"tests"`
	TimeoutMs       int64               `json:"timeoutMs"`
	SlowThresholdMs int64               `json:"slowThresholdMs"`
	PacketSizeBytes int                 `json:"packetSizeBytes"`
}

func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req runRequest
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "bad_request", "message": err.Error()})
			return
		}
	}

	runReq := ipv6test.RunRequest{
		Tests:           req.Tests,
		PacketSizeBytes: s.opts.PacketSize,
	}
	if req.PacketSizeBytes > 0 {
		runReq.PacketSizeBytes = req.PacketSizeBytes
	}
	if req.TimeoutMs > 0 {
		runReq.Timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}
	if req.SlowThresholdMs > 0 {
		runReq.SlowThreshold = time.Duration(req.SlowThresholdMs) * time.Millisecond
	}

	result, err := s.runner.Run(context.Background(), runReq)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"code": "run_failed", "message": err.Error()})
		return
	}
	s.store.Lock()
	s.store.data[result.RunID] = result
	s.store.Unlock()

	writeJSON(w, http.StatusOK, result)
}

func (s *server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Expect /api/v1/tests/{id}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/tests/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	runID := parts[0]
	s.store.RLock()
	res, ok := s.store.data[runID]
	s.store.RUnlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "not_found", "message": "run not found"})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func env(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return def
}

func envInt(key string, def int) int {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			return n
		}
	}
	return def
}
