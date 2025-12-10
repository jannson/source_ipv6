package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/falling-sky/source/pkg/ipv6test"
	"github.com/oschwald/geoip2-golang"
)

type server struct {
	opts   ipv6test.Options
	runner *ipv6test.Runner
	store  struct {
		sync.RWMutex
		data map[string]ipv6test.RunResult
	}
	asnDB *geoip2.Reader
}

func main() {
	domainDefault := env("TESTIPV6_DOMAIN", "toany.net")
	lookupDefault := env("TESTIPV6_LOOKUP_DOMAIN", domainDefault)
	addrFlag := flag.String("addr", env("TESTIPV6_ADDR", ":8080"), "listen address (e.g. :8080)")
	domainFlag := flag.String("domain", domainDefault, "base domain for test endpoints")
	lookupFlag := flag.String("lookup-domain", lookupDefault, "lookup domain for ASN endpoints")
	timeoutFlag := flag.Duration("timeout", envDuration("TESTIPV6_TIMEOUT", 15*time.Second), "per-test timeout")
	slowFlag := flag.Duration("slow", envDuration("TESTIPV6_SLOW", 5*time.Second), "slow threshold")
	packetFlag := flag.Int("packet-size", envInt("TESTIPV6_PACKET_SIZE", 1600), "packet size for MTU-style tests")
	asnFlag := flag.String("asn-db", env("TESTIPV6_ASN_DB", ""), "path to GeoLite2-ASN.mmdb for ASN lookups")
	flag.Parse()

	addr := *addrFlag
	domain := *domainFlag
	lookupDomain := *lookupFlag
	timeout := *timeoutFlag
	slow := *slowFlag
	packetSize := *packetFlag
	asnPath := *asnFlag

	opts := ipv6test.DefaultOptions()
	opts.Domain = domain
	opts.Endpoints = ipv6test.DefaultEndpoints(domain, lookupDomain, packetSize)
	opts.Timeout = timeout
	opts.SlowThreshold = slow
	opts.PacketSize = packetSize

	s := &server{
		opts:   opts,
		runner: ipv6test.NewRunner(opts),
	}
	s.store.data = make(map[string]ipv6test.RunResult)
	if asnPath != "" {
		db, err := geoip2.Open(asnPath)
		if err != nil {
			log.Printf("asn db load failed (%s): %v", asnPath, err)
		} else {
			s.asnDB = db
			log.Printf("asn db loaded: %s", asnPath)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/v1/tests/catalog", s.handleCatalog)
	mux.HandleFunc("/api/v1/tests/run", s.handleRun)
	mux.HandleFunc("/api/v1/tests/", s.handleGetRun) // /api/v1/tests/{id}
	mux.HandleFunc("/ip/", s.handleIP)
	mux.HandleFunc("/ip", s.handleIP)

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
	clientIP, scheme := forwardedClient(r)
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

	if clientIP != "" {
		result.Results = append(result.Results, ipv6test.TestResult{
			Name:   "client_info",
			Status: ipv6test.StatusOK,
			Notes:  fmt.Sprintf("client_ip=%s scheme=%s", clientIP, scheme),
		})
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

// /ip/?callback=?&asn=1 compatible handler.
func (s *server) handleIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	testIP := q.Get("testip")
	if testIP == "" {
		testIP, _ = forwardedClient(r)
	}
	ipStr, ipType := parseIP(testIP)
	ipObs := ipv6test.IpObservation{
		IP:   ipStr,
		Type: ipType,
	}
	if s.asnDB != nil && ipStr != "" {
		if addr := net.ParseIP(ipStr); addr != nil {
			if rec, err := s.asnDB.ASN(addr); err == nil {
				ipObs.ASN = int(rec.AutonomousSystemNumber)
				ipObs.ASNName = rec.AutonomousSystemOrganization
			}
		}
	}

	body, _ := json.Marshal(ipObs)
	callback := q.Get("callback")
	if callback != "" && callback != "?" {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprintf(w, "%s(%s);", callback, string(body))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
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

// forwardedClient extracts client address and scheme honoring common proxy headers.
func forwardedClient(r *http.Request) (ip string, scheme string) {
	scheme = r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = r.URL.Scheme
		if scheme == "" {
			scheme = "http"
		}
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0]), scheme
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip, scheme
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host, scheme
}

func parseIP(s string) (string, string) {
	ip := net.ParseIP(s)
	if ip == nil {
		return "", "unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), "ipv4"
	}
	return ip.String(), "ipv6"
}
