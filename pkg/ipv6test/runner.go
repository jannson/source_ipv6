package ipv6test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"
)

// Runner executes connectivity tests.
type Runner struct {
	client  *http.Client
	options Options
}

// NewRunner returns a Runner with merged options.
func NewRunner(opts Options) *Runner {
	c := &http.Client{
		Timeout: opts.Timeout,
	}
	if opts.HTTPUserAgent == "" {
		opts.HTTPUserAgent = defaultUserAgent
	}
	return &Runner{client: c, options: opts}
}

// Catalog lists supported tests with example URLs.
func Catalog(opts Options) []Definition {
	return []Definition{
		{Name: TestIPv4DNS, Description: "A-only hostname reachability", Category: "connectivity", RequiresIPv6: false, LargePayload: false, ExampleURL: opts.Endpoints[TestIPv4DNS]},
		{Name: TestIPv6DNS, Description: "AAAA-only hostname reachability", Category: "connectivity", RequiresIPv6: true, LargePayload: false, ExampleURL: opts.Endpoints[TestIPv6DNS]},
		{Name: TestDualStack, Description: "Dual-stack hostname reachability", Category: "connectivity", RequiresIPv6: false, LargePayload: false, ExampleURL: opts.Endpoints[TestDualStack]},
		{Name: TestDualStackMTU, Description: "Dual-stack large-payload reachability", Category: "mtu", RequiresIPv6: false, LargePayload: true, ExampleURL: opts.Endpoints[TestDualStackMTU], PacketSize: opts.PacketSize},
		{Name: TestIPv6MTU, Description: "IPv6 large-payload reachability", Category: "mtu", RequiresIPv6: true, LargePayload: true, ExampleURL: opts.Endpoints[TestIPv6MTU], PacketSize: opts.PacketSize},
		{Name: TestDNSV6Resolver, Description: "Resolver reachability to IPv6-only auth", Category: "dns", RequiresIPv6: false, LargePayload: false, ExampleURL: opts.Endpoints[TestDNSV6Resolver]},
		{Name: TestASNLookupV4, Description: "ASN lookup over IPv4", Category: "metadata", RequiresIPv6: false, LargePayload: false, ExampleURL: opts.Endpoints[TestASNLookupV4]},
		{Name: TestASNLookupV6, Description: "ASN lookup over IPv6", Category: "metadata", RequiresIPv6: true, LargePayload: false, ExampleURL: opts.Endpoints[TestASNLookupV6]},
	}
}

// Run executes a batch synchronously.
func (r *Runner) Run(ctx context.Context, req RunRequest) (RunResult, error) {
	opts := r.options
	if req.Timeout > 0 {
		opts.Timeout = req.Timeout
	}
	if req.SlowThreshold > 0 {
		opts.SlowThreshold = req.SlowThreshold
	}
	if req.PacketSizeBytes > 0 {
		opts.PacketSize = req.PacketSizeBytes
	}

	// Clone client with per-run timeout.
	client := *r.client
	client.Timeout = opts.Timeout

	tests := req.Tests
	if len(tests) == 0 {
		tests = []TestName{TestIPv4DNS, TestIPv6DNS, TestDualStack, TestDualStackMTU, TestIPv6MTU, TestDNSV6Resolver, TestASNLookupV4, TestASNLookupV6}
	}

	start := time.Now()
	result := RunResult{
		RunID:           randomRunID(),
		StartedAt:       start,
		SlowThresholdMs: opts.SlowThreshold.Milliseconds(),
		TimeoutMs:       opts.Timeout.Milliseconds(),
		PacketSizeBytes: opts.PacketSize,
	}

	for _, tn := range tests {
		tr := r.runSingle(ctx, &client, opts, tn)
		result.Results = append(result.Results, tr)
		if tr.IP != nil {
			switch tr.IP.Type {
			case "ipv4":
				if result.IPv4 == nil {
					result.IPv4 = tr.IP
				}
			case "ipv6":
				if result.IPv6 == nil {
					result.IPv6 = tr.IP
				}
			}
		}
	}
	result.DurationMs = time.Since(start).Milliseconds()
	return result, nil
}

func (r *Runner) runSingle(ctx context.Context, client *http.Client, opts Options, tn TestName) TestResult {
	url, ok := opts.Endpoints[tn]
	if !ok || url == "" {
		return TestResult{Name: tn, Status: StatusSkipped, Notes: "no endpoint configured"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return TestResult{Name: tn, Status: StatusError, Error: err.Error(), URL: url}
	}
	req.Header.Set("User-Agent", opts.HTTPUserAgent)

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	tr := TestResult{
		Name:       tn,
		URL:        url,
		PacketSize: opts.PacketSize,
		Duration:   duration,
		TimeMs:     duration.Milliseconds(),
	}

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			tr.Status = StatusTimeout
		} else {
			tr.Status = StatusError
		}
		tr.Error = err.Error()
		return tr
	}
	defer resp.Body.Close()
	tr.HTTPStatusCode = resp.StatusCode

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	ipObs := parseIPObservation(body)
	if ipObs != nil {
		tr.IP = ipObs
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		if duration > opts.SlowThreshold {
			tr.Status = StatusSlow
		} else {
			tr.Status = StatusOK
		}
	} else {
		tr.Status = StatusBad
		tr.Error = fmt.Sprintf("http status %d", resp.StatusCode)
	}

	return tr
}

func parseIPObservation(body []byte) *IpObservation {
	var ipObs IpObservation
	if err := json.Unmarshal(body, &ipObs); err == nil {
		if ipObs.IP != "" || ipObs.Type != "" {
			return &ipObs
		}
	}
	// Try JSONP payload: callback({...})
	// Look for first '{' and last '}'.
	for i, b := range body {
		if b == '{' {
			for j := len(body) - 1; j > i; j-- {
				if body[j] == '}' {
					var obs IpObservation
					if json.Unmarshal(body[i:j+1], &obs) == nil {
						if obs.IP != "" || obs.Type != "" {
							return &obs
						}
					}
					break
				}
			}
			break
		}
	}
	return nil
}

func randomRunID() string {
	return fmt.Sprintf("run-%d-%d", time.Now().UnixNano(), rand.Int63())
}
