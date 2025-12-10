package ipv6test

import (
	"time"
)

// TestName enumerates supported tests.
type TestName string

const (
	TestIPv4DNS       TestName = "ipv4_dns"        // A-only name reachability
	TestIPv6DNS       TestName = "ipv6_dns"        // AAAA-only name reachability
	TestDualStack     TestName = "dual_stack"      // A+AAAA reachability
	TestDualStackMTU  TestName = "dual_stack_mtu"  // large payload via dual-stack
	TestIPv6MTU       TestName = "ipv6_mtu"        // large payload via IPv6-only host
	TestDNSV6Resolver TestName = "dns_v6_resolver" // resolver can reach IPv6-only auth
	TestASNLookupV4   TestName = "asn_v4"          // ASN lookup over IPv4
	TestASNLookupV6   TestName = "asn_v6"          // ASN lookup over IPv6
)

// Status values mirror the OpenAPI spec.
type Status string

const (
	StatusOK      Status = "ok"
	StatusSlow    Status = "slow"
	StatusBad     Status = "bad"
	StatusTimeout Status = "timeout"
	StatusSkipped Status = "skipped"
	StatusError   Status = "error"
)

// Definition describes a test target.
type Definition struct {
	Name         TestName
	Description  string
	Category     string
	RequiresIPv6 bool
	LargePayload bool
	ExampleURL   string
	PacketSize   int
}

// IpObservation is what we can infer from the target response.
type IpObservation struct {
	IP      string `json:"ip,omitempty"`
	Type    string `json:"type,omitempty"` // ipv4/ipv6/unknown
	Subtype string `json:"subtype,omitempty"`
	Via     string `json:"via,omitempty"`
	ASN     int    `json:"asn,omitempty"`
	ASNName string `json:"asn_name,omitempty"`
}

// TestResult is the outcome of a single probe.
type TestResult struct {
	Name           TestName       `json:"name"`
	Status         Status         `json:"status"`
	TimeMs         int64          `json:"timeMs"`
	URL            string         `json:"url"`
	PacketSize     int            `json:"packetSizeBytes,omitempty"`
	IP             *IpObservation `json:"ip,omitempty"`
	Notes          string         `json:"notes,omitempty"`
	HTTPStatusCode int            `json:"httpStatusCode,omitempty"`
	Error          string         `json:"error,omitempty"`
	Duration       time.Duration  `json:"-"`
}

// RunRequest configures a run.
type RunRequest struct {
	Tests           []TestName
	Timeout         time.Duration
	SlowThreshold   time.Duration
	PacketSizeBytes int
}

// RunResult is the aggregate outcome.
type RunResult struct {
	RunID           string         `json:"runId"`
	StartedAt       time.Time      `json:"startedAt"`
	DurationMs      int64          `json:"durationMs"`
	IPv4            *IpObservation `json:"ipv4,omitempty"`
	IPv6            *IpObservation `json:"ipv6,omitempty"`
	Results         []TestResult   `json:"results"`
	SlowThresholdMs int64          `json:"slowThresholdMs"`
	TimeoutMs       int64          `json:"timeoutMs"`
	PacketSizeBytes int            `json:"packetSizeBytes"`
}
