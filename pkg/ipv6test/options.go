package ipv6test

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Options controls how test URLs are built and executed.
type Options struct {
	Domain        string
	Endpoints     map[TestName]string
	Timeout       time.Duration
	SlowThreshold time.Duration
	PacketSize    int
	HTTPUserAgent string
}

const (
	defaultDomain        = "toany.net"
	defaultLookupDomain  = "toany.net"
	defaultTimeout       = 15 * time.Second
	defaultSlowThreshold = 5 * time.Second
	defaultPacketSize    = 1600
	defaultUserAgent     = "testipv6-go/0.1"
)

// DefaultOptions builds a ready-to-use Options.
func DefaultOptions() Options {
	return Options{
		Domain:        defaultDomain,
		Endpoints:     DefaultEndpoints(defaultDomain, defaultLookupDomain, defaultPacketSize),
		Timeout:       defaultTimeout,
		SlowThreshold: defaultSlowThreshold,
		PacketSize:    defaultPacketSize,
		HTTPUserAgent: defaultUserAgent,
	}
}

// DefaultEndpoints constructs URLs similar to the legacy JS.
func DefaultEndpoints(domain string, lookupDomain string, packetSize int) map[TestName]string {
	trimmed := strings.TrimSpace(domain)
	if trimmed == "" {
		trimmed = defaultDomain
	}
	lkd := strings.TrimSpace(lookupDomain)
	if lkd == "" {
		lkd = trimmed
	}
	qs := "ip/?callback=?"
	fill := strings.Repeat("x", packetSize)
	mk := func(prefix string) string {
		return fmt.Sprintf("https://%s.%s/%s", prefix, trimmed, qs)
	}
	mkMTU := func(prefix string) string {
		return fmt.Sprintf("https://%s.%s/ip/?callback=?&size=%d&fill=%s", prefix, trimmed, packetSize, url.QueryEscape(fill))
	}

	return map[TestName]string{
		TestIPv4DNS:       mk("ipv4"),
		TestIPv6DNS:       mk("ipv6"),
		TestDualStack:     mk("ds"),
		TestDualStackMTU:  mkMTU("ds"),
		TestIPv6MTU:       mkMTU("mtu1280"),
		TestDNSV6Resolver: mk("ds.v6ns"),
		TestASNLookupV4:   fmt.Sprintf("https://ipv4.lookup.%s/ip/?callback=?&asn=1", lkd),
		TestASNLookupV6:   fmt.Sprintf("https://ipv6.lookup.%s/ip/?callback=?&asn=1", lkd),
	}
}
