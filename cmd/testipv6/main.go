package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/falling-sky/source/pkg/ipv6test"
)

func main() {
	var (
		domain   = flag.String("domain", "toany.net", "Base domain for test endpoints")
		lookup   = flag.String("lookup-domain", "", "Lookup domain for ASN endpoints (default: same as domain)")
		timeout  = flag.Duration("timeout", 15*time.Second, "Per-test timeout")
		slow     = flag.Duration("slow", 5*time.Second, "Slow threshold")
		packet   = flag.Int("packet-size", 1600, "Packet size for MTU-style tests")
		testsCSV = flag.String("tests", "", "Comma separated test names (default: all)")
		jsonOut  = flag.Bool("json", false, "Output JSON instead of human readable text")
	)
	flag.Parse()

	opts := ipv6test.DefaultOptions()
	opts.Domain = *domain
	ld := *lookup
	if ld == "" {
		ld = *domain
	}
	opts.Endpoints = ipv6test.DefaultEndpoints(*domain, ld, *packet)
	opts.Timeout = *timeout
	opts.SlowThreshold = *slow
	opts.PacketSize = *packet

	runner := ipv6test.NewRunner(opts)

	var tests []ipv6test.TestName
	if *testsCSV != "" {
		for _, t := range strings.Split(*testsCSV, ",") {
			trim := strings.TrimSpace(t)
			if trim == "" {
				continue
			}
			tests = append(tests, ipv6test.TestName(trim))
		}
	}

	result, err := runner.Run(context.Background(), ipv6test.RunRequest{
		Tests:           tests,
		Timeout:         opts.Timeout,
		SlowThreshold:   opts.SlowThreshold,
		PacketSizeBytes: opts.PacketSize,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "run failed: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return
	}

	fmt.Printf("Run ID: %s\n", result.RunID)
	fmt.Printf("Started: %s, Duration: %d ms\n", result.StartedAt.Format(time.RFC3339), result.DurationMs)
	for _, tr := range result.Results {
		fmt.Printf("- %-14s %-7s %5dms", tr.Name, tr.Status, tr.TimeMs)
		if tr.IP != nil && tr.IP.IP != "" {
			fmt.Printf(" ip=%s", tr.IP.IP)
		}
		if tr.Error != "" {
			fmt.Printf(" err=%s", tr.Error)
		}
		fmt.Println()
	}
}
