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
		showErrs = flag.Bool("show-errors", false, "Show error details (truncated); default hides error strings for cleaner output")
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
		if tr.Error != "" && *showErrs {
			fmt.Printf(" err=%s", truncateErr(tr.Error))
		}
		fmt.Println()
	}

	analysis := ipv6test.Analyze(result)
	printScores(analysis)
	printTokens(analysis.Tokens)
}

func printScores(a ipv6test.Analysis) {
	s4 := "n/a"
	if a.ScoreTransition >= 0 {
		s4 = fmt.Sprintf("%d/10", a.ScoreTransition)
	}
	s6 := "n/a"
	if a.ScoreStrict >= 0 {
		s6 = fmt.Sprintf("%d/10", a.ScoreStrict)
	}
	fmt.Printf("\nReadiness: IPv4 %s, IPv6 %s (mini %s / %s)\n", s4, s6, a.MiniPrimary, a.MiniSecondary)
}

func printTokens(tokens []ipv6test.TokenDetail) {
	if len(tokens) == 0 {
		return
	}
	fmt.Println("Findings:")
	for _, t := range tokens {
		marker := markerForColor(t.Color)
		msg := t.Message
		if msg == "" {
			msg = t.Token
		}
		if t.MoreInfo != "" {
			msg = msg + fmt.Sprintf(" [more: %s]", t.MoreInfo)
		}
		fmt.Printf("  %s %-18s %s (v4=%d v6=%d)\n", marker, t.Color, msg, t.ScoreIPv4, t.ScoreIPv6)
	}
}

func markerForColor(color string) string {
	switch strings.ToUpper(color) {
	case "GREEN":
		return "[OK]"
	case "BLUE":
		return "[INFO]"
	case "ORANGE":
		return "[WARN]"
	case "RED":
		return "[FAIL]"
	default:
		return "[INFO]"
	}
}

func truncateErr(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
