package ipv6test

import (
	"fmt"
	"sort"
	"strings"
)

// TokenDetail describes a derived diagnosis token.
type TokenDetail struct {
	Token     string `json:"token"`
	ScoreIPv4 int    `json:"scoreIPv4"`
	ScoreIPv6 int    `json:"scoreIPv6"`
	Color     string `json:"color"`
	Message   string `json:"message"`
	MoreInfo  string `json:"moreInfo,omitempty"`
}

// Analysis mirrors the JS verdict: tokens plus readiness scores.
type Analysis struct {
	Tokens          []TokenDetail `json:"tokens"`
	ScoreTransition int           `json:"scoreTransition"`
	ScoreStrict     int           `json:"scoreStrict"`
	MiniPrimary     string        `json:"miniPrimary"`
	MiniSecondary   string        `json:"miniSecondary"`
}

// Analyze converts a RunResult into JS-like verdict tokens and scores.
func Analyze(res RunResult) Analysis {
	status := buildStatusIndex(res)

	miniPrimary := status.miniPrimary()
	miniSecondary := status.miniSecondary()

	tokens := deriveTokens(res, status, miniPrimary, miniSecondary)
	tokens = dedupe(tokens)

	details := expandTokens(tokens)
	scoreTransition, scoreStrict := computeScores(details)

	return Analysis{
		Tokens:          details,
		ScoreTransition: scoreTransition,
		ScoreStrict:     scoreStrict,
		MiniPrimary:     miniPrimary,
		MiniSecondary:   miniSecondary,
	}
}

// statusIndex holds per-test status and IP info.
type statusIndex struct {
	a     Status // ipv4_dns
	aaaa  Status // ipv6_dns
	ds4   Status
	ds6   Status
	v6mtu Status
	dsmtu Status
	v6ns  Status
	ipv4  *IpObservation
	ipv6  *IpObservation
}

func statusChar(st Status) string {
	switch st {
	case StatusOK:
		return "o"
	case StatusSlow:
		return "s"
	case StatusTimeout:
		return "t"
	case StatusBad, StatusError:
		return "b"
	case StatusSkipped:
		return "x"
	default:
		return "b"
	}
}

func (s statusIndex) miniPrimary() string {
	return statusChar(s.a) + statusChar(s.aaaa) + statusChar(s.ds4) + statusChar(s.ds6)
}

func (s statusIndex) miniSecondary() string {
	return statusChar(s.v6mtu) + statusChar(s.v6ns)
}

func buildStatusIndex(res RunResult) statusIndex {
	idx := statusIndex{}
	for i := range res.Results {
		tr := res.Results[i]
		switch tr.Name {
		case TestIPv4DNS:
			idx.a = tr.Status
			if tr.IP != nil && tr.IP.Type == "ipv4" && idx.ipv4 == nil {
				idx.ipv4 = tr.IP
			}
		case TestIPv6DNS:
			idx.aaaa = tr.Status
			if tr.IP != nil && tr.IP.Type == "ipv6" && idx.ipv6 == nil {
				idx.ipv6 = tr.IP
			}
		case TestDualStack:
			// Mirror JS logic: whichever family answered sets the matching ds status; the other is bad.
			if tr.IP != nil && strings.EqualFold(tr.IP.Type, "ipv6") {
				idx.ds6 = tr.Status
				if idx.ds4 == "" {
					idx.ds4 = StatusBad
				}
				if idx.ipv6 == nil {
					idx.ipv6 = tr.IP
				}
			} else {
				idx.ds4 = tr.Status
				if idx.ds6 == "" {
					idx.ds6 = StatusBad
				}
				if tr.IP != nil && tr.IP.Type == "ipv4" && idx.ipv4 == nil {
					idx.ipv4 = tr.IP
				}
			}
		case TestDualStackMTU:
			idx.dsmtu = tr.Status
		case TestIPv6MTU:
			idx.v6mtu = tr.Status
		case TestDNSV6Resolver:
			idx.v6ns = tr.Status
		}
	}

	// Also record overall IPv4/IPv6 seen in the run summary.
	if res.IPv4 != nil && idx.ipv4 == nil {
		idx.ipv4 = res.IPv4
	}
	if res.IPv6 != nil && idx.ipv6 == nil {
		idx.ipv6 = res.IPv6
	}

	// Default unset statuses to skipped to avoid empty chars.
	if idx.a == "" {
		idx.a = StatusSkipped
	}
	if idx.aaaa == "" {
		idx.aaaa = StatusSkipped
	}
	if idx.ds4 == "" {
		idx.ds4 = StatusSkipped
	}
	if idx.ds6 == "" {
		idx.ds6 = StatusSkipped
	}
	if idx.v6mtu == "" {
		idx.v6mtu = StatusSkipped
	}
	if idx.dsmtu == "" {
		idx.dsmtu = StatusSkipped
	}
	if idx.v6ns == "" {
		idx.v6ns = StatusSkipped
	}
	return idx
}

func deriveTokens(res RunResult, st statusIndex, miniPrimary, miniSecondary string) []string {
	var tokens []string

	hasIPv4 := st.ipv4 != nil && st.ipv4.IP != ""
	hasIPv6 := st.ipv6 != nil && st.ipv6.IP != ""

	// No address fallbacks.
	if !hasIPv4 && !hasIPv6 {
		tokens = append(tokens, "no_address")
	} else if !hasIPv4 {
		tokens = append(tokens, "ipv4:no_address")
	} else if !hasIPv6 {
		tokens = append(tokens, "ipv6:no_address")
	}

	// Primary connectivity buckets.
	switch {
	case hasIPv4 && !hasIPv6:
		// IPv4 only, refine by dual-stack status.
		ds := statusChar(st.ds6)
		switch ds {
		case "s":
			tokens = append(tokens, "ipv4_only:ds_slow")
		case "t", "b":
			tokens = append(tokens, "ipv4_only:ds_timeout")
		default:
			tokens = append(tokens, "ipv4_only:ds_good")
		}
		tokens = append(tokens, "ipv4_only")
	case hasIPv6 && !hasIPv4:
		tokens = append(tokens, "ipv6_only")
	case hasIPv4 && hasIPv6:
		ds6c := statusChar(st.ds6)
		if ds6c == "b" || ds6c == "t" {
			tokens = append(tokens, "avoids_ipv6")
		} else {
			tokens = append(tokens, "dualstack:safe")
		}
	}

	// DNS v6 resolver.
	if (isGood(st.ds4) || isGood(st.ds6)) && st.v6ns != "" && st.v6ns != StatusSkipped {
		if isGood(st.v6ns) {
			tokens = append(tokens, "v6ns:ok")
		} else {
			tokens = append(tokens, "v6ns:bad")
		}
	}

	// MTU problems: only warn if IPv6 basic connectivity succeeded.
	if isGood(st.aaaa) && (isBadish(st.v6mtu) || isBadish(st.dsmtu)) {
		tokens = append(tokens, "IPv6 MTU")
	}

	// Need IPv6 encouragement (mirrors JS simplified).
	if !hasIPv6 || isTunnel(st.ipv6) {
		if isGood(st.dsmtu) || st.dsmtu == StatusSkipped {
			tokens = append(tokens, "needs_ipv6")
		}
	} else if !isGood(st.dsmtu) && st.dsmtu != StatusSkipped {
		tokens = append(tokens, "dualstack:unsafe")
	}

	// Tunnels.
	if isTunnelType(st.ipv6, "Teredo") {
		tokens = append(tokens, "teredo")
	}
	if isTunnelType(st.ipv6, "6to4") {
		tokens = append(tokens, "6to4")
	}

	// Preserve mini_primary/minor confusion token if nothing added.
	if len(tokens) == 0 {
		tokens = append(tokens, miniPrimary)
	}
	return tokens
}

func isTunnel(ip *IpObservation) bool {
	return isTunnelType(ip, "Teredo") || isTunnelType(ip, "6to4")
}

func isTunnelType(ip *IpObservation, name string) bool {
	if ip == nil {
		return false
	}
	return strings.EqualFold(ip.Subtype, name)
}

func isGood(st Status) bool {
	return st == StatusOK || st == StatusSlow
}

func isBadish(st Status) bool {
	return st == StatusBad || st == StatusTimeout || st == StatusError
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, t := range in {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func computeScores(tokens []TokenDetail) (int, int) {
	scoreTransition := 100
	scoreStrict := 100
	for _, t := range tokens {
		if t.ScoreIPv4 < scoreTransition {
			scoreTransition = t.ScoreIPv4
		}
		if t.ScoreIPv6 < scoreStrict {
			scoreStrict = t.ScoreIPv6
		}
	}
	if scoreTransition == 100 {
		scoreTransition = -1
	}
	if scoreStrict == 100 {
		scoreStrict = -1
	}
	return scoreTransition, scoreStrict
}

func expandTokens(tokens []string) []TokenDetail {
	var details []TokenDetail
	for _, t := range tokens {
		entry, ok := scoreTable[t]
		if !ok {
			details = append(details, TokenDetail{
				Token:     t,
				ScoreIPv4: 10,
				ScoreIPv6: 10,
				Color:     "YELLOW",
				Message:   fmt.Sprintf("(unknown result code: %s)", t),
				MoreInfo:  "",
			})
			continue
		}
		msg := messageTable[t]
		info := moreInfoTable[t]
		details = append(details, TokenDetail{
			Token:     t,
			ScoreIPv4: entry[0],
			ScoreIPv6: entry[1],
			Color:     colorName(entry[2]),
			Message:   msg,
			MoreInfo:  info,
		})
	}

	// Keep stable order.
	sort.SliceStable(details, func(i, j int) bool { return details[i].Token < details[j].Token })
	return details
}

// scoreTable and messageTable are trimmed ports of templates/js/inc/scores.js and messages.js.
var scoreTable = map[string][3]int{
	"6to4":                     {7, 7, intBlue},
	"teredo":                   {7, 7, intBlue},
	"teredo-v4pref":            {10, 7, intBlue},
	"teredo-minimum":           {10, 0, intBlue},
	"IPv6 MTU":                 {1, 1, intRed},
	"dualstack:ipv4_preferred": {10, 10, intGreen},
	"dualstack:ipv6_preferred": {10, 10, intGreen},
	"dualstack:slow":           {7, 7, intBlue},
	"ipv4_only":                {10, 0, intBlue},
	"ipv4_only:ds_good":        {10, 0, intBlue},
	"ipv4_only:ds_slow":        {5, 0, intRed},
	"ipv4_only:ds_timeout":     {5, 0, intRed},
	"ipv4_slow":                {5, 10, intRed},
	"ipv6_only":                {0, 10, intBlue},
	"ipv6_slow":                {10, 5, intRed},
	"ipv6_timeout":             {10, 0, intRed},
	"ipv6:nodns":               {10, 0, intRed},
	"broken_ipv6":              {0, 0, intRed},
	"webfilter:blocked":        {-1, -1, intOrange},
	"webfilter:dsboth":         {10, 10, intOrange},
	"webfilter:addons":         {10, 10, intOrange},
	"webfilter:firefox":        {10, 10, intOrange},
	"v6ns:ok":                  {10, 10, intGreen},
	"v6ns:bad":                 {10, 9, intBlue},
	"ip_timeout:firefox":       {10, 10, intRed},
	"ipv4:no_address":          {10, 10, intBlue},
	"ipv6:no_address":          {10, 10, intRed},
	"no_address":               {10, 10, intRed},
	"dualstack:safe":           {10, 10, intGreen},
	"needs_ipv6":               {10, 10, intBlue},
	"dualstack:unsafe":         {10, 10, intRed},
	"dualstack:mtu":            {10, 10, intRed},
	"proxy_via":                {10, 10, intOrange},
	"proxy_via_dumb":           {10, 10, intOrange},
	"broken":                   {0, 0, intBlue},
	"avoids_ipv6":              {10, 10, intOrange},
}

var intGreen = 1
var intRed = 2
var intBlue = 3
var intOrange = 4

func colorName(code int) string {
	switch code {
	case intGreen:
		return "GREEN"
	case intRed:
		return "RED"
	case intBlue:
		return "BLUE"
	case intOrange:
		return "ORANGE"
	default:
		return "YELLOW"
	}
}

var messageTable = map[string]string{
	"6to4":                     "You appear to be using a public 6to4 gateway; performance may suffer. Native IPv6 is preferred.",
	"teredo":                   "Your IPv6 connection appears to be using Teredo, a public IPv4/IPv6 gateway; quality may suffer.",
	"teredo-v4pref":            "Your IPv6 connection uses Teredo as a last resort; IPv4 will be preferred on dual-stack sites.",
	"teredo-minimum":           "Your IPv6 connection uses Teredo and only works to literal IPs; not useful for browsing IPv6 sites.",
	"IPv6 MTU":                 "IPv6 works but large packets fail; check MTU and allow ICMPv6 Packet Too Big.",
	"dualstack:ipv4_preferred": "Dual-stack reachable; browser prefers IPv4.",
	"dualstack:ipv6_preferred": "Dual-stack reachable; browser prefers IPv6.",
	"dualstack:slow":           "Dual-stack reachable but browser slows down when both families are offered.",
	"ipv4_only":                "You appear to be able to browse the IPv4 Internet only. You will not be able to reach IPv6-only sites.",
	"ipv4_only:ds_good":        "When a publisher offers both IPv4 and IPv6, your browser takes IPv4 without delay.",
	"ipv4_only:ds_slow":        "When a publisher offers both IPv4 and IPv6, your browser is slower than IPv4-only sites.",
	"ipv4_only:ds_timeout":     "When a publisher offers both IPv4 and IPv6, your browser times out trying to connect.",
	"ipv4_slow":                "Connections to IPv4 are slow, but functional.",
	"ipv6_only":                "You appear to be able to browse the IPv6 Internet only. You have no access to IPv4.",
	"ipv6_slow":                "Connections to IPv6 are slow, but functional.",
	"ipv6_timeout":             "Connections to IPv6-only sites are timing out.",
	"ipv6:nodns":               "IPv6 connections work, but DNS lookups do not use IPv6 (no AAAA).",
	"broken_ipv6":              "You appear to have IPv6 configured, but it completely fails for IPv6 sites.",
	"webfilter:blocked":        "Tests appear blocked by a firewall or browser filter; critical tests failed.",
	"webfilter:dsboth":         "Dual-stack tests appear blocked by a browser or network filter.",
	"webfilter:addons":         "Browser blocked test URLs; alternate methods may be incomplete.",
	"webfilter:firefox":        "Likely a Firefox add-on (e.g., NoScript/AdBlock) blocked tests.",
	"v6ns:ok":                  "Your DNS server appears to have IPv6 Internet access.",
	"v6ns:bad":                 "Your DNS server appears to have no IPv6 Internet access or is not configured to use it.",
	"ip_timeout:firefox":       "Firefox add-on likely caused IP-based tests to fail.",
	"ipv4:no_address":          "No IPv4 address detected.",
	"ipv6:no_address":          "No IPv6 address detected.",
	"no_address":               "IP addresses could not be detected due to interference from browser add-ons.",
	"dualstack:safe":           "Good news! Your current configuration will continue to work as sites enable IPv6.",
	"needs_ipv6":               "To ensure the best Internet performance and connectivity, ask your ISP about native IPv6.",
	"dualstack:unsafe":         "Our tests show dual-stack readiness is unsafe; IPv6 may cause problems.",
	"dualstack:mtu":            "MTU issues detected; IPv6-only sites may fail or load slowly.",
	"proxy_via":                "A proxy was detected; tests reflect the proxy, not the local host.",
	"proxy_via_dumb":           "A proxy was detected; tests reflect the proxy, not the local host.",
	"broken":                   "We have suggestions to help you fix your system.",
	"avoids_ipv6":              "Browser has working IPv6 but is avoiding using it; this is concerning.",
}

var moreInfoTable = map[string]string{
	"ipv6:no_address":    "faq_no_ipv6.html",
	"needs_ipv6":         "faq_no_ipv6.html",
	"6to4":               "faq_6to4.html",
	"teredo-minimum":     "faq_teredo_minimum.html",
	"v6ns:bad":           "faq_v6ns_bad.html",
	"webfilter:blocked":  "faq_browser_plugins.html",
	"webfilter:dsboth":   "faq_browser_plugins.html",
	"webfilter:firefox":  "faq_firefox_plugins.html",
	"webfilter:addons":   "faq_browser_plugins.html",
	"ip_timeout:firefox": "faq_firefox_plugins.html",
	"ipv6:nodns":         "faq_broken_aaaa.html",
	"avoids_ipv6":        "faq_avoids_ipv6.html",
}
