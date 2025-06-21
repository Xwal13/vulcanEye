package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func debugPrintf(cfg *ScanConfig, s string, args ...interface{}) {
	if cfg.Debug {
		fmt.Printf(ColorCyan+"[DEBUG] "+s+ColorReset+"\n", args...)
	}
}

func isNumericParam(param string) bool {
	param = strings.ToLower(param)
	return strings.Contains(param, "id") || strings.Contains(param, "num") || strings.Contains(param, "age")
}

// --- WAF Detection Function ---
// Returns (detected, infoString)
func detectWAF(cfg *ScanConfig) (bool, string) {
	testPayload := "<script>alert('waf')</script>"
	baseURL, params, _ := extractParamsFromURL(cfg.URL)
	found := false
	info := ""
	// Try on all parameters if possible
	for k := range params {
		orig := params.Get(k)
		params.Set(k, testPayload)
		urlWithParams := baseURL + "?" + params.Encode()
		body, headers, err := fetchURL(cfg, urlWithParams, "GET", nil, nil)
		params.Set(k, orig)
		if err != nil {
			continue
		}
		// Check for common WAF responses
		// Blocked status
		if strings.Contains(strings.ToLower(body), "access denied") ||
			strings.Contains(strings.ToLower(body), "request rejected") ||
			strings.Contains(strings.ToLower(body), "waf") ||
			strings.Contains(strings.ToLower(body), "firewall") ||
			strings.Contains(strings.ToLower(body), "blocked") ||
			strings.Contains(strings.ToLower(body), "forbidden") ||
			strings.Contains(strings.ToLower(body), "406 not acceptable") ||
			strings.Contains(strings.ToLower(body), "mod_security") ||
			strings.Contains(strings.ToLower(body), "cloudflare") ||
			strings.Contains(strings.ToLower(body), "incapsula") {
			found = true
			info = "WAF detected (body message)"
			break
		}
		if headers.Get("Server") != "" && (strings.Contains(strings.ToLower(headers.Get("Server")), "cloudflare") ||
			strings.Contains(strings.ToLower(headers.Get("Server")), "akamai") ||
			strings.Contains(strings.ToLower(headers.Get("Server")), "f5") ||
			strings.Contains(strings.ToLower(headers.Get("Server")), "barracuda") ||
			strings.Contains(strings.ToLower(headers.Get("Server")), "sucuri")) {
			found = true
			info = "WAF detected (Server header: " + headers.Get("Server") + ")"
			break
		}
		if headers.Get("X-Sucuri-ID") != "" || headers.Get("X-WAF-Blocked") != "" ||
			headers.Get("X-CDN") == "Incapsula" {
			found = true
			info = "WAF detected (special header)"
			break
		}
	}
	return found, info
}

// --- WAF Evasion Techniques ---

// Encode payload (URL, double, hex etc)
func wafEvadeEncodings(payload string) []string {
	encodings := []string{payload}
	// URL encode
	encodings = append(encodings, url.QueryEscape(payload))
	// Double encode
	encodings = append(encodings, url.QueryEscape(url.QueryEscape(payload)))
	// Hex encode (for ASCII)
	hex := ""
	for i := 0; i < len(payload); i++ {
		hex += fmt.Sprintf("%%%02x", payload[i])
	}
	encodings = append(encodings, hex)
	return encodings
}

// If a WAF is detected, try using the IP address instead of the domain
func domainToIP(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	host := u.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return targetURL
	}
	ip := ips[0].String()
	u.Host = strings.Replace(u.Host, host, ip, 1)
	return u.String()
}

// Optionally add random case, comments, etc. (for SQLi etc.)
// For simplicity, only encode techniques are added here.