package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"unicode/utf8"
)

func runCLI() {
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" {
			printUsage()
			os.Exit(0)
		}
	}

	urlFlag := flag.String("u", "", "Target URL to scan")
	methodFlag := flag.String("m", "GET", "HTTP method (GET or POST)")
	paramFlag := flag.String("p", "", "Parameter name to inject if not present (if omitted, will auto-detect)")
	cookieFlag := flag.String("cookie", "", "Cookie header to use for authenticated scans")
	outputFlag := flag.String("o", "", "Output file to save the results")
	debugFlag := flag.Bool("d", false, "Enable debug mode")
	crawlLevelFlag := flag.Int("crawl", 1, "Crawl level (default 1, higher = deeper crawl)")

	// New flags for per-bug scanning
	scanXSSFlag := flag.Bool("x", false, "Scan for Cross-Site Scripting (XSS)")
	scanSQLiFlag := flag.Bool("s", false, "Scan for SQL Injection (SQLi)")
	scanLFIFlag := flag.Bool("l", false, "Scan for Local File Inclusion (LFI)")
	scanRCEFlag := flag.Bool("r", false, "Scan for Remote Code Execution (RCE)")
	scanOpenRedirectFlag := flag.Bool("or", false, "Scan for Open Redirect")
	scanPathTraversalFlag := flag.Bool("pt", false, "Scan for Path Traversal")
	scanCSRFFlag := flag.Bool("csrf", false, "Scan for Cross-Site Request Forgery (CSRF)")

	flag.Parse()

	if *urlFlag == "" {
		printUsage()
		os.Exit(1)
	}

	cfg := &ScanConfig{
		URL:               *urlFlag,
		Method:            strings.ToUpper(*methodFlag),
		InjectParam:       *paramFlag,
		Cookie:            *cookieFlag,
		OutputFile:        *outputFlag,
		Debug:             *debugFlag,
		CrawlLevel:        *crawlLevelFlag,
		ScanXSS:           *scanXSSFlag,
		ScanSQLi:          *scanSQLiFlag,
		ScanLFI:           *scanLFIFlag,
		ScanRCE:           *scanRCEFlag,
		ScanOpenRedirect:  *scanOpenRedirectFlag,
		ScanPathTraversal: *scanPathTraversalFlag,
		ScanCSRF:          *scanCSRFFlag,
	}

	// If no scan type is specified, enable all
	if !cfg.ScanXSS && !cfg.ScanSQLi && !cfg.ScanLFI && !cfg.ScanRCE && !cfg.ScanOpenRedirect && !cfg.ScanPathTraversal && !cfg.ScanCSRF {
		cfg.ScanXSS = true
		cfg.ScanSQLi = true
		cfg.ScanLFI = true
		cfg.ScanRCE = true
		cfg.ScanOpenRedirect = true
		cfg.ScanPathTraversal = true
		cfg.ScanCSRF = true
	}

	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			fmt.Printf("%s[!] Could not open output file: %v%s\n", ColorRed, err, ColorReset)
			return
		}
		defer f.Close()
		os.Stdout = f
	}

	printBanner()
	printBoxedSection("Scanning URL: " + cfg.URL)

	// Consistent [!] alignment block
	printAlignedInfo(ColorCyan, "[!] Fingerprinting backend Technologies.")
	printAlignedInfo(ColorCyan, "[!] Host: "+extractHost(cfg.URL))
	printAlignedInfo(ColorCyan, "[!] WebServer:")

	fmt.Printf("%s[!] Crawling with level %d...%s\n", ColorCyan, cfg.CrawlLevel, ColorReset)
	urls := crawlSite(cfg, cfg.URL, cfg.CrawlLevel)
	fmt.Printf("%s[!] Crawled %d URLs:%s\n", ColorCyan, len(urls), ColorReset)
	for _, u := range urls {
		fmt.Printf("%s - %s%s\n", ColorCyan, u, ColorReset)
	}
	fmt.Println()

	for _, targetURL := range urls {
		printAlignedInfo(ColorCyan, "[!] Scanning page: "+targetURL)
		pageBody, _, err := fetchURL(cfg, targetURL, "GET", nil, nil)
		if err != nil {
			printAlignedInfo(ColorRed, "[!] Could not fetch page: "+err.Error())
			continue
		}
		paramList, _, _ := extractParamNamesFromHTML(pageBody, cfg.Method)
		uploadForms := findFileUploadForms(pageBody)
		if cfg.Debug {
			for _, f := range uploadForms {
				printAlignedInfo(ColorCyan, fmt.Sprintf("[DEBUG] Upload form found: action=%q method=%q fileField=%q otherFields=%v", f.Action, f.Method, f.FileField, f.OtherFields))
			}
		}
		scanFileUploadForms(cfg, targetURL, uploadForms)

		if len(paramList) == 0 {
			_, params, _ := extractParamsFromURL(targetURL)
			for k := range params {
				paramList = append(paramList, k)
			}
		}

		if cfg.InjectParam != "" {
			paramList = []string{cfg.InjectParam}
		}
		if len(paramList) == 0 {
			printAlignedInfo(ColorRed, "[!] No injectable parameters found on page.")
			continue
		}
		printAlignedInfo(ColorCyan, fmt.Sprintf("[!] Auto-detected parameters: %v", paramList))

		for _, param := range paramList {
			baseURL, params, _ := extractParamsFromURL(targetURL)
			origVal := params.Get(param)
			baseVal := origVal
			if baseVal == "" {
				if isNumericParam(param) {
					baseVal = "1"
				} else {
					baseVal = "test"
				}
			}

			for _, submitName := range []string{"Submit", "submit", "go", "Go"} {
				if _, ok := params[submitName]; !ok {
					params.Set(submitName, "Submit")
				}
			}

			if param == "ip" && strings.Contains(targetURL, "/vulnerabilities/exec/") {
				cfg.Method = "POST"
				params.Set("Submit", "Submit")
				baseVal = "127.0.0.1"
			}

			if cfg.ScanRCE {
				printAlignedInfo(ColorCyan, fmt.Sprintf("[!] Scanning for Remote Code/Command Execution vulnerabilities in parameter '%s'...", param))
				rceFound := scanRCEMarker(cfg, param, baseVal, origVal, baseURL, params)
				if !rceFound {
					printAlignedInfo(ColorCyan, fmt.Sprintf("[!] No Remote Code/Command Execution vulnerabilities detected in parameter '%s'.", param))
				}
			}

			if cfg.ScanXSS {
				printAlignedInfo(ColorCyan, fmt.Sprintf("[!] Scanning for XSS vulnerabilities in parameter '%s'...", param))
				xssFound := scanXSS(cfg, param, baseVal, origVal, baseURL, params)
				if xssFound == 0 {
					printAlignedInfo(ColorCyan, fmt.Sprintf("[!] No XSS vulnerabilities detected in parameter '%s'.", param))
				} else {
					printAlignedInfo(ColorRed, fmt.Sprintf("[!] Congratulations! Found %d XSS bug(s) in parameter '%s'.", xssFound, param))
				}
			}

			if cfg.ScanSQLi {
				printAlignedInfo(ColorCyan, fmt.Sprintf("[!] Scanning for SQL Injection vulnerabilities in parameter '%s'...", param))
				sqliFound := scanSQLi(cfg, param, baseVal, origVal, baseURL, params)
				if sqliFound == 0 {
					printAlignedInfo(ColorCyan, fmt.Sprintf("[!] No SQL Injection vulnerabilities detected in parameter '%s'.", param))
				} else {
					printAlignedInfo(ColorRed, fmt.Sprintf("[!] Congratulations! Found %d SQL Injection bug(s) in parameter '%s'.", sqliFound, param))
				}

				if scanBooleanSQLi(cfg, param, baseVal, origVal, baseURL, params) {
					printAlignedInfo(ColorRed, fmt.Sprintf("[!] Boolean-based SQL Injection detected in parameter '%s'.", param))
				} else {
					printAlignedInfo(ColorCyan, fmt.Sprintf("[!] No Boolean-based SQL Injection detected in parameter '%s'.", param))
				}
			}

			if cfg.ScanLFI {
				printAlignedInfo(ColorCyan, fmt.Sprintf("[!] Scanning for Local/Remote File Inclusion vulnerabilities in parameter '%s'...", param))
				lfiFound := scanLFI(cfg, param, baseVal, origVal, baseURL, params)
				if lfiFound == 0 {
					printAlignedInfo(ColorCyan, fmt.Sprintf("[!] No Local/Remote File Inclusion vulnerabilities detected in parameter '%s'.", param))
				} else {
					printAlignedInfo(ColorRed, fmt.Sprintf("[!] Congratulations! Found %d LFI/RFI bug(s) in parameter '%s'.", lfiFound, param))
				}
			}

			if cfg.ScanPathTraversal {
				printAlignedInfo(ColorCyan, fmt.Sprintf("[!] Scanning for Path Traversal vulnerabilities in parameter '%s'...", param))
				ptFound := scanPathTraversal(cfg, param, baseVal, origVal, baseURL, params)
				if ptFound == 0 {
					printAlignedInfo(ColorCyan, fmt.Sprintf("[!] No Path Traversal vulnerabilities detected in parameter '%s'.", param))
				} else {
					printAlignedInfo(ColorRed, fmt.Sprintf("[!] Congratulations! Found %d Path Traversal bug(s) in parameter '%s'.", ptFound, param))
				}
			}

			if cfg.ScanCSRF {
				printAlignedInfo(ColorCyan, fmt.Sprintf("[!] Scanning for CSRF vulnerabilities in parameter '%s'...", param))
				csrfFound := scanCSRF(cfg, targetURL, param, baseVal, origVal, baseURL, params)
				if csrfFound == 0 {
					printAlignedInfo(ColorCyan, fmt.Sprintf("[!] No CSRF vulnerabilities detected in parameter '%s'.", param))
				} else {
					printAlignedInfo(ColorRed, fmt.Sprintf("[!] Possible CSRF risk detected in parameter '%s'.", param))
				}
			}

			if cfg.ScanOpenRedirect {
				redirectParams := []string{"url", "next", "redirect", "return", "dest", "destination", "continue"}
				openRedirectParam := false
				for _, rParam := range redirectParams {
					if strings.EqualFold(param, rParam) {
						openRedirectParam = true
						break
					}
				}
				if openRedirectParam {
					printAlignedInfo(ColorCyan, fmt.Sprintf("[!] Scanning for Open Redirect vulnerabilities in parameter '%s'...", param))
					found := scanOpenRedirect(cfg, param, baseVal, origVal, baseURL, params)
					if !found {
						printAlignedInfo(ColorCyan, fmt.Sprintf("[!] No Open Redirect vulnerabilities detected in parameter '%s'.", param))
					}
				} else {
					printAlignedInfo(ColorCyan, fmt.Sprintf("[!] Skipping Open Redirect scan for parameter '%s' (not a typical redirect parameter).", param))
				}
			}
		}
	}
}

// Helper: extracts host from URL for pretty output
func extractHost(fullURL string) string {
	u, err := url.Parse(fullURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// Prints a message with [!] left-aligned and rest of line starting at column 6, with color
func printAlignedInfo(color, msg string) {
	const prefix = "[!]"
	const padTo = 6 // space after [!]
	// Remove any existing prefix
	if strings.HasPrefix(msg, prefix) {
		msg = msg[len(prefix):]
	}
	// Remove any leading spaces
	msg = strings.TrimLeft(msg, " ")
	fmt.Printf("%s[!]%s%s%s\n", color, strings.Repeat(" ", padTo-len(prefix)), msg, ColorReset)
}

// Boxed section function for the scanning URL, Unicode box + ellipsis if needed
func printBoxedSection(title string) {
	maxLen := 78
	ellipsis := "..."
	titleLen := utf8.RuneCountInString(title)
	displayTitle := title
	if titleLen > maxLen {
		runes := []rune(title)
		displayTitle = string(runes[:maxLen-len(ellipsis)]) + ellipsis
		titleLen = utf8.RuneCountInString(displayTitle)
	}
	padding := (maxLen - titleLen) / 2
	rightPadding := maxLen - titleLen - padding
	fmt.Println(ColorCyan + "╭──────────────────────────────────────────────────────────────────────────────╮" + ColorReset)
	fmt.Print(ColorCyan + "│" + ColorReset)
	fmt.Print(strings.Repeat(" ", padding))
	fmt.Print(displayTitle)
	fmt.Print(strings.Repeat(" ", rightPadding))
	fmt.Println(ColorCyan + "│" + ColorReset)
	fmt.Println(ColorCyan + "╰──────────────────────────────────────────────────────────────────────────────╯" + ColorReset)
}