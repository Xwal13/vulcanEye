package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
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
	fmt.Printf("\n%s==================================================%s\nScanning URL: %s\n%s==================================================%s\n\n", ColorPurple, ColorReset, cfg.URL, ColorPurple, ColorReset)

	scanBackendInfo(cfg)

	fmt.Printf("%s[!] Crawling with level %d...%s\n", ColorCyan, cfg.CrawlLevel, ColorReset)
	urls := crawlSite(cfg, cfg.URL, cfg.CrawlLevel)
	fmt.Printf("%s[!] Crawled %d URLs:%s\n", ColorGreen, len(urls), ColorReset)
	for _, u := range urls {
		fmt.Printf(" - %s\n", u)
	}
	fmt.Println()

	for _, targetURL := range urls {
		fmt.Printf("%s[!] Scanning page: %s%s\n", ColorPurple, targetURL, ColorReset)
		pageBody, _, err := fetchURL(cfg, targetURL, "GET", nil, nil)
		if err != nil {
			fmt.Printf("%s[!] Could not fetch page: %v%s\n", ColorRed, err, ColorReset)
			continue
		}
		paramList, _, _ := extractParamNamesFromHTML(pageBody, cfg.Method)
		uploadForms := findFileUploadForms(pageBody)
		if cfg.Debug {
			for _, f := range uploadForms {
				fmt.Printf("[DEBUG] Upload form found: action=%q method=%q fileField=%q otherFields=%v\n", f.Action, f.Method, f.FileField, f.OtherFields)
			}
		}
		// File upload scanning
		scanFileUploadForms(cfg, targetURL, uploadForms)

		if cfg.InjectParam != "" {
			paramList = []string{cfg.InjectParam}
		}
		if len(paramList) == 0 {
			fmt.Printf("%s[!] No injectable parameters found on page.%s\n", ColorRed, ColorReset)
			continue
		}
		fmt.Printf("%s[!] Auto-detected parameters: %v%s\n", ColorGreen, paramList, ColorReset)

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
				fmt.Printf("%s[!] Scanning for Remote Code/Command Execution vulnerabilities in parameter '%s'...%s\n", ColorCyan, param, ColorReset)
				rceFound := scanRCEMarker(cfg, param, baseVal, origVal, baseURL, params)
				if !rceFound {
					fmt.Printf("%s[!] No Remote Code/Command Execution vulnerabilities detected in parameter '%s'.%s\n", ColorGreen, param, ColorReset)
				}
			}

			if cfg.ScanXSS {
				fmt.Printf("%s[!] Scanning for XSS vulnerabilities in parameter '%s'...%s\n", ColorCyan, param, ColorReset)
				xssFound := scanXSS(cfg, param, baseVal, origVal, baseURL, params)
				if xssFound == 0 {
					fmt.Printf("%s[!] No XSS vulnerabilities detected in parameter '%s'.%s\n", ColorGreen, param, ColorReset)
				} else {
					fmt.Printf("%s[!] Congratulations! Found %d XSS bug(s) in parameter '%s'.%s\n", ColorRed, xssFound, param, ColorReset)
				}
			}

			if cfg.ScanSQLi {
				fmt.Printf("%s[!] Scanning for SQL Injection vulnerabilities in parameter '%s'...%s\n", ColorCyan, param, ColorReset)
				sqliFound := scanSQLi(cfg, param, baseVal, origVal, baseURL, params)
				if sqliFound == 0 {
					fmt.Printf("%s[!] No SQL Injection vulnerabilities detected in parameter '%s'.%s\n", ColorGreen, param, ColorReset)
				} else {
					fmt.Printf("%s[!] Congratulations! Found %d SQL Injection bug(s) in parameter '%s'.%s\n", ColorRed, sqliFound, param, ColorReset)
				}

				if scanBooleanSQLi(cfg, param, baseVal, origVal, baseURL, params) {
					fmt.Printf("%s[!] Boolean-based SQL Injection detected in parameter '%s'.%s\n", ColorRed, param, ColorReset)
				} else {
					fmt.Printf("%s[!] No Boolean-based SQL Injection detected in parameter '%s'.%s\n", ColorGreen, param, ColorReset)
				}
			}

			if cfg.ScanLFI {
				fmt.Printf("%s[!] Scanning for Local/Remote File Inclusion vulnerabilities in parameter '%s'...%s\n", ColorCyan, param, ColorReset)
				lfiFound := scanLFI(cfg, param, baseVal, origVal, baseURL, params)
				if lfiFound == 0 {
					fmt.Printf("%s[!] No Local/Remote File Inclusion vulnerabilities detected in parameter '%s'.%s\n", ColorGreen, param, ColorReset)
				} else {
					fmt.Printf("%s[!] Congratulations! Found %d LFI/RFI bug(s) in parameter '%s'.%s\n", ColorRed, lfiFound, param, ColorReset)
				}
			}

			if cfg.ScanPathTraversal {
				fmt.Printf("%s[!] Scanning for Path Traversal vulnerabilities in parameter '%s'...%s\n", ColorCyan, param, ColorReset)
				ptFound := scanPathTraversal(cfg, param, baseVal, origVal, baseURL, params)
				if ptFound == 0 {
					fmt.Printf("%s[!] No Path Traversal vulnerabilities detected in parameter '%s'.%s\n", ColorGreen, param, ColorReset)
				} else {
					fmt.Printf("%s[!] Congratulations! Found %d Path Traversal bug(s) in parameter '%s'.%s\n", ColorRed, ptFound, param, ColorReset)
				}
			}

			if cfg.ScanCSRF {
				fmt.Printf("%s[!] Scanning for CSRF vulnerabilities in parameter '%s'...%s\n", ColorCyan, param, ColorReset)
				csrfFound := scanCSRF(cfg, targetURL, param, baseVal, origVal, baseURL, params)
				if csrfFound == 0 {
					fmt.Printf("%s[!] No CSRF vulnerabilities detected in parameter '%s'.%s\n", ColorGreen, param, ColorReset)
				} else {
					fmt.Printf("%s[!] Possible CSRF risk detected in parameter '%s'.%s\n", ColorRed, param, ColorReset)
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
					fmt.Printf("%s[!] Scanning for Open Redirect vulnerabilities in parameter '%s'...%s\n", ColorCyan, param, ColorReset)
					found := scanOpenRedirect(cfg, param, baseVal, origVal, baseURL, params)
					if !found {
						fmt.Printf("%s[!] No Open Redirect vulnerabilities detected in parameter '%s'.%s\n", ColorGreen, param, ColorReset)
					}
				} else {
					fmt.Printf("%s[!] Skipping Open Redirect scan for parameter '%s' (not a typical redirect parameter).%s\n", ColorYellow, param, ColorReset)
				}
			}
		}
	}
}