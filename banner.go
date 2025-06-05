package main

import (
  "fmt"
  "net/url"
)

var BANNER = `
 Y88b      /          888                            888~~                    
 Y88b    /  888  888 888  e88~~\   /~~~8e  888-~88e 888___ Y88b  /  e88~~8e  
  Y88b  /   888  888 888 d888          88b 888  888 888     Y888/  d888  88b 
   Y888/    888  888 888 8888     e88~-888 888  888 888      Y8/   8888__888 
    Y8/     888  888 888 Y888    C888  888 888  888 888       Y    Y888    , 
     Y      "88_-888 888  "88__/  "88_-888 888  888 888___   /      "88___/  
                                                           _/                

             VulcanEye - Web Vulnerability Scanner
                      by Xwal13
`

func printBanner() {
  fmt.Println(BANNER)
}

func printUsage() {
  printBanner()
  fmt.Println(`Usage: VulcanEye -u <url> [options]

Options:
  -u string
        Target URL to scan (required)
  -m string
        HTTP method (GET or POST) (default "GET")
  -p string
        Parameter name to inject (if omitted, will auto-detect all)
  --cookie string
        Cookie header to use for authenticated scans
  -o string
        Output file to save the results
  -d
        Enable debug mode
  --crawl int
        Crawl level (default 1, higher = deeper crawl)

  -x
        Scan for Cross-Site Scripting (XSS)
  -s
        Scan for SQL Injection (SQLi)
  -l
        Scan for Local File Inclusion (LFI)
  -r
        Scan for Remote Code Execution (RCE)
  --or
        Scan for Open Redirect
  --pt
        Scan for Path Traversal
  --csrf
        Scan for Cross-Site Request Forgery (CSRF)

Examples:
  VulcanEye -u "http://127.0.0.1:8081/vulnerabilities/xss_r/"
  VulcanEye -u "http://site.com/search.php?test=1" -m GET
  VulcanEye -u "http://site.com/" -m POST --cookie "PHPSESSID=...; security=low"
  VulcanEye -u "http://site.com/search.php" -x           # Only scan for XSS
  VulcanEye -u "http://site.com/search.php" -s -l        # Only scan for SQLi and LFI
  VulcanEye -u "http://site.com/file?name=foo" --pt      # Only scan for Path Traversal
  VulcanEye -u "http://site.com/profile" --csrf          # Only scan for CSRF

If you do not specify '-p', VulcanEye will auto-detect parameters in forms and links.

If you do not specify any vulnerability scan flags, all vulnerability scans are performed by default.
`)
}

func scanBackendInfo(cfg *ScanConfig) {
  fmt.Println(" [!] Fingerprinting backend Technologies.")
  _, headers, err := fetchURL(cfg, cfg.URL, "GET", nil, nil)
  if err != nil {
    fmt.Printf("%s [!] Error fetching URL: %v%s\n", ColorRed, err, ColorReset)
    return
  }
  u, _ := url.Parse(cfg.URL)
  fmt.Printf(" [!] Host: %s\n", u.Host)
  fmt.Printf(" [!] WebServer: %s\n", headers.Get("Server"))
  if xpb := headers.Get("X-Powered-By"); xpb != "" {
    fmt.Printf(" [!] X-Powered-By: %s\n", xpb)
  }
}