# VulcanEye

**VulcanEye** is a fast, user-friendly web vulnerability scanner for penetration testers and bug bounty hunters.  
It automates the detection of common web application security issues—like XSS, SQLi, LFI, RCE, Open Redirect, Path Traversal, and CSRF—across URLs and page parameters.

## Features

- 🚀 **Blazing fast** scanning with automatic crawling and parameter detection
- 🔎 **Detects**:  
  - Cross-Site Scripting (XSS)  
  - SQL Injection (SQLi)  
  - Local File Inclusion (LFI)  
  - Remote Code Execution (RCE)  
  - Open Redirect  
  - Path Traversal  
  - Cross-Site Request Forgery (CSRF)
- 🕵️ **Crawls** target sites to discover endpoints and forms
- 🪝 **Auto-detects injectable parameters** in forms and URLs
- 🍪 **Supports authenticated scans** (via cookies)
- 📝 **Optional output to file**
- 🐞 **Debug mode** for detailed analysis
- 👨‍💻 **Built in Go** — runs anywhere, easy to install

## Installation

With Go 1.20+:

```sh
go install github.com/Xwal13/VulcanEye@latest
```

Make sure `$GOPATH/bin` or `$HOME/go/bin` is in your `$PATH`.

## Usage

```sh
VulcanEye -u <url> [options]
```

### Main options

- `-u` : Target URL (required)
- `-m` : HTTP method (GET or POST, default: GET)
- `-p` : Parameter to inject (auto-detects if omitted)
- `--cookie` : Cookie header for authenticated scans
- `-o` : Output file for results
- `-d` : Enable debug mode
- `--crawl` : Crawl depth (default: 1)

### Vulnerability flags

- `-x` : Scan for XSS
- `-s` : Scan for SQLi
- `-l` : Scan for LFI
- `-r` : Scan for RCE
- `--or` : Scan for Open Redirect
- `--pt` : Scan for Path Traversal
- `--csrf` : Scan for CSRF

### Examples

```sh
VulcanEye -u "http://site.com/search.php?test=1" -x
VulcanEye -u "http://site.com/" -m POST --cookie "PHPSESSID=xyz"
VulcanEye -u "http://site.com/" -s -l
VulcanEye -u "http://site.com/profile" --csrf
VulcanEye -u "http://site.com/" -o results.txt
```

If no scan flags are specified, **all vulnerability scans are performed by default**.

---

## Credits

Developed by [Xwal13](https://github.com/Xwal13)

---

**Disclaimer:** Use only against systems you have permission to test.  
Illegal or unauthorized usage is strictly prohibited.
