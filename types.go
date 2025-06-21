package main

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorPurple = "\033[35m"
	ColorBlue   = "\033[94m"
	ColorBold   = "\033[1m"
	ColorWhite  = "\033[97m"
)

type ScanConfig struct {
	URL               string
	Method            string
	InjectParam       string
	Cookie            string
	OutputFile        string
	Debug             bool
	CrawlLevel        int

	// Flags for per-bug scanning
	ScanXSS           bool
	ScanSQLi          bool
	ScanLFI           bool
	ScanRCE           bool
	ScanOpenRedirect  bool
	ScanPathTraversal bool
	ScanCSRF          bool
}

type UploadForm struct {
	Action      string
	Method      string
	FileField   string
	OtherFields map[string]string
}