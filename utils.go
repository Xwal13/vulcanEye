package main

import (
	"fmt"
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