package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	zyvorOrange = "\033[38;2;241;90;41m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiCyan    = "\033[36m"
	ansiGreen   = "\033[32m"
	resetColor  = "\033[0m"
)

func useColor(w *os.File) bool {
	if w == nil {
		return false
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if v := strings.TrimSpace(os.Getenv("SHUKRA_CLI_COLOR")); v != "" {
		return !strings.EqualFold(v, "false") && v != "0"
	}
	return isTTY(w)
}

func colorize(w *os.File, code, s string) string {
	if !useColor(w) {
		return s
	}
	return code + s + resetColor
}

func printBanner(w *os.File) {
	if w == nil {
		return
	}
	logo := []string{
		` ____  _           _              `,
		`/ ___|| |__  _   _| | ___ __ __ _ `,
		`\___ \| '_ \| | | | |/ / '__/ _' |`,
		` ___) | | | | |_| |   <| | | (_| |`,
		`|____/|_| |_|\__,_|_|\_\_|  \__,_|`,
	}
	if useColor(w) {
		fmt.Fprint(w, zyvorOrange)
	}
	for _, line := range logo {
		fmt.Fprintln(w, line)
	}
	if useColor(w) {
		fmt.Fprint(w, resetColor)
	}
	fmt.Fprintln(w, "  Shukra · Zyvor")
	fmt.Fprintln(w, "  eBPF-powered runtime intelligence and security for KVM")
	fmt.Fprintln(w, "  observe · protect · explain")
	fmt.Fprintln(w)
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func bannerEnabled() bool {
	return os.Getenv("SHUKRA_CLI_NO_BANNER") == ""
}
