package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/zyvorai/shukra/internal/detect"
)

// rulesCmd is `shukractl rules check <file>`. It runs the daemon's own strict
// parser on a file without touching a daemon, so an edit can be tested before
// `systemctl reload shukra`. It exits non-zero when the file would be refused.
func rulesCmd(args []string, out io.Writer) error {
	if len(args) < 2 || args[0] != "check" {
		return fmt.Errorf("rules check <file> [--json]")
	}
	b, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	c, err := detect.Parse(b)
	if err != nil {
		if has(args[2:], "--json") {
			_ = json.NewEncoder(out).Encode(map[string]any{"ok": false, "error": err.Error()})
		}
		return fmt.Errorf("%s: %w", args[1], err)
	}
	names := func(n int, get func(int) string) []string {
		var s []string
		for i := 0; i < n; i++ {
			s = append(s, get(i))
		}
		return s
	}
	sum := map[string]any{
		"ok":         true,
		"suppress":   c.Suppress.String(),
		"ports":      names(len(c.Ports), func(i int) string { return c.Ports[i].Name }),
		"execAllow":  c.ExecAllow,
		"thresholds": names(len(c.Thresholds), func(i int) string { return c.Thresholds[i].Name }),
		"maxWindow":  c.MaxWindow().String(),
	}
	if has(args[2:], "--json") {
		return json.NewEncoder(out).Encode(sum)
	}
	fmt.Fprintf(out, "ok: %s would be accepted\n", args[1])
	fmt.Fprintf(out, "  suppress   %s\n", c.Suppress)
	fmt.Fprintf(out, "  ports      %s\n", listOrNone(sum["ports"].([]string)))
	fmt.Fprintf(out, "  exec_allow %s\n", listOrNone(c.ExecAllow))
	fmt.Fprintf(out, "  thresholds %s\n", listOrNone(sum["thresholds"].([]string)))
	if len(c.Thresholds) > 0 {
		fmt.Fprintln(out, "  thresholds need the kernel programs attached, and stay quiet until a full window of history exists")
	}
	return nil
}

func listOrNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}
