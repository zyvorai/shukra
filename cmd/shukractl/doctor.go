package main

import (
	"encoding/json"
	"fmt"
	"io"
)

// doctorCmd audits the running daemon: how it is exposed, what is attached, what
// it cannot see, and what is not kept. It only reads. Exit status is non-zero when
// anything failed, and with --strict when anything warned too, so it can gate a
// deploy.
func doctorCmd(args []string, out io.Writer) error {
	b, _, err := do("GET", "/api/v1/doctor", nil)
	if err != nil {
		return err
	}
	if has(args, "--json") {
		if _, werr := out.Write(append(b, '\n')); werr != nil {
			return werr
		}
	}
	var body struct {
		Worst  string `json:"worst"`
		Checks []struct {
			ID, Status, Title, Detail, Fix string
		} `json:"checks"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		return err
	}
	if !has(args, "--json") {
		mark := map[string]string{"ok": "[ ok ]", "info": "[info]", "warn": "[warn]", "fail": "[FAIL]"}
		var ok int
		for _, c := range body.Checks {
			if c.Status == "ok" {
				ok++
				continue
			}
			fmt.Fprintf(out, "%s %s\n", mark[c.Status], c.Title)
			if c.Detail != "" {
				fmt.Fprintf(out, "       %s\n", c.Detail)
			}
			if c.Fix != "" {
				fmt.Fprintf(out, "       fix: %s\n", c.Fix)
			}
		}
		fmt.Fprintf(out, "%d checks passed, %d need attention (worst: %s)\n", ok, len(body.Checks)-ok, body.Worst)
	}
	switch {
	case body.Worst == "fail":
		return fmt.Errorf("doctor found a failure")
	case body.Worst == "warn" && has(args, "--strict"):
		return fmt.Errorf("doctor found a warning (--strict)")
	}
	return nil
}
