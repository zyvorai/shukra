package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// policyCmd is `shukractl policy`: which networks each VM may start connections to. Bare it lists the policies;
// learn proposes one from a VM's baseline; apply, confirm and remove change one.
func policyCmd(args []string, out io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "learn":
			return policyLearn(args[1:], out)
		case "apply":
			return policyApply(args[1:], out)
		case "confirm", "remove":
			return policyChange(args[0], args[1:], out)
		}
	}
	path := "/api/v1/policy"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		path += "?vm=" + url.QueryEscape(args[0])
	}
	return getBoard(out, path, has(args, "--json"), formatPolicies)
}

// vmArg is the VM a subcommand names: its first argument, which must not be a flag.
func vmArg(sub string, args []string) (string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", fmt.Errorf("policy %s <vm>", sub)
	}
	return args[0], nil
}

func policyLearn(args []string, out io.Writer) error {
	vm, err := vmArg("learn", args)
	if err != nil {
		return err
	}
	return getBoard(out, "/api/v1/policy/proposal?vm="+url.QueryEscape(vm), has(args, "--json"), formatProposal)
}

func policyApply(args []string, out io.Writer) error {
	vm, err := vmArg("apply", args)
	if err != nil {
		return fmt.Errorf("policy apply <vm> --mode audit|enforce [--allow a,b,c | --from-baseline] [--confirm 5m | --permanent]")
	}
	rest := args[1:]
	req := map[string]any{"vm": vm, "mode": flagValue(rest, "--mode", "")}
	if req["mode"] == "" {
		return fmt.Errorf("policy apply %s: --mode audit, enforce or off is required (audit first: it drops nothing)", vm)
	}
	if v := flagValue(rest, "--allow", ""); v != "" {
		var allow []string
		for _, a := range strings.Split(v, ",") {
			if a = strings.TrimSpace(a); a != "" {
				allow = append(allow, a)
			}
		}
		req["allow"] = allow
	}
	if has(rest, "--from-baseline") {
		req["fromBaseline"] = true
	}
	if v := flagValue(rest, "--confirm", ""); v != "" {
		req["confirm"] = v
	}
	if has(rest, "--permanent") {
		req["permanent"] = true
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return printPolicyRow(out, "POST", "/api/v1/policy/apply", body, has(rest, "--json"), "applied")
}

func policyChange(verb string, args []string, out io.Writer) error {
	vm, err := vmArg(verb, args)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"vm": vm})
	if err != nil {
		return err
	}
	done := "confirmed"
	if verb == "remove" {
		done = "removed"
	}
	return printPolicyRow(out, "POST", "/api/v1/policy/"+verb, body, has(args[1:], "--json"), done)
}

func printPolicyRow(out io.Writer, method, path string, body []byte, asJSON bool, done string) error {
	b, _, err := do(method, path, body)
	if err != nil {
		return err
	}
	if asJSON {
		_, err := out.Write(b)
		return err
	}
	m, err := decode(b)
	if err != nil {
		return err
	}
	row, _ := m["policy"].(map[string]any)
	if str(row, "mode") == "off" {
		fmt.Fprintf(out, "%s: the egress policy is %s. Nothing is judged on its taps now.\n", str(row, "vm"), done)
	} else {
		fmt.Fprintf(out, "%s: egress policy %s\n", str(row, "vm"), done)
		writePolicyRow(out, row)
	}
	if p := str(row, "problem"); p != "" {
		fmt.Fprintf(out, "  PROBLEM  %s\n", p)
	}
	return nil
}

func formatPolicies(w io.Writer, m map[string]any) {
	if enabled, _ := m["enabled"].(bool); !enabled {
		fmt.Fprintln(w, "EGRESS POLICY  not available: this build has no egress policy engine")
		return
	}
	rows := list(m, "policies")
	fmt.Fprintf(w, "EGRESS POLICY  %d VMs", len(rows))
	if p, _ := m["persisted"].(bool); !p {
		fmt.Fprint(w, "  (audit only: enforcing needs -data-dir, so that the record survives a restart)")
	}
	fmt.Fprintln(w)
	if len(rows) == 0 {
		fmt.Fprintln(w, "  none. shukractl policy learn <vm> proposes one from what the VM has been seen to do; audit it before enforcing")
	}
	for _, r := range rows {
		writePolicyRow(w, r)
	}
	for _, o := range list(m, "orphans") {
		fmt.Fprintf(w, "  ORPHAN  %s (%s) is %s: the kernel applies a policy nobody has a record of. shukractl policy remove %s\n", str(o, "vm"), str(o, "tap"), str(o, "mode"), str(o, "vm"))
	}
}

func writePolicyRow(w io.Writer, r map[string]any) {
	allow, _ := r["allow"].([]any)
	present := ""
	if p, _ := r["present"].(bool); !p {
		present = "  (VM not running)"
	}
	fmt.Fprintf(w, "  %s  %s  %d networks (%s), set by %s at %s%s\n", str(r, "vm"), str(r, "mode"), len(allow), str(r, "source"), str(r, "by"), str(r, "applied"), present)
	if rv, ok := r["revert"].(map[string]any); ok {
		fmt.Fprintf(w, "      UNCONFIRMED: goes back to %s at %s unless confirmed: shukractl policy confirm %s\n", str(rv, "to"), str(rv, "until"), str(r, "vm"))
	}
	for _, t := range list(r, "taps") {
		fmt.Fprintf(w, "      %s  kernel %s  judged %s new connections", str(t, "tap"), str(t, "kernel"), num(t, "checked"))
		if n := num(t, "auditPackets"); n != "0" {
			fmt.Fprintf(w, ", %s would have been dropped (%s bytes)", n, num(t, "auditBytes"))
		}
		if n := num(t, "droppedPackets"); n != "0" {
			fmt.Fprintf(w, ", %s dropped (%s bytes)", n, num(t, "droppedBytes"))
		}
		fmt.Fprintln(w)
	}
	if p := str(r, "problem"); p != "" {
		fmt.Fprintf(w, "      PROBLEM  %s\n", p)
	}
}

func formatProposal(w io.Writer, m map[string]any) {
	allow, _ := m["allow"].([]any)
	fmt.Fprintf(w, "POLICY PROPOSAL  %s  %d networks", str(m, "vm"), len(allow))
	if l, _ := m["learning"].(bool); l {
		fmt.Fprint(w, "  (still learning: it may be incomplete)")
	}
	fmt.Fprintln(w)
	if n := str(m, "note"); n != "" {
		fmt.Fprintf(w, "  %s\n", n)
	}
	for _, a := range allow {
		fmt.Fprintf(w, "    %v\n", a)
	}
	if cur, _ := m["current"].([]any); len(cur) > 0 || len(list(m, "added")) > 0 {
		for _, k := range []string{"added", "removed"} {
			xs, _ := m[k].([]any)
			for _, x := range xs {
				sign := "+"
				if k == "removed" {
					sign = "-"
				}
				fmt.Fprintf(w, "    %s %v  (against its current policy)\n", sign, x)
			}
		}
	}
	fmt.Fprintf(w, "  audit it first: shukractl policy apply %s --mode audit --from-baseline\n", str(m, "vm"))
}
