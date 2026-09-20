package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zyvorai/shukra/internal/version"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	loadConfig()
	if len(args) > 0 && (args[0] == "version" || args[0] == "--version") {
		fmt.Fprintf(out, "shukractl %s\n", version.Version)
		return nil
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(out)
		return nil
	}
	switch args[0] {
	case "status":
		return statusCmd(args[1:], out)
	case "programs":
		return getBoard(out, "/api/v1/programs", has(args[1:], "--json"), formatPrograms)
	case "trace":
		return traceCmd(args[1:], out)
	case "vms":
		return getBoard(out, "/api/v1/vms", has(args[1:], "--json"), formatVMs)
	case "explain":
		if len(args) < 2 {
			return fmt.Errorf("explain <vm>")
		}
		path := "/api/v1/explain?vm=" + args[1]
		if w := flagValue(args[2:], "--window", ""); w != "" {
			path += "&window=" + w
		}
		return getBoard(out, path, has(args[2:], "--json"), formatExplain)
	case "recorder":
		if len(args) < 2 {
			return fmt.Errorf("recorder <vm> [--window 60s]")
		}
		window := flagValue(args[2:], "--window", "60s")
		return getBoard(out, "/api/v1/recorder?vm="+args[1]+"&window="+window, has(args[2:], "--json"), formatRecorder)
	case "watch":
		return watchCmd(args[1:], out)
	case "export":
		return getBoard(out, "/api/v1/export", true, nil)
	case "security":
		if len(args) < 2 {
			return fmt.Errorf("security <vm>")
		}
		return getBoard(out, "/api/v1/security?vm="+args[1], has(args[2:], "--json"), formatSecurity)
	case "isolate":
		if len(args) < 2 {
			return fmt.Errorf("isolate <vm>")
		}
		return actCmd("isolate", args[1], has(args[2:], "--json"), out)
	case "release":
		if len(args) < 2 {
			return fmt.Errorf("release <vm>")
		}
		return actCmd("release", args[1], has(args[2:], "--json"), out)
	case "rules":
		return rulesCmd(args[1:], out)
	case "doctor":
		return doctorCmd(args[1:], out)
	case "install-cli":
		return installCLI(args[1:], out)
	default:
		return fmt.Errorf("unknown command %q (try: shukractl --help)", args[0])
	}
}

func has(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func flagValue(args []string, name, def string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return def
}

func getBoard(out io.Writer, path string, asJSON bool, human func(io.Writer, map[string]any)) error {
	b, _, err := do("GET", path, nil)
	if err != nil {
		return err
	}
	if asJSON {
		var pretty bytesPretty
		return pretty.write(out, b)
	}
	m, err := decode(b)
	if err != nil {
		return err
	}
	human(out, m)
	return nil
}

type bytesPretty struct{}

func (bytesPretty) write(out io.Writer, b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func statusCmd(args []string, out io.Writer) error {
	asJSON := has(args, "--json")
	wait := has(args, "--wait")
	deadline := time.Now().Add(2 * time.Minute)
	for {
		b, _, err := do("GET", "/api/v1/status", nil)
		if err != nil {
			if !wait || time.Now().After(deadline) {
				return err
			}
			fmt.Fprintf(os.Stderr, "waiting for shukrad: %v\n", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if asJSON {
			return (bytesPretty{}).write(out, b)
		}
		m, err := decode(b)
		if err != nil {
			return err
		}
		formatStatus(out, m)
		return nil
	}
}

func traceCmd(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "list" {
		return getBoard(out, "/api/v1/programs", has(args, "--json"), formatTraceList)
	}
	kind := args[0]
	switch kind {
	case "kvm", "sched", "block", "net", "tap", "drops":
	default:
		return fmt.Errorf("trace kvm|sched|block|net|tap|drops")
	}
	vm := flagValue(args[1:], "--vm", "")
	path := "/api/v1/trace/" + kind
	if vm != "" {
		path += "?vm=" + vm
	}
	return getBoard(out, path, has(args[1:], "--json"), func(w io.Writer, m map[string]any) {
		if kind == "drops" {
			formatDrops(w, m)
			return
		}
		formatTrace(w, kind, m)
	})
}

func watchCmd(args []string, out io.Writer) error {
	asJSON := has(args, "--json")
	if has(args, "--once") {
		_, err := watchPoll(0, asJSON, out)
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return watchLoop(ctx, out, asJSON, time.Second)
}

// watchLoop follows events until ctx ends. It streams from the daemon and, before
// every (re)connect, polls once with the last seq it saw. That poll fills any gap
// and notices a daemon that restarted with lower seqs, which a stream cursor
// alone would wait on forever. A daemon with no stream endpoint is polled instead.
func watchLoop(ctx context.Context, out io.Writer, asJSON bool, retry time.Duration) error {
	var since uint64
	streaming := true
	for ctx.Err() == nil {
		var err error
		if since, err = watchPoll(since, asJSON, out); err != nil {
			return err
		}
		if streaming {
			var unsupported bool
			since, unsupported, err = watchStream(ctx, since, asJSON, out)
			if unsupported {
				streaming = false
			} else if err != nil && ctx.Err() == nil && errors.Is(err, errUnauthorized) {
				return err
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(retry):
		}
	}
	return nil
}

var errUnauthorized = errors.New("the daemon rejected the API key")

// streamClient has no overall timeout: a stream is meant to stay open.
func streamClient() *http.Client {
	c := httpClient()
	return &http.Client{Transport: c.Transport}
}

// watchStream reads /api/v1/stream until it ends. unsupported is true when the
// daemon has no such endpoint, so the caller should fall back to polling.
func watchStream(ctx context.Context, since uint64, asJSON bool, out io.Writer) (uint64, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/stream", nil)
	if err != nil {
		return since, false, err
	}
	if key := os.Getenv("SHUKRA_API_KEY"); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Last-Event-ID", strconv.FormatUint(since, 10))
	resp, err := streamClient().Do(req)
	if err != nil {
		return since, false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return since, true, nil
	case http.StatusUnauthorized:
		return since, false, errUnauthorized
	default:
		return since, false, fmt.Errorf("stream: status %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var data string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		case line == "" && data != "":
			var e map[string]any
			if json.Unmarshal([]byte(data), &e) == nil {
				if seq, ok := e["seq"].(float64); ok && uint64(seq) > since {
					since = uint64(seq)
				}
				if err := printEvent(e, asJSON, out); err != nil {
					return since, false, err
				}
			}
			data = ""
		}
	}
	return since, false, sc.Err()
}

func printEvent(e map[string]any, asJSON bool, out io.Writer) error {
	if asJSON {
		return json.NewEncoder(out).Encode(e)
	}
	extra := ""
	if n, ok := e["dns_name"].(string); ok {
		extra = fmt.Sprintf("  name=%v  qtype=%v", n, e["qtype"])
	}
	_, err := fmt.Fprintf(out, "%v  %v  %v  vm=%v  dst=%v%s\n", e["ts"], e["kind"], e["attribution"], nested(e, "vm", "name"), e["dst"], extra)
	return err
}

// watchPoll prints the events newer than since and returns the new cursor.
func watchPoll(since uint64, asJSON bool, out io.Writer) (uint64, error) {
	b, _, err := do("GET", fmt.Sprintf("/api/v1/events?since=%d", since), nil)
	if err != nil {
		return since, err
	}
	var body struct {
		Seq    uint64           `json:"seq"`
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		return since, err
	}
	// A daemon that restarted without a data dir starts again from seq 0. Our
	// cursor is ahead of it, so start over rather than wait for it to catch up.
	if body.Seq < since {
		return 0, nil
	}
	for _, e := range body.Events {
		if seq, ok := e["seq"].(float64); ok && uint64(seq) > since {
			since = uint64(seq)
		}
		if err := printEvent(e, asJSON, out); err != nil {
			return since, err
		}
	}
	return since, nil
}

// actCmd asks the daemon to isolate or release a VM and prints what actually
// happened. "applied" is the daemon's word, set only after the kernel program took
// the change, so a refused or recorded-only request is never shown as done.
func actCmd(action, vm string, asJSON bool, out io.Writer) error {
	body, err := json.Marshal(map[string]string{"vm": vm})
	if err != nil {
		return err
	}
	b, _, err := do("POST", "/api/v1/"+action, body)
	if err != nil {
		return err
	}
	if asJSON {
		return (bytesPretty{}).write(out, b)
	}
	m, err := decode(b)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s  %s\n", strings.ToUpper(action), vm)
	fmt.Fprintf(out, "enforcement   %v\n", m["enforcement"])
	fmt.Fprintf(out, "applied       %v\n", m["applied"])
	if taps := stringsOf(m["taps"]); len(taps) > 0 {
		fmt.Fprintf(out, "taps          %s\n", strings.Join(taps, ", "))
	}
	fmt.Fprintf(out, "%v\n", m["reason"])
	if applied, _ := m["applied"].(bool); !applied && m["enforcement"] == "not_attached" {
		fmt.Fprintln(out, "no datapath change — enforcement is not attached")
	}
	return nil
}

func nested(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[k]
	}
	return cur
}

func str(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

func num(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case float64:
		return fmt.Sprintf("%.0f", v)
	case json.Number:
		return v.String()
	default:
		if v == nil {
			return "0"
		}
		return fmt.Sprint(v)
	}
}

func formatStatus(w io.Writer, m map[string]any) {
	fmt.Fprintln(w, "SHUKRA")
	fmt.Fprintf(w, "  product     %s\n", str(m, "product"))
	fmt.Fprintf(w, "  version     %s\n", str(m, "version"))
	fmt.Fprintf(w, "  tagline     %s\n", str(m, "tagline"))
	fmt.Fprintf(w, "  mode        %s\n", str(m, "mode"))
	fmt.Fprintf(w, "  vms         %s\n", num(m, "vms"))
	fmt.Fprintf(w, "  programs    %s/%s attached\n", num(m, "programsAttached"), num(m, "programsTotal"))
	fmt.Fprintf(w, "  detections  %s\n", num(m, "detections"))
	fmt.Fprintf(w, "  %s\n", str(m, "summary"))
}

func formatPrograms(w io.Writer, m map[string]any) {
	fmt.Fprintln(w, "PROGRAMS")
	for _, row := range list(m, "programs") {
		fmt.Fprintf(w, "  %-8s  %-10s  %s\n", str(row, "name"), str(row, "status"), str(row, "detail"))
	}
}

func formatTraceList(w io.Writer, m map[string]any) {
	fmt.Fprintln(w, "TRACE")
	fmt.Fprintln(w, "  kvm     kvm_exit kvm_entry kvm_mmio kvm_pio counters, not per-exit events")
	fmt.Fprintln(w, "  sched   sched_switch sched_wakeup exec: on-CPU time, run-queue delay, vCPU preemption")
	fmt.Fprintln(w, "  block   block_rq_issue/complete log2 histogram. p50/p99 in userspace")
	fmt.Fprintln(w, "  net     tcp_v4/v6_connect (exact) and sampled retransmits. QEMU process, not the guest")
	fmt.Fprintln(w, "  tap     TCX on each VM tap: the guest's own traffic, and isolation")
	fmt.Fprintln(w, "  drops   skb:kfree_skb on each VM tap: what the kernel dropped, why, and whether it was Shukra")
	fmt.Fprintln(w)
	formatPrograms(w, m)
}

func formatVMs(w io.Writer, m map[string]any) {
	fmt.Fprintln(w, "VMS")
	rows := list(m, "vms")
	if len(rows) == 0 {
		fmt.Fprintln(w, "  none — no qemu-system or FluxVM VMM process in the proc scan")
		return
	}
	for _, row := range rows {
		fmt.Fprintf(w, "  %s  runtime=%s  pid=%s  uuid=%s  taps=%s\n",
			str(row, "name"), str(row, "runtime"), num(row, "pid"), str(row, "uuid"), joinTaps(row["taps"]))
	}
}

func formatExplain(w io.Writer, m map[string]any) {
	fmt.Fprintf(w, "EXPLAIN  %s", str(m, "question"))
	if win := str(m, "window"); win != "" {
		fmt.Fprintf(w, "  (window: %s)", win)
	}
	fmt.Fprintln(w)
	if fs := list(m, "findings"); len(fs) > 0 {
		fmt.Fprintln(w, "findings (best supported first)")
		for _, f := range fs {
			fmt.Fprintf(w, "  [%s] %s: %s\n", str(f, "confidence"), str(f, "cause"), str(f, "summary"))
			for _, e := range stringsOf(f["evidence"]) {
				fmt.Fprintf(w, "      %s\n", e)
			}
		}
		if b := str(m, "basis"); b != "" {
			fmt.Fprintf(w, "  note: %s\n", b)
		}
	}
	fmt.Fprintln(w, "evidence")
	for _, e := range stringsOf(m["evidence"]) {
		fmt.Fprintf(w, "  %s\n", e)
	}
	fmt.Fprintln(w, "missing")
	for _, e := range stringsOf(m["missing"]) {
		fmt.Fprintf(w, "  %s\n", e)
	}
}

func formatRecorder(w io.Writer, m map[string]any) {
	fmt.Fprintf(w, "RECORDER  window=%s\n", str(m, "window"))
	rows := list(m, "events")
	if len(rows) == 0 {
		fmt.Fprintln(w, "  no events in this window")
		return
	}
	for _, e := range rows {
		fmt.Fprintf(w, "  %s  %s  %s\n", str(e, "ts"), str(e, "kind"), str(e, "message"))
	}
}

func formatSecurity(w io.Writer, m map[string]any) {
	fmt.Fprintf(w, "SECURITY  %s  enforcement=%s\n", str(m, "vm"), str(m, "enforcement"))
	if allow := stringsOf(m["allowList"]); len(allow) > 0 {
		fmt.Fprintf(w, "  management allow list: %s\n", strings.Join(allow, ", "))
	}
	if why := str(m, "reason"); why != "" {
		fmt.Fprintf(w, "  isolate is not enforced: %s\n", why)
	}
	rows := list(m, "detections")
	if len(rows) == 0 {
		fmt.Fprintln(w, "  no detections")
		return
	}
	for _, e := range rows {
		fmt.Fprintf(w, "  %s  %s  %s  guest_attributed=%v  attribution=%s\n", str(e, "severity"), str(e, "dst"), str(e, "message"), e["guest_attributed"], str(e, "attribution"))
	}
}

func formatTrace(w io.Writer, kind string, m map[string]any) {
	if note := str(m, "note"); note != "" {
		fmt.Fprintln(w, note)
	}
	fmt.Fprintf(w, "TRACE %s\n", strings.ToUpper(kind))
	rows := list(m, "rows")
	if len(rows) == 0 {
		fmt.Fprintln(w, "  no rows")
		return
	}
	for _, row := range rows {
		fmt.Fprintf(w, "  vm=%s", str(row, "vm"))
		switch kind {
		case "kvm":
			fmt.Fprintf(w, "  exits=%s  entries=%s  mmio=%s  pio=%s", num(row, "exits"), num(row, "entries"), num(row, "mmio"), num(row, "pio"))
		case "sched":
			fmt.Fprintf(w, "  oncpu_ns=%s  wakeup_ns=%s  wakeups=%s", num(row, "onCpuNs"), num(row, "wakeupDelayNs"), num(row, "wakeupCount"))
			if str(row, "vm") != "_host" { // the rest of the host has no vCPUs
				fmt.Fprintf(w, "\n      vCPU preempted: %sns over %s preemptions%s", num(row, "vcpuPreemptedNs"), num(row, "vcpuPreemptions"), preemptors(row))
			}
		case "block":
			fmt.Fprintf(w, "  issues=%s  read_p50=%s  read_p99=%s  write_p99=%s", num(row, "issues"), num(row, "readP50Ns"), num(row, "readP99Ns"), num(row, "writeP99Ns"))
		case "net":
			fmt.Fprintf(w, "  connects=%s  retransmits=%s  attribution=%s  guest_attributed=%v", num(row, "connects"), num(row, "retransmits"), str(row, "attribution"), row["guest_attributed"])
		case "tap":
			fmt.Fprintf(w, "  tap=%s  from_guest=%s B/%s pkts  to_guest=%s B/%s pkts  dropped=%s pkts  isolated=%v",
				str(row, "tap"), num(row, "fromGuestBytes"), num(row, "fromGuestPackets"), num(row, "toGuestBytes"), num(row, "toGuestPackets"), num(row, "droppedPackets"), row["isolated"])
			fmt.Fprintf(w, "\n      connects out: %s attempts = %s accepted + %s refused + %s never answered + %s blocked  (%s retransmits, handshake p50 %sns p99 %sns)",
				num(row, "outSyn"), num(row, "outAccepted"), num(row, "outRefused"), num(row, "outTimedOut"), num(row, "outBlocked"), num(row, "outRetransmits"), num(row, "handshakeP50Ns"), num(row, "handshakeP99Ns"))
			fmt.Fprintf(w, "\n      connects in:  %s attempts = %s accepted + %s refused + %s ignored + %s blocked  (%s retransmits)",
				num(row, "inSyn"), num(row, "inAccepted"), num(row, "inRefused"), num(row, "inIgnored"), num(row, "inBlocked"), num(row, "inRetransmits"))
		}
		fmt.Fprintln(w)
	}
}

// preemptors renders "  (taken by: vm:web 3500000000ns, kworker 500000000ns)" from a sched row, or nothing.
func preemptors(row map[string]any) string {
	var parts []string
	for _, p := range list(row, "topPreemptors") {
		parts = append(parts, fmt.Sprintf("%s %sns", str(p, "who"), num(p, "ns")))
	}
	if len(parts) == 0 {
		return ""
	}
	return "  (taken by: " + strings.Join(parts, ", ") + ")"
}

// formatDrops shows, per tap, how many packets the kernel dropped and whose drops they were, then
// each reason with the kernel function that freed the last one.
func formatDrops(w io.Writer, m map[string]any) {
	if note := str(m, "note"); note != "" {
		fmt.Fprintln(w, note)
	}
	fmt.Fprintln(w, "TRACE DROPS")
	if measured, _ := m["measured"].(bool); !measured {
		fmt.Fprintln(w, "  the drops program is not measuring, so nothing can be said about drops (shukractl programs says why)")
		return
	}
	taps := list(m, "taps")
	if len(taps) == 0 {
		fmt.Fprintln(w, "  no VM tap has been seen yet")
		return
	}
	rows := list(m, "rows")
	for _, t := range taps {
		fmt.Fprintf(w, "  vm=%s  tap=%s  kernel=%s  shukra=%s  other=%s  guest_not_reading=%s\n",
			str(t, "vm"), str(t, "tap"), num(t, "kernelDrops"), num(t, "shukraDropped"), num(t, "otherDrops"), num(t, "guestNotReading"))
		for _, r := range rows {
			if str(r, "tap") != str(t, "tap") {
				continue
			}
			where := ""
			if loc := str(r, "location"); loc != "" {
				where = "  freed in " + loc
			}
			fmt.Fprintf(w, "      %-14s %s%s\n", str(r, "reason"), num(r, "count"), where)
		}
	}
}

func list(m map[string]any, key string) []map[string]any {
	raw, _ := m[key].([]any)
	var out []map[string]any
	for _, item := range raw {
		if row, ok := item.(map[string]any); ok {
			out = append(out, row)
		}
	}
	return out
}

func stringsOf(v any) []string {
	raw, _ := v.([]any)
	var out []string
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func joinTaps(v any) string {
	raw, _ := v.([]any)
	var parts []string
	for _, item := range raw {
		if s, ok := item.(string); ok {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ",")
}
