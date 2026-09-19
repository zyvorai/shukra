package sink

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/event"
)

func det(rule string) event.Event {
	return event.Event{Product: "shukra", Kind: event.KindDetection, Rule: rule, Severity: "high", Message: "m", VM: event.VM{Name: "db"}}
}

func fast(w *Webhook) *Webhook { w.backoff = time.Millisecond; return w }

func TestWebhookSignsAndCarriesTheEvent(t *testing.T) {
	var gotBody []byte
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		hdr = r.Header.Clone()
	}))
	defer srv.Close()
	wh, _ := NewWebhook(srv.URL, "s3cret")
	wh.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	if err := wh.Send(context.Background(), det("slow-disk")); err != nil {
		t.Fatal(err)
	}
	var e event.Event
	if err := json.Unmarshal(gotBody, &e); err != nil || e.Rule != "slow-disk" || e.VM.Name != "db" {
		t.Fatalf("%v %s", err, gotBody)
	}
	if hdr.Get("X-Shukra-Timestamp") != "1700000000" || hdr.Get("Content-Type") != "application/json" {
		t.Fatalf("%v", hdr)
	}
	// A receiver recomputes the MAC over "<timestamp>.<body>".
	if want := Sign([]byte("s3cret"), 1_700_000_000, gotBody); hdr.Get("X-Shukra-Signature") != want {
		t.Fatalf("signature %q, want %q", hdr.Get("X-Shukra-Signature"), want)
	}
	if Sign([]byte("other"), 1_700_000_000, gotBody) == hdr.Get("X-Shukra-Signature") {
		t.Fatal("signature does not depend on the secret")
	}
	if Sign([]byte("s3cret"), 1_700_000_001, gotBody) == hdr.Get("X-Shukra-Signature") {
		t.Fatal("signature does not cover the timestamp")
	}
}

func TestWebhookWithoutSecretSendsNoSignature(t *testing.T) {
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hdr = r.Header.Clone() }))
	defer srv.Close()
	wh, _ := NewWebhook(srv.URL, "")
	if err := wh.Send(context.Background(), det("x")); err != nil {
		t.Fatal(err)
	}
	if hdr.Get("X-Shukra-Signature") != "" || hdr.Get("X-Shukra-Timestamp") != "" {
		t.Fatalf("%v", hdr)
	}
}

func TestWebhookRetriesServerErrorsThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	wh, _ := NewWebhook(srv.URL, "")
	if err := fast(wh).Send(context.Background(), det("x")); err != nil || calls.Load() != 3 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
}

func TestWebhookGivesUpAfterThreeAndDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	status := http.StatusServiceUnavailable
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	wh, _ := NewWebhook(srv.URL, "")
	if err := fast(wh).Send(context.Background(), det("x")); err == nil || calls.Load() != 3 {
		t.Fatalf("err=%v calls=%d", err, calls.Load())
	}
	calls.Store(0)
	status = http.StatusForbidden
	if err := fast(wh).Send(context.Background(), det("x")); err == nil || calls.Load() != 1 {
		t.Fatalf("a 403 was retried: err=%v calls=%d", err, calls.Load())
	}
}

func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	var hit atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusFound)
	}))
	defer srv.Close()
	wh, _ := NewWebhook(srv.URL, "s3cret")
	if err := fast(wh).Send(context.Background(), det("x")); err == nil {
		t.Fatal("a redirect counted as delivered")
	}
	if hit.Load() {
		t.Fatal("followed a redirect with a signed body")
	}
}

func TestWebhookErrorDoesNotLeakTheURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL + "/hooks/TOKEN-123"
	srv.Close() // connection refused
	wh, _ := NewWebhook(url, "")
	err := fast(wh).Send(context.Background(), det("x"))
	if err == nil || strings.Contains(err.Error(), "TOKEN-123") {
		t.Fatalf("%v", err)
	}
}

func TestWebhookStopsRetryingWhenCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	wh, _ := NewWebhook(srv.URL, "")
	wh.backoff = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := wh.Send(ctx, det("x")); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("err=%v after %s", err, time.Since(start))
	}
}

func TestNewWebhookRejectsOtherSchemes(t *testing.T) {
	for _, u := range []string{"", "ftp://x/y", "file:///etc/passwd", "http://", "//host/x", "not a url"} {
		if _, err := NewWebhook(u, ""); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
}

type fake struct {
	mu     sync.Mutex
	got    []string
	block  chan struct{}
	err    error
	closed atomic.Bool
}

func (f *fake) Name() string { return "fake" }
func (f *fake) Close() error { f.closed.Store(true); return nil }
func (f *fake) Send(ctx context.Context, e event.Event) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, e.Rule)
	return f.err
}
func (f *fake) rules() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.got...)
}

func TestDispatcherDeliversInOrderAndCountsAndDrainsOnClose(t *testing.T) {
	a, b := &fake{}, &fake{err: errors.New("boom")}
	d := NewDispatcher(a, b)
	for i := 0; i < 5; i++ {
		d.Emit(det("r" + strconv.Itoa(i)))
	}
	d.Close(5 * time.Second)
	if got := strings.Join(a.rules(), ","); got != "r0,r1,r2,r3,r4" {
		t.Fatalf("%s", got)
	}
	st := d.Stats()
	if len(st) != 2 || st[0].Sent != 5 || st[0].Failed != 0 || st[1].Sent != 0 || st[1].Failed != 5 {
		t.Fatalf("%+v", st)
	}
	if !a.closed.Load() || !b.closed.Load() {
		t.Fatal("sinks not closed")
	}
	d.Emit(det("late")) // must not panic or deliver
	d.Close(time.Second)
}

func TestSlowSinkDropsWithoutBlockingTheOtherSink(t *testing.T) {
	slow := &fake{block: make(chan struct{})}
	quick := &fake{}
	d := NewDispatcher(slow, quick)
	start := time.Now()
	const n = QueueSize + 50
	for i := 0; i < n; i++ {
		d.Emit(det("r"))
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("Emit blocked on a stuck sink")
	}
	// The worker holds one event, the queue holds QueueSize, the rest are dropped.
	var dropped uint64
	for i := 0; i < 200 && dropped == 0; i++ {
		dropped = d.Stats()[0].Dropped
		time.Sleep(5 * time.Millisecond)
	}
	if dropped == 0 || dropped > 50 {
		t.Fatalf("dropped %d", dropped)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(quick.rules()) < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(quick.rules()) != n {
		t.Fatalf("the healthy sink got %d of %d", len(quick.rules()), n)
	}
	start = time.Now()
	d.Close(50 * time.Millisecond) // the stuck sink is cancelled, not waited on forever
	if time.Since(start) > 5*time.Second {
		t.Fatal("Close hung on a stuck sink")
	}
}

func TestFileSinkWritesJSONLinesWithMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	f, err := NewFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"a", "b"} {
		if err := f.Send(context.Background(), det(r)); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var e event.Event
	if len(lines) != 2 || json.Unmarshal([]byte(lines[1]), &e) != nil || e.Rule != "b" {
		t.Fatalf("%q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

type sysrec struct{ level, msg string }
type fakeSyslog struct{ got []sysrec }

func (f *fakeSyslog) rec(l, m string) error  { f.got = append(f.got, sysrec{l, m}); return nil }
func (f *fakeSyslog) Crit(m string) error    { return f.rec("crit", m) }
func (f *fakeSyslog) Err(m string) error     { return f.rec("err", m) }
func (f *fakeSyslog) Warning(m string) error { return f.rec("warning", m) }
func (f *fakeSyslog) Notice(m string) error  { return f.rec("notice", m) }
func (f *fakeSyslog) Close() error           { return nil }

func TestSyslogMapsSeverity(t *testing.T) {
	fs := &fakeSyslog{}
	s := &Syslog{w: fs}
	for _, sev := range []string{"critical", "high", "medium", "low", ""} {
		e := det("r")
		e.Severity = sev
		if err := s.Send(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	var levels []string
	for _, g := range fs.got {
		levels = append(levels, g.level)
		if !strings.HasPrefix(g.msg, "{") || !strings.Contains(g.msg, `"rule":"r"`) {
			t.Fatalf("%q", g.msg)
		}
	}
	if got := strings.Join(levels, ","); got != "crit,err,warning,notice,warning" {
		t.Fatalf("%s", got)
	}
}
