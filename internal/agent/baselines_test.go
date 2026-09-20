package agent

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/baseline"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/state"
)

var b0 = time.Date(2026, 9, 20, 3, 0, 0, 0, time.UTC)

func baselineAgent(t *testing.T, yaml string) (*Agent, *state.State, *baseline.Store) {
	t.Helper()
	ag, st := newTapAgent(t, yaml)
	store := baseline.NewStore(baseline.DefaultOptions())
	ag.SetBaselines(store, true)
	return ag, st, store
}

func seen(ag *Agent, at time.Duration, e event.Event) {
	e.TS = b0.Add(at)
	if e.Iface == "" {
		e.Iface = "tapdb"
	}
	ag.Ingest(e)
}

func dest(ip string, port uint16) event.Event {
	return event.Event{Kind: event.KindGuestConnect, Proto: "tcp", Src: "10.0.0.5", Dst: ip, DPort: port}
}

func newDetections(st *state.State) []event.Event {
	var out []event.Event
	for _, d := range st.Detections("db") {
		if strings.HasPrefix(d.Rule, "new-") || d.Rule == "baseline-cap" {
			out = append(out, d)
		}
	}
	return out
}

const learn1h = "baselines:\n  learn: 1h\n"

func TestNothingIsLearnedOrReportedUnlessTheRulesFileTurnsBaselinesOn(t *testing.T) {
	ag, st, store := baselineAgent(t, "")
	seen(ag, 0, dest("203.0.113.9", 443))
	seen(ag, 5*time.Hour, dest("198.51.100.7", 443))
	if len(store.Status("", b0)) != 0 || len(newDetections(st)) != 0 {
		t.Fatalf("baselines are off: %+v %+v", store.Status("", b0), newDetections(st))
	}
}

func TestAnythingNewAfterLearningIsReportedOnceAsAGuestAttributedDetection(t *testing.T) {
	ag, st, store := baselineAgent(t, learn1h)
	seen(ag, 0, dest("203.0.113.9", 443))
	seen(ag, 10*time.Minute, dest("198.51.100.7", 443))
	if len(newDetections(st)) != 0 {
		t.Fatalf("nothing is reported while learning: %+v", newDetections(st))
	}
	seen(ag, 2*time.Hour, dest("203.0.113.200", 8443)) // the same /24 as a learned one: not new
	seen(ag, 2*time.Hour, dest("192.0.2.44", 22))      // a network never seen
	seen(ag, 2*time.Hour+time.Minute, dest("192.0.2.99", 22))
	got := newDetections(st)
	if len(got) != 1 {
		t.Fatalf("one new network is one detection: %+v", got)
	}
	d := got[0]
	if d.Rule != "new-destination" || d.Severity != "medium" || !d.GuestAttributed || d.Attribution != event.AttributionGuestTap || d.Iface != "tapdb" || d.VM.Name != "db" {
		t.Fatalf("%+v", d)
	}
	if !strings.Contains(d.Message, "db contacted 192.0.2.0/24 for the first time") || !strings.Contains(d.Message, "192.0.2.44:22") {
		t.Fatalf("the message names the network and the address: %s", d.Message)
	}
	if len(store.Items("db", 0)) != 3 {
		t.Fatalf("learned %+v", store.Items("db", 0))
	}
}

func TestDNSSuffixesAndInboundPeersAreLearnedToo(t *testing.T) {
	ag, st, _ := baselineAgent(t, learn1h)
	seen(ag, 0, event.Event{Kind: event.KindGuestDNS, DNSName: "api.example.com", QType: "A", Dst: "10.0.0.1"})
	seen(ag, 0, event.Event{Kind: event.KindGuestInbound, Src: "198.51.100.4", Dst: "10.0.0.5", DPort: 22})
	late := 3 * time.Hour
	seen(ag, late, event.Event{Kind: event.KindGuestDNS, DNSName: "WWW.Example.com", QType: "AAAA", Dst: "10.0.0.1"}) // same site
	seen(ag, late, event.Event{Kind: event.KindGuestDNS, DNSName: "c2.badsite.test", QType: "A", Dst: "10.0.0.1"})
	seen(ag, late, event.Event{Kind: event.KindGuestInbound, Src: "198.51.100.77", Dst: "10.0.0.5", DPort: 22}) // same /24
	seen(ag, late, event.Event{Kind: event.KindGuestInbound, Src: "203.0.113.8", Dst: "10.0.0.5", DPort: 3389})
	got := map[string]event.Event{}
	for _, d := range newDetections(st) {
		got[d.Rule] = d
	}
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if d := got["new-dns-suffix"]; d.Severity != "low" || !strings.Contains(d.Message, "db looked up badsite.test for the first time (c2.badsite.test, A)") {
		t.Fatalf("%+v", d)
	}
	if d := got["new-inbound-peer"]; d.Severity != "medium" || !strings.Contains(d.Message, "connected to from 203.0.113.0/24 for the first time (203.0.113.8, to port 3389)") {
		t.Fatalf("%+v", d)
	}
}

func TestAKindTurnedOffIsNeitherLearnedNorReportedAndSeverityFollowsTheConfig(t *testing.T) {
	ag, st, store := baselineAgent(t, "baselines:\n  learn: 1h\n  kinds: [dns-suffix]\n  severity: {dns-suffix: critical}\n")
	seen(ag, 0, dest("203.0.113.9", 443))
	seen(ag, 0, event.Event{Kind: event.KindGuestDNS, DNSName: "a.example.com", QType: "A"})
	seen(ag, 2*time.Hour, dest("198.51.100.7", 443))
	seen(ag, 2*time.Hour, event.Event{Kind: event.KindGuestDNS, DNSName: "evil.test", QType: "A"})
	got := newDetections(st)
	if len(got) != 1 || got[0].Rule != "new-dns-suffix" || got[0].Severity != "critical" {
		t.Fatalf("%+v", got)
	}
	for _, it := range store.Items("db", 0) {
		if it.Kind == baseline.Destination {
			t.Fatalf("a kind that is off was learned: %+v", it)
		}
	}
}

func TestACutShortNameAndAnUnattributedTapAreNotLearned(t *testing.T) {
	ag, st, store := baselineAgent(t, learn1h)
	seen(ag, 0, event.Event{Kind: event.KindGuestDNS, DNSName: "aaaa.aaaa", DNSTruncated: true})
	seen(ag, 0, event.Event{Kind: event.KindGuestConnect, Iface: "tap-nobody-owns", Dst: "203.0.113.9", DPort: 1})
	if len(store.Status("", b0)) != 0 {
		t.Fatalf("a name that is only part of a name is not a site, and a tap no VM owns is no VM's baseline: %+v", store.Status("", b0))
	}
	seen(ag, 5*time.Hour, event.Event{Kind: event.KindGuestDNS, DNSName: "aaaa.aaaa", DNSTruncated: true})
	if len(newDetections(st)) != 0 {
		t.Fatalf("%+v", newDetections(st))
	}
}

func TestADailyCapIsAnnouncedOnceAndTheRestAreHeldBack(t *testing.T) {
	ag, st, store := baselineAgent(t, "baselines:\n  learn: 1h\n  max_alerts_per_day: 3\n")
	seen(ag, 0, dest("10.9.9.9", 1))
	for i := 0; i < 8; i++ {
		seen(ag, 2*time.Hour+time.Duration(i)*time.Second, dest("198.51."+string(rune('0'+i))+".1", 1)) // eight different /24s
	}
	var news, caps int
	for _, d := range newDetections(st) {
		switch d.Rule {
		case "new-destination":
			news++
		case "baseline-cap":
			caps++
			if !strings.Contains(d.Message, "3 new-item alerts") || !strings.Contains(d.Message, "shukractl baseline db") {
				t.Fatalf("%s", d.Message)
			}
		}
	}
	if news != 3 || caps != 1 {
		t.Fatalf("%d new-destination and %d baseline-cap", news, caps)
	}
	if s := store.Status("db", b0.Add(3*time.Hour))[0]; s.Suppressed == 0 {
		t.Fatalf("held-back items are counted: %+v", s)
	}
}

func TestReloadingTheRulesChangesTheLearningPeriodAndRemovingTheSectionStopsIt(t *testing.T) {
	ag, st, store := baselineAgent(t, "baselines:\n  learn: 24h\n")
	if store.Options().Learn != 24*time.Hour {
		t.Fatalf("%+v", store.Options())
	}
	path := ag.watchPath
	if err := os.WriteFile(path, []byte("baselines:\n  learn: 30m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ag.Reload(); err != nil || store.Options().Learn != 30*time.Minute {
		t.Fatalf("%v %+v", err, store.Options())
	}
	seen(ag, 0, dest("203.0.113.9", 443))
	if err := os.WriteFile(path, []byte("suppress: 5m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ag.Reload(); err != nil {
		t.Fatal(err)
	}
	seen(ag, 5*time.Hour, dest("198.51.100.7", 443))
	if len(newDetections(st)) != 0 {
		t.Fatal("reported after the section was removed")
	}
	if len(store.Items("db", 0)) != 1 {
		t.Fatal("and it stopped learning too")
	}
}

func TestABadBaselinesSectionKeepsTheRulesThatWereInForce(t *testing.T) {
	ag, _, store := baselineAgent(t, "baselines:\n  learn: 24h\n")
	if err := os.WriteFile(ag.watchPath, []byte("baselines:\n  learn: 1s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ag.Reload(); err == nil {
		t.Fatal("a learning period of a second was accepted")
	}
	if store.Options().Learn != 24*time.Hour || ag.cfg.Load().Baselines == nil {
		t.Fatal("the previous rules must stay in force")
	}
}
