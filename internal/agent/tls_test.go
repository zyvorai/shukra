package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/event"
)

func guestTLS(ag *Agent, iface, sni string) {
	ag.Ingest(event.Event{Kind: event.KindGuestTLS, Proto: "tcp", TS: time.Now().UTC(), Iface: iface, Src: "10.0.0.5", Dst: "203.0.113.9", DPort: 443, SNI: sni, TLSVersion: "1.3"})
}

func TestAGuestTLSHelloIsAttributedToTheVMAndKeepsItsName(t *testing.T) {
	ag, st := newTapAgent(t, "")
	guestTLS(ag, "tapweb", "example.com")
	got := kinds(st, event.KindGuestTLS)
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	e := got[0]
	if e.VM.Name != "web" || e.TGID != 200 || !e.GuestAttributed || e.Attribution != event.AttributionGuestTap || e.SNI != "example.com" || e.DPort != 443 {
		t.Fatalf("%+v", e)
	}
	guestTLS(ag, "tap-nobody-owns", "example.com")
	for _, e := range kinds(st, event.KindGuestTLS) {
		if e.Iface == "tap-nobody-owns" && (e.GuestAttributed || e.VM.Name != "") {
			t.Fatalf("a tap no VM owns must stay unattributed: %+v", e)
		}
	}
	if len(st.Detections("")) != 0 {
		t.Fatalf("no rules, no detections: %+v", st.Detections(""))
	}
}

func TestATLSRuleFiresOnTheServerNameAndOnlyThere(t *testing.T) {
	ag, st := newTapAgent(t, `
destinations:
  - {cidr: 10.0.0.0/24, name: lan}
tls:
  - {name: doh, suffix: dns.google, severity: critical}
dns:
  - {name: pool, suffix: nanopool.org}
`)
	guestTLS(ag, "tapdb", "dns.google")
	guestTLS(ag, "tapdb", "example.com")
	guestTLS(ag, "tapdb", "")                                                                                                                          // no name: an address, or hidden by ECH
	guestTLS(ag, "tapdb", "eth.nanopool.org")                                                                                                          // a dns rule's name, seen in TLS
	ag.Ingest(event.Event{Kind: event.KindGuestDNS, TS: time.Now().UTC(), Iface: "tapdb", Proto: "udp", DPort: 53, DNSName: "dns.google", QType: "A"}) // a tls rule's name, looked up
	dets := st.Detections("db")
	if len(dets) != 1 || dets[0].Rule != "doh" || dets[0].Severity != "critical" || !dets[0].GuestAttributed || dets[0].Iface != "tapdb" ||
		!strings.Contains(dets[0].Message, "connected to dns.google (TLS, port 443)") {
		t.Fatalf("only the tls rule may fire, and only on a TLS name: %+v", dets)
	}
}

func TestTheSameServerNameIsHeldBackButADifferentOneIsNot(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\ntls:\n  - {name: pool, suffix: nanopool.org}\n")
	guestTLS(ag, "tapdb", "a.nanopool.org")
	guestTLS(ag, "tapdb", "a.nanopool.org")
	guestTLS(ag, "tapdb", "b.nanopool.org")
	if len(st.Detections("db")) != 2 || st.Suppressed() != 1 {
		t.Fatalf("%d detections, %d suppressed", len(st.Detections("db")), st.Suppressed())
	}
}

func TestATLSServerNameTeachesTheSameSiteADNSLookupWouldHave(t *testing.T) {
	ag, st, store := baselineAgent(t, learn1h)
	seen(ag, 0, event.Event{Kind: event.KindGuestDNS, DNSName: "api.example.com", QType: "A", Dst: "10.0.0.1"})
	seen(ag, 0, event.Event{Kind: event.KindGuestTLS, Proto: "tcp", SNI: "cdn.other.org", DPort: 443, Dst: "203.0.113.9"})
	late := 3 * time.Hour
	seen(ag, late, event.Event{Kind: event.KindGuestTLS, Proto: "tcp", SNI: "WWW.Example.com", DPort: 443, Dst: "203.0.113.9"})   // learned through DNS
	seen(ag, late, event.Event{Kind: event.KindGuestDNS, DNSName: "img.other.org", QType: "A", Dst: "10.0.0.1"})                  // learned through TLS
	seen(ag, late, event.Event{Kind: event.KindGuestTLS, Proto: "tcp", SNI: "c2.badsite.test", DPort: 8443, Dst: "198.51.100.7"}) // new
	got := newDetections(st)
	if len(got) != 1 || got[0].Rule != "new-dns-suffix" || got[0].Severity != "low" ||
		!strings.Contains(got[0].Message, "db connected to badsite.test for the first time (TLS server name c2.badsite.test, port 8443)") {
		t.Fatalf("%+v", got)
	}
	if n := len(store.Items("db", 0)); n != 3 {
		t.Fatalf("learned %+v", store.Items("db", 0))
	}
}

func TestAHelloWithNoUsableNameTeachesNothing(t *testing.T) {
	ag, st, store := baselineAgent(t, learn1h)
	for _, sni := range []string{"", "203.0.113.9", "2001:db8::1"} {
		seen(ag, 0, event.Event{Kind: event.KindGuestTLS, Proto: "tcp", SNI: sni, DPort: 443, Dst: "203.0.113.9"})
		seen(ag, 3*time.Hour, event.Event{Kind: event.KindGuestTLS, Proto: "tcp", SNI: sni, DPort: 443, Dst: "203.0.113.9"})
	}
	if len(newDetections(st)) != 0 || len(store.Items("db", 0)) != 0 {
		t.Fatalf("%+v %+v", newDetections(st), store.Items("db", 0))
	}
}
