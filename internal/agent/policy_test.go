package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/event"
)

func strayed(ag *Agent, iface, dst, policy, proto string, dport uint16) {
	kind := event.KindGuestConnect
	if proto == "udp" {
		kind = event.KindGuestFlow
	}
	ag.Ingest(event.Event{Kind: kind, TS: time.Now().UTC(), Iface: iface, Proto: proto, Src: "10.0.0.5", Dst: dst, DPort: dport, Policy: policy, Blocked: policy == "enforce"})
}

func TestAConnectionOutsideAnAuditedPolicyIsALowDetectionSayingItWouldHaveBeenDropped(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	strayed(ag, "tapdb", "198.51.100.7", "audit", "tcp", 443)
	dets := st.Detections("db")
	if len(dets) != 1 || dets[0].Rule != "egress-policy-audit" || dets[0].Severity != "low" || !dets[0].GuestAttributed || dets[0].Iface != "tapdb" ||
		dets[0].Message != "db opened tcp to 198.51.100.7:443, outside its egress policy: it would have been dropped (audit mode)" {
		t.Fatalf("%+v", dets)
	}
}

func TestAConnectionAnEnforcedPolicyDroppedIsAMediumDetection(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	strayed(ag, "tapweb", "198.51.100.7", "enforce", "udp", 5300)
	dets := st.Detections("web")
	if len(dets) != 1 || dets[0].Rule != "egress-policy-blocked" || dets[0].Severity != "medium" ||
		dets[0].Message != "web opened udp to 198.51.100.7:5300, outside its egress policy: it was dropped" {
		t.Fatalf("%+v", dets)
	}
}

func TestAVMThatKeepsTryingOnePlaceIsOneDetectionButAnotherNetworkOrModeIsNot(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	strayed(ag, "tapdb", "198.51.100.7", "audit", "tcp", 443)
	strayed(ag, "tapdb", "198.51.100.99", "audit", "tcp", 8443) // the same /24 and protocol
	if len(st.Detections("db")) != 1 || st.Suppressed() != 1 {
		t.Fatalf("%d detections, %d suppressed", len(st.Detections("db")), st.Suppressed())
	}
	strayed(ag, "tapdb", "203.0.113.5", "audit", "tcp", 443)    // another network
	strayed(ag, "tapdb", "198.51.100.7", "audit", "udp", 5300)  // another protocol
	strayed(ag, "tapdb", "198.51.100.7", "enforce", "tcp", 443) // enforcement is a different fact from audit
	strayed(ag, "tapweb", "198.51.100.7", "audit", "tcp", 443)  // another VM
	if len(st.Detections("db")) != 4 || len(st.Detections("web")) != 1 {
		t.Fatalf("db %d web %d", len(st.Detections("db")), len(st.Detections("web")))
	}
}

func TestNothingIsReportedForAConnectionNoPolicyJudgedOrOnATapNoVMOwns(t *testing.T) {
	ag, st := newTapAgent(t, "")
	strayed(ag, "tapdb", "198.51.100.7", "", "tcp", 443)
	strayed(ag, "tap-nobody-owns", "198.51.100.7", "audit", "tcp", 443)
	strayed(ag, "tapdb", "198.51.100.7", "novel", "tcp", 443) // a verdict this build does not know is not one
	if got := st.Detections(""); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
	for _, e := range st.Events("") {
		if e.Kind == event.KindDetection && strings.HasPrefix(e.Rule, "egress-policy") {
			t.Fatalf("%+v", e)
		}
	}
}

func TestTheEventItselfKeepsItsPolicyVerdict(t *testing.T) {
	ag, st := newTapAgent(t, "")
	strayed(ag, "tapdb", "198.51.100.7", "enforce", "tcp", 443)
	var got []event.Event
	for _, e := range st.Events("") {
		if e.Kind == event.KindGuestConnect {
			got = append(got, e)
		}
	}
	if len(got) != 1 || got[0].Policy != "enforce" || !got[0].Blocked {
		t.Fatalf("%+v", got)
	}
}
