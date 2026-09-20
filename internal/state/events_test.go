package state

import (
	"sort"
	"testing"

	"github.com/zyvorai/shukra/internal/event"
)

func addN(s *State, n int, kind event.Kind, vm string) {
	for i := 0; i < n; i++ {
		s.AddEvent(event.Event{Kind: kind, VM: event.VM{Name: vm}, PID: 1})
	}
}

func count(events []event.Event, kind event.Kind) int {
	n := 0
	for _, e := range events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func TestTheSharesAddUpToTheWholeList(t *testing.T) {
	sum := 0
	for _, n := range classShare {
		sum += n
	}
	if sum != MaxEvents {
		t.Fatalf("shares add up to %d, not %d: the victim search relies on some class being over its share once the list is full", sum, MaxEvents)
	}
}

func TestEveryKindBelongsToAClassAndAnUnknownOneToOther(t *testing.T) {
	want := map[event.Kind]eventClass{
		event.KindGuestConnect: classGuest, event.KindGuestFlow: classGuest, event.KindGuestInbound: classGuest, event.KindGuestDNS: classGuest, event.KindGuestTLS: classGuest,
		event.KindDetection: classNotable, event.KindVMStart: classNotable, event.KindVMStop: classNotable,
		event.KindExec: classProcess, event.KindExit: classProcess,
		event.KindBlockSlow: classLatency, event.KindSchedDelay: classLatency,
		event.KindTCPConnect: classHostNet, event.KindTCPRetransmit: classHostNet,
		"something_new": classOther,
	}
	for k, c := range want {
		if got := classOf(k); got != c {
			t.Errorf("%s: class %d, want %d", k, got, c)
		}
	}
}

// A host that produces only one kind of event still keeps the whole list of it: a class may use every
// slot while nobody else wants them.
func TestOneKindMayFillTheWholeList(t *testing.T) {
	st := New("node-07")
	addN(st, MaxEvents+500, event.KindBlockSlow, "db")
	if got := len(st.Events("")); got != MaxEvents {
		t.Fatalf("kept %d of one kind, want %d", got, MaxEvents)
	}
}

// The reason for the classes: a flood of one kind must not push out a rare kind that is under its share.
func TestAFloodCannotEvictWhatIsUnderItsShare(t *testing.T) {
	st := New("node-07")
	addN(st, 5, event.KindGuestDNS, "web-01")
	addN(st, 3, event.KindGuestInbound, "web-01")
	addN(st, 2, event.KindDetection, "web-01")
	for round := 0; round < 3; round++ { // far more than the list holds, of the two noisy kinds
		addN(st, MaxEvents, event.KindTCPConnect, "")
		addN(st, MaxEvents, event.KindBlockSlow, "db")
	}
	got := st.Events("")
	if len(got) != MaxEvents {
		t.Fatalf("kept %d, want %d", len(got), MaxEvents)
	}
	if count(got, event.KindGuestDNS) != 5 || count(got, event.KindGuestInbound) != 3 || count(got, event.KindDetection) != 2 {
		t.Fatalf("rare events were evicted: dns %d inbound %d detections %d", count(got, event.KindGuestDNS), count(got, event.KindGuestInbound), count(got, event.KindDetection))
	}
}

// Once every class is at or over its share the noisiest is the one that loses, and two noisy classes end
// up sharing what the quiet ones leave.
func TestTheClassFurthestOverItsShareIsTheOneThatLoses(t *testing.T) {
	st := New("node-07")
	addN(st, MaxEvents, event.KindBlockSlow, "db") // fills the list alone
	addN(st, 1000, event.KindTCPConnect, "")
	got := st.Events("")
	if count(got, event.KindTCPConnect) != 1000 || count(got, event.KindBlockSlow) != MaxEvents-1000 {
		t.Fatalf("the older, larger class must give way: connects %d, slow blocks %d", count(got, event.KindTCPConnect), count(got, event.KindBlockSlow))
	}
	// Both are far over their shares now, so each keeps being trimmed from the one that is further over.
	addN(st, 3000, event.KindTCPConnect, "")
	got = st.Events("")
	if len(got) != MaxEvents {
		t.Fatalf("kept %d", len(got))
	}
	if n := count(got, event.KindBlockSlow); n < classShare[classLatency] {
		t.Fatalf("a class must never be pushed below its share while it has events: %d slow blocks left, share %d", n, classShare[classLatency])
	}
}

func TestEventsComeBackInSeqOrderAcrossClassesAndSinceFilters(t *testing.T) {
	st := New("node-07")
	kinds := []event.Kind{event.KindTCPConnect, event.KindGuestDNS, event.KindBlockSlow, event.KindDetection, event.KindExec, "novel", event.KindGuestFlow}
	for i := 0; i < 300; i++ {
		st.AddEvent(event.Event{Kind: kinds[i%len(kinds)], VM: event.VM{Name: []string{"a", "b"}[i%2]}, PID: 1})
	}
	all := st.EventsSince("", 0)
	if len(all) != 300 || !sort.SliceIsSorted(all, func(i, j int) bool { return all[i].Seq < all[j].Seq }) {
		t.Fatalf("%d events, sorted=%v", len(all), sort.SliceIsSorted(all, func(i, j int) bool { return all[i].Seq < all[j].Seq }))
	}
	for i, e := range all {
		if e.Seq != uint64(i+1) {
			t.Fatalf("event %d has Seq %d: an event was lost or repeated", i, e.Seq)
		}
	}
	after := st.EventsSince("", 250)
	if len(after) != 50 || after[0].Seq != 251 {
		t.Fatalf("since 250: %d events starting at %d", len(after), after[0].Seq)
	}
	for _, e := range st.EventsSince("a", 0) {
		if e.VM.Name != "a" {
			t.Fatalf("a VM filter returned %s", e.VM.Name)
		}
	}
	if got := st.EventsSince("", 300); len(got) != 0 {
		t.Fatalf("since the newest: %d", len(got))
	}
}

// A poller that resumes from the last Seq it saw must not repeat or skip an event, whichever class
// the events belong to, even after some have been evicted.
func TestAResumingPollerNeverRepeatsAnEventAfterEviction(t *testing.T) {
	st := New("node-07")
	var cursor uint64
	seen := map[uint64]bool{}
	for round := 0; round < 12; round++ {
		addN(st, 700, event.KindTCPConnect, "")
		addN(st, 40, event.KindGuestConnect, "web-01")
		for _, e := range st.EventsSince("", cursor) {
			if seen[e.Seq] {
				t.Fatalf("Seq %d delivered twice", e.Seq)
			}
			seen[e.Seq] = true
			cursor = e.Seq
		}
	}
	if cursor != st.Seq() {
		t.Fatalf("cursor %d, newest %d", cursor, st.Seq())
	}
}

// The victim is the class furthest over its SHARE, not the class with the most events: a large class that
// is under its share is protected, and a smaller class that is over its share is the one that gives way.
func TestTheVictimIsChosenByShareNotBySize(t *testing.T) {
	st := New("node-07")
	addN(st, 500, event.KindGuestFlow, "web-01") // the biggest class, and under its 512 share
	addN(st, 400, event.KindDetection, "web-01") // over its 256 share by 144
	addN(st, 512, event.KindTCPConnect, "")      // exactly its share
	addN(st, 256, event.KindBlockSlow, "db")     // exactly its share
	addN(st, 256, event.KindExec, "")            // exactly its share
	addN(st, 124, "novel", "")                   // under its share: the list is now exactly full
	if got := len(st.Events("")); got != MaxEvents {
		t.Fatalf("set-up: %d events", got)
	}
	addN(st, 1, "novel", "") // one more forces an eviction
	got := st.Events("")
	if count(got, event.KindGuestFlow) != 500 {
		t.Fatalf("the biggest class is under its share and must not lose: %d left", count(got, event.KindGuestFlow))
	}
	if count(got, event.KindDetection) != 399 {
		t.Fatalf("the class over its share must give up one: %d left", count(got, event.KindDetection))
	}
}
