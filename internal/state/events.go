package state

import (
	"sort"

	"github.com/zyvorai/shukra/internal/event"
)

// The event list is bounded at MaxEvents, but it is not one queue. On a busy hypervisor a few kinds of
// event arrive by the hundreds a second (a k3s node's connects, slow-block samples), and a plain
// oldest-first queue lets them push out the rare ones an operator is looking for: a guest's DNS name, a
// connection made into a VM, a detection. So every kind of event belongs to a class, and each class
// has a share of the list that no other class can take.
//
// The rule is only about who is dropped once the list is full. A class may use as much of the list as it
// likes while there is room, so a host that produces one kind of event still keeps MaxEvents of it. When
// the list is full, the oldest event of the class furthest over its share is dropped, so a class that
// is under its share is never the one that loses.
type eventClass int

const (
	classGuest   eventClass = iota // what a guest did, seen on its tap
	classNotable                   // detections and VM start and stop
	classProcess                   // exec and exit of a QEMU child
	classLatency                   // slow block requests and slow wakeups
	classHostNet                   // the QEMU process's and the host's own TCP connects
	classOther                     // a kind this build does not know
	classCount
)

// classShare is each class's guaranteed share. They add up to MaxEvents, which is what makes "the class
// furthest over its share" always exist once the list is full.
var classShare = [classCount]int{
	classGuest:   512,
	classNotable: 256,
	classProcess: 256,
	classLatency: 256,
	classHostNet: 512,
	classOther:   256,
}

func classOf(k event.Kind) eventClass {
	switch k {
	case event.KindGuestConnect, event.KindGuestFlow, event.KindGuestInbound, event.KindGuestDNS, event.KindGuestTLS:
		return classGuest
	case event.KindDetection, event.KindVMStart, event.KindVMStop:
		return classNotable
	case event.KindExec, event.KindExit, event.KindVMMOpen, event.KindVMMCall:
		return classProcess
	case event.KindBlockSlow, event.KindSchedDelay:
		return classLatency
	case event.KindTCPConnect, event.KindTCPRetransmit:
		return classHostNet
	}
	return classOther
}

// eventStore holds the events, one list per class, each in Seq order. It is not safe for concurrent use:
// State's lock guards it.
type eventStore struct {
	by    [classCount][]event.Event
	total int
}

// add stores e, and drops the oldest event of the class furthest over its share if that leaves the list
// over MaxEvents. e.Seq must be greater than any stored Seq.
func (s *eventStore) add(e event.Event) {
	c := classOf(e.Kind)
	s.by[c] = append(s.by[c], e)
	s.total++
	for s.total > MaxEvents {
		victim, excess := eventClass(0), -1<<31
		for i := eventClass(0); i < classCount; i++ {
			if x := len(s.by[i]) - classShare[i]; x > excess {
				victim, excess = i, x
			}
		}
		l := s.by[victim]
		l[0] = event.Event{} // let the dropped event be collected
		s.by[victim] = l[1:]
		s.total--
	}
}

// since returns the stored events with Seq greater than since, for one VM or for every VM when vm is empty,
// in Seq order. Each class list is already in order, so it finds the start of each by search and merges.
func (s *eventStore) since(vm string, since uint64) []event.Event {
	var lists [classCount][]event.Event
	n := 0
	for i := range s.by {
		l := s.by[i]
		l = l[sort.Search(len(l), func(j int) bool { return l[j].Seq > since }):]
		lists[i] = l
		n += len(l)
	}
	out := make([]event.Event, 0, n)
	var pos [classCount]int
	for {
		best := -1
		for i := range lists {
			if pos[i] < len(lists[i]) && (best < 0 || lists[i][pos[i]].Seq < lists[best][pos[best]].Seq) {
				best = i
			}
		}
		if best < 0 {
			return out
		}
		e := lists[best][pos[best]]
		pos[best]++
		if vm == "" || e.VM.Name == vm {
			out = append(out, e)
		}
	}
}
