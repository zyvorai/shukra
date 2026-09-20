//go:build linux && shukrabpf

package observe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/zyvorai/shukra/internal/bpfgen"
	"github.com/zyvorai/shukra/internal/event"
)

var tapErrOnce sync.Map

// SyncTaps puts the tap program on the named interfaces and takes it off any
// others. Names whose interface does not exist yet are tried again next time.
// A failure is logged once per interface and reason, not on every scan.
func SyncTaps(names []string) {
	errs, err := bpfgen.SyncTaps(names)
	if err != nil {
		if _, seen := tapErrOnce.LoadOrStore("load:"+err.Error(), true); !seen {
			log.Printf("tap program: %v", err)
		}
		return
	}
	for name, e := range errs {
		if _, seen := tapErrOnce.LoadOrStore(name+":"+e.Error(), true); !seen {
			log.Printf("tap program on %s: %v", name, e)
		}
	}
	watchDrops()
}

// TapProgram is the state of the tap program: attached once at least one VM tap
// carries it, and detached, with the reason, otherwise.
func TapProgram() (status, detail string) {
	loaded, n, err := bpfgen.TapStatus()
	switch {
	case err != nil:
		return "detached", err.Error()
	case !loaded:
		return "detached", "not loaded"
	case n == 0:
		return "detached", "no VM tap interfaces to attach to yet"
	default:
		durable := "enforcement survives a daemon restart"
		if !bpfgen.TapPinned() {
			durable = "not pinned: enforcement lasts only while the daemon runs"
		}
		return "attached", fmt.Sprintf("%d taps, %s", n, durable)
	}
}

// ShutdownTaps is the daemon's graceful exit. It detaches every tap that is not
// isolated and leaves isolated ones enforcing. See bpfgen.ShutdownTaps.
func ShutdownTaps() {
	kept, detached := bpfgen.ShutdownTaps()
	if kept+detached > 0 {
		log.Printf("tap program: detached %d taps, left %d isolated taps enforcing", detached, kept)
	}
}

// DetachAllTaps removes every pinned tap link and map, isolated or not, and says
// how many links it detached. It works whether or not the daemon is running.
func DetachAllTaps() int { return bpfgen.DetachAllTaps() }

// TapSample reads the per-tap counters. It first counts the TCP handshakes that were never answered,
// which the kernel cannot do for itself.
func TapSample() []TapCounters {
	bpfgen.SweepPending()
	stats := bpfgen.TapStats()
	outcomes := bpfgen.TapOutcomes()
	hs := bpfgen.TapHandshakeHist()
	var out []TapCounters
	for _, name := range bpfgen.TapAttached() {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		s := stats[uint32(iface.Index)]
		c := TapCounters{
			Name: name, Ifindex: uint32(iface.Index),
			FromPkts: s.FromPkts, FromBytes: s.FromBytes, ToPkts: s.ToPkts, ToBytes: s.ToBytes,
			DroppedPkts: s.DroppedPkts, DroppedBytes: s.DroppedBytes, Isolated: bpfgen.TapIsolated(name),
		}
		o := outcomes[uint32(iface.Index)]
		c.OutSyn, c.OutOK, c.OutRefused, c.OutTimeout, c.OutRetrans, c.OutBlocked = o.OutSyn, o.OutOK, o.OutRefused, o.OutTimeout, o.OutRetrans, o.OutBlocked
		c.InSyn, c.InOK, c.InRefused, c.InIgnored, c.InRetrans, c.InBlocked = o.InSyn, o.InOK, o.InRefused, o.InIgnored, o.InRetrans, o.InBlocked
		c.HandshakeHist = hs[uint32(iface.Index)]
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var tapStartOnce sync.Once

// StartTap reads the tap event ring. Each event is a TCP connect attempt the
// guest made, seen on its tap, so it is the guest's own traffic.
func StartTap(handler func(event.Event)) {
	tapStartOnce.Do(func() {
		if handler == nil {
			return
		}
		coll := bpfgen.TapCollection()
		if coll == nil {
			return
		}
		rd, err := ringbuf.NewReader(coll.Maps["tap_events"])
		if err != nil {
			lost.Add(1)
			return
		}
		readTapRing(rd, handler, decodeTap)
		if m := coll.Maps["tap_dns"]; m != nil {
			// A tap program from before DNS names has no such ring. Everything else still works.
			if dns, err := ringbuf.NewReader(m); err == nil {
				readTapRing(dns, handler, decodeDNS)
			} else {
				lost.Add(1)
			}
		}
		if m := coll.Maps["tap_tls"]; m != nil {
			// The same for a program from before TLS names.
			if tls, err := ringbuf.NewReader(m); err == nil {
				readTapRing(tls, handler, decodeTLS)
			} else {
				lost.Add(1)
			}
		}
	})
}

// readTapRing hands every record of a ring to decode and the result to handler. A record that does not decode
// is counted as lost, never guessed at.
func readTapRing(rd *ringbuf.Reader, handler func(event.Event), decode func([]byte, func(uint32) string) (event.Event, bool)) {
	go func() {
		var rec ringbuf.Record
		for {
			if err := rd.ReadInto(&rec); err != nil {
				if errors.Is(err, os.ErrClosed) {
					return
				}
				lost.Add(1)
				continue
			}
			if e, ok := decode(append([]byte(nil), rec.RawSample...), bpfgen.TapName); ok {
				handler(e)
			} else {
				lost.Add(1)
			}
		}
	}()
}

// SetDNSEvents turns DNS name events on or off in the kernel program. It is set on every start, since the
// switch is pinned and a previous run may have left it either way.
func SetDNSEvents(on bool) {
	if err := bpfgen.SetTapDNS(on); err != nil {
		log.Printf("tap program: DNS name events: %v", err)
	}
}

// SetTLSEvents turns TLS server name events on or off in the kernel program. It is set on every start, for
// the same reason as SetDNSEvents. With it off the program reads no TCP payload at all.
func SetTLSEvents(on bool) {
	if err := bpfgen.SetTapTLS(on); err != nil {
		log.Printf("tap program: TLS name events: %v", err)
	}
}

// decodeTap turns one tap ring sample into an event. The VM is filled in later,
// from the interface name, by whoever knows which VM owns that tap.
func decodeTap(b []byte, name func(ifindex uint32) string) (event.Event, bool) {
	if len(b) < tapEventSize {
		return event.Event{}, false
	}
	e := event.Event{
		Iface:   name(binary.LittleEndian.Uint32(b[8:12])),
		DPort:   binary.LittleEndian.Uint16(b[12:14]),
		Blocked: b[17] != 0,
		Policy:  policyName(b[20]),
	}
	// A TCP SYN is a connect and a new UDP flow is a flow. proto 0 is a TCP event
	// from a build that predates the field, which the previous program can still
	// emit during an upgrade until the new one is swapped in, so it is TCP.
	switch b[18] {
	case 0, 6:
		e.Kind, e.Proto = event.KindGuestConnect, "tcp"
		if b[19] == 1 { // a SYN sent to the guest: someone connecting in
			e.Kind = event.KindGuestInbound
		}
	case 17:
		e.Kind, e.Proto = event.KindGuestFlow, "udp"
	default:
		return event.Event{}, false
	}
	switch b[16] {
	case 2:
		e.Src, e.Dst = net.IP(b[24:28]).String(), net.IP(b[40:44]).String()
	case 10:
		e.Src, e.Dst = net.IP(b[24:40]).String(), net.IP(b[40:56]).String()
	default:
		return event.Event{}, false
	}
	if e.Iface == "" {
		return event.Event{}, false // a tap we no longer track
	}
	return e, true
}

// Enforcer turns isolation on and off on the taps that carry the program. It
// refuses to work without a management allow list: an isolated VM that could
// reach nothing could not be reached by the host that isolated it.
type Enforcer struct {
	allow    []netip.Prefix
	loadErr  error
	allowErr error
}

// NewEnforcer loads the allow list into the kernel program.
func NewEnforcer(allow []netip.Prefix) *Enforcer {
	e := &Enforcer{allow: allow}
	if len(allow) > 0 {
		e.allowErr = bpfgen.SetTapAllow(allow)
	}
	return e
}

func (e *Enforcer) Available() (bool, string) {
	loaded, _, err := bpfgen.TapStatus()
	switch {
	case !loaded || err != nil:
		return false, fmt.Sprintf("the tap program is not loaded: %v", err)
	case len(e.allow) == 0:
		return false, "no management allow list is configured (-isolate-allow), so refusing to isolate: an isolated VM must keep the access its host needs"
	case e.allowErr != nil:
		return false, fmt.Sprintf("the management allow list could not be loaded: %v", e.allowErr)
	}
	return true, ""
}

func (e *Enforcer) AllowList() []string {
	out := make([]string, 0, len(e.allow))
	for _, p := range e.allow {
		out = append(out, p.String())
	}
	return out
}

func (e *Enforcer) Isolated(tap string) bool { return bpfgen.TapIsolated(tap) }

// Durable reports whether isolation survives the daemon, which needs a bpf filesystem to pin on.
func (e *Enforcer) Durable() bool { return bpfgen.TapPinned() }

func (e *Enforcer) set(taps []string, on bool) ([]string, error) {
	var done []string
	var failed []string
	for _, t := range taps {
		if err := bpfgen.SetTapIsolated(t, on); err != nil {
			failed = append(failed, err.Error())
			continue
		}
		done = append(done, t)
	}
	if len(failed) > 0 {
		return done, errors.New(strings.Join(failed, "; "))
	}
	return done, nil
}

// Isolate flags the taps. It returns the ones that were flagged.
func (e *Enforcer) Isolate(taps []string) ([]string, error) { return e.set(taps, true) }

// Release clears the flag. It returns the taps that were cleared.
func (e *Enforcer) Release(taps []string) ([]string, error) { return e.set(taps, false) }

// EgressKernel is what the egress policy engine uses to reach the kernel program.
type EgressKernel struct{ enf *Enforcer }

// NewEgressKernel is the kernel side of the egress policy. Enforcement needs the management allow list that
// isolation needs, because that list is the floor no policy can take away: without one, a wrong policy could
// cut a VM off from the host that manages it. Auditing needs only the program.
func NewEgressKernel(enf *Enforcer) *EgressKernel { return &EgressKernel{enf: enf} }

// Available says whether the tap program is loaded, and if not, why not.
func (*EgressKernel) Available() (bool, string) {
	loaded, _, err := bpfgen.TapStatus()
	if err != nil {
		return false, err.Error()
	}
	return loaded, "not loaded"
}

// CanEnforce says whether a policy may be set to enforce, and if not, why not.
func (k *EgressKernel) CanEnforce() (bool, string) {
	if k.enf == nil {
		return false, "no management allow list is configured"
	}
	return k.enf.Available()
}

// Set puts a tap under an egress policy. mode is 0 (off), 1 (audit) or 2 (enforce).
func (*EgressKernel) Set(tap string, mode uint8, prefixes []netip.Prefix) error {
	return bpfgen.SetTapEgress(tap, mode, prefixes)
}

// Mode is the egress mode a tap is in: what was last set, or read back from the kernel when the tap was adopted.
func (*EgressKernel) Mode(tap string) uint8 { return bpfgen.TapEgress(tap) }

// Stats is what each attached tap's policy has done.
func (*EgressKernel) Stats() []EgressCounters {
	stats := bpfgen.TapEgressStats()
	var out []EgressCounters
	for _, name := range bpfgen.TapAttached() {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			continue
		}
		s := stats[uint32(iface.Index)]
		out = append(out, EgressCounters{Tap: name, Mode: bpfgen.TapEgress(name), Checked: s.Checked, AuditPkts: s.AuditPkts, AuditBytes: s.AuditBytes, DropPkts: s.DropPkts, DropBytes: s.DropBytes})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tap < out[j].Tap })
	return out
}
