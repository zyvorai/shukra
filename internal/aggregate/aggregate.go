// Package aggregate folds per-PID counters onto discovered QEMU virtual machines.
// PIDs that are not in a VM thread group stay in the host rollup. They are never given a fake VM name.
package aggregate

import (
	"github.com/zyvorai/shukra/internal/hist"
	"github.com/zyvorai/shukra/internal/identity"
)

// SlowBlockNS and SlowWakeupNS match bpf/event.h. A row below these lines is not called slow.
const (
	Host         = "_host"
	SlowBlockNS  = 10_000_000
	SlowWakeupNS = 20_000_000
)

// Counters are scraped from maps, or supplied by tests. They are not guest metrics.
type Counters struct {
	Exits                           map[uint32]uint64
	ExitNs                          map[uint32]uint64 // handling time per exit reason, halts included
	KVMLat                          []uint64          // exit handling time, log2 ns, halts left out
	Entries                         uint64
	MMIO                            uint64
	PIO                             uint64
	OnCPUNs                         uint64
	WakeupDelayNs                   uint64
	WakeupCount                     uint64
	SchedHist                       []uint64 // run-queue delay, log2 ns
	BlockRead                       []uint64
	BlockWrite                      []uint64
	BlockReadMax                    uint64
	BlockWriteMax                   uint64
	BlockReadOps, BlockWriteOps     uint64
	BlockReadBytes, BlockWriteBytes uint64
	BlockIssues                     uint64
	Connects                        uint64
	Retransmits                     uint64
}

type Reason struct {
	Reason uint32 `json:"reason"`
	Count  uint64 `json:"count"`
	// TotalNs is the host time spent handling this reason. For a halt it is guest
	// idle time, which is why halts are not in the latency histogram.
	TotalNs uint64 `json:"totalNs"`
	// Name is set only where the exit numbering is known for the CPU vendor.
	Name string `json:"name,omitempty"`
}

type KVMRow struct {
	VM      string   `json:"vm"`
	Runtime string   `json:"runtime,omitempty"`
	Exits   uint64   `json:"exits"`
	Entries uint64   `json:"entries"`
	MMIO    uint64   `json:"mmio"`
	PIO     uint64   `json:"pio"`
	Top     []Reason `json:"topReasons"`
	// TopByTime is the reasons that cost the most host time. It is not the same list
	// as Top: a rare, slow exit can outweigh a common, fast one.
	TopByTime []Reason `json:"topReasonsByTime"`
	// AllReasons is every reason seen, most frequent first. It is not in the JSON:
	// the metrics endpoint needs a stable set of series, and the top three change.
	AllReasons []Reason `json:"-"`
	// Handling latency, kvm_exit to the next kvm_entry, halts excluded. Percentiles
	// are log2 bucket edges, so up to 2x high.
	LatencyP50Ns uint64   `json:"exitLatencyP50Ns"`
	LatencyP99Ns uint64   `json:"exitLatencyP99Ns"`
	LatencyHist  []uint64 `json:"exitLatencyHist,omitempty"`
	Measured     bool     `json:"measured"`
}

type SchedRow struct {
	VM            string `json:"vm"`
	OnCPUNs       uint64 `json:"onCpuNs"`
	WakeupDelayNs uint64 `json:"wakeupDelayNs"`
	WakeupCount   uint64 `json:"wakeupCount"`
	// Run-queue delay percentiles are log2 bucket edges, so up to 2x high.
	WakeupDelayP50Ns uint64   `json:"wakeupDelayP50Ns"`
	WakeupDelayP99Ns uint64   `json:"wakeupDelayP99Ns"`
	WakeupHist       []uint64 `json:"wakeupHist,omitempty"`
	Measured         bool     `json:"measured"`
}

type BlockRow struct {
	VM         string `json:"vm"`
	Issues     uint64 `json:"issues"`
	ReadP50Ns  uint64 `json:"readP50Ns"`
	ReadP99Ns  uint64 `json:"readP99Ns"`
	WriteP50Ns uint64 `json:"writeP50Ns"`
	WriteP99Ns uint64 `json:"writeP99Ns"`
	ReadMaxNs  uint64 `json:"readMaxNs"`
	WriteMaxNs uint64 `json:"writeMaxNs"`
	// Completed requests and bytes on the QEMU iothread, not the guest filesystem.
	ReadOps    uint64   `json:"readOps"`
	WriteOps   uint64   `json:"writeOps"`
	ReadBytes  uint64   `json:"readBytes"`
	WriteBytes uint64   `json:"writeBytes"`
	ReadHist   []uint64 `json:"readHist,omitempty"`
	WriteHist  []uint64 `json:"writeHist,omitempty"`
	Measured   bool     `json:"measured"`
}

type NetRow struct {
	VM              string `json:"vm"`
	Connects        uint64 `json:"connects"`
	Retransmits     uint64 `json:"retransmits"`
	Attribution     string `json:"attribution"`
	GuestAttributed bool   `json:"guest_attributed"`
	Note            string `json:"note"`
}

func add(dst, src *Counters) {
	if src.Exits != nil {
		if dst.Exits == nil {
			dst.Exits = map[uint32]uint64{}
		}
		for k, v := range src.Exits {
			dst.Exits[k] += v
		}
	}
	if src.ExitNs != nil {
		if dst.ExitNs == nil {
			dst.ExitNs = map[uint32]uint64{}
		}
		for k, v := range src.ExitNs {
			dst.ExitNs[k] += v
		}
	}
	dst.KVMLat = addHist(dst.KVMLat, src.KVMLat)
	dst.Entries += src.Entries
	dst.MMIO += src.MMIO
	dst.PIO += src.PIO
	dst.OnCPUNs += src.OnCPUNs
	dst.WakeupDelayNs += src.WakeupDelayNs
	dst.WakeupCount += src.WakeupCount
	dst.SchedHist = addHist(dst.SchedHist, src.SchedHist)
	dst.BlockRead = addHist(dst.BlockRead, src.BlockRead)
	dst.BlockWrite = addHist(dst.BlockWrite, src.BlockWrite)
	if src.BlockReadMax > dst.BlockReadMax {
		dst.BlockReadMax = src.BlockReadMax
	}
	if src.BlockWriteMax > dst.BlockWriteMax {
		dst.BlockWriteMax = src.BlockWriteMax
	}
	dst.BlockIssues += src.BlockIssues
	dst.BlockReadOps += src.BlockReadOps
	dst.BlockWriteOps += src.BlockWriteOps
	dst.BlockReadBytes += src.BlockReadBytes
	dst.BlockWriteBytes += src.BlockWriteBytes
	dst.Connects += src.Connects
	dst.Retransmits += src.Retransmits
}

func addHist(a, b []uint64) []uint64 {
	if len(b) == 0 {
		return a
	}
	if a == nil {
		a = make([]uint64, hist.Buckets)
	}
	for i := 0; i < len(b) && i < len(a); i++ {
		a[i] += b[i]
	}
	return a
}

type bucket struct {
	name    string
	runtime string
	c       Counters
}

func group(vms []identity.VM, byPID map[uint32]Counters) []bucket {
	owned := map[uint32]string{}
	var rows []bucket
	index := map[string]int{}
	for _, vm := range vms {
		index[vm.Name] = len(rows)
		rows = append(rows, bucket{name: vm.Name, runtime: vm.Runtime})
		owned[uint32(vm.PID)] = vm.Name
		for _, tid := range vm.Threads {
			owned[uint32(tid)] = vm.Name
		}
	}
	host := bucket{name: Host}
	hostUsed := false
	for pid, c := range byPID {
		name, ok := owned[pid]
		if !ok {
			add(&host.c, &c)
			hostUsed = true
			continue
		}
		b := &rows[index[name]]
		add(&b.c, &c)
	}
	if hostUsed {
		rows = append(rows, host)
	}
	return rows
}

// PerVM folds per-PID counters onto each discovered VM by name. The host rollup
// is left out: a PID that is not a QEMU thread has no VM to alert on.
func PerVM(vms []identity.VM, byPID map[uint32]Counters) map[string]Counters {
	out := map[string]Counters{}
	for _, b := range group(vms, byPID) {
		if b.name != Host {
			out[b.name] = b.c
		}
	}
	return out
}

// TotalExits is the sum of the per-reason exit counts.
func (c Counters) TotalExits() uint64 {
	var n uint64
	for _, v := range c.Exits {
		n += v
	}
	return n
}

func filter(rows []bucket, vm string) []bucket {
	if vm == "" {
		return rows
	}
	var out []bucket
	for _, r := range rows {
		if r.name == vm {
			out = append(out, r)
		}
	}
	return out
}

// KVM aggregates exit reasons. Top is the three most frequent reasons and
// TopByTime the three that cost the most host time.
func KVM(vms []identity.VM, byPID map[uint32]Counters, vm string) []KVMRow {
	var out []KVMRow
	for _, b := range filter(group(vms, byPID), vm) {
		var exits uint64
		var top []Reason
		for reason, n := range b.c.Exits {
			exits += n
			top = append(top, Reason{Reason: reason, Count: n, TotalNs: b.c.ExitNs[reason]})
		}
		byTime := append([]Reason(nil), top...)
		sortReasons(top)
		sortReasonsByTime(byTime)
		all := append([]Reason(nil), top...)
		if len(top) > 3 {
			top = top[:3]
		}
		if len(byTime) > 3 {
			byTime = byTime[:3]
		}
		out = append(out, KVMRow{
			VM: b.name, Runtime: b.runtime, Exits: exits, Entries: b.c.Entries,
			MMIO: b.c.MMIO, PIO: b.c.PIO, Top: top, TopByTime: byTime, AllReasons: all,
			LatencyP50Ns: hist.Percentile(b.c.KVMLat, 50), LatencyP99Ns: hist.Percentile(b.c.KVMLat, 99),
			LatencyHist: b.c.KVMLat,
			Measured:    exits+b.c.Entries+b.c.MMIO+b.c.PIO > 0,
		})
	}
	return out
}

func sortReasonsByTime(rs []Reason) {
	for i := 1; i < len(rs); i++ {
		j := i
		for j > 0 && rs[j].TotalNs > rs[j-1].TotalNs {
			rs[j], rs[j-1] = rs[j-1], rs[j]
			j--
		}
	}
}

func sortReasons(rs []Reason) {
	for i := 1; i < len(rs); i++ {
		j := i
		for j > 0 && rs[j].Count > rs[j-1].Count {
			rs[j], rs[j-1] = rs[j-1], rs[j]
			j--
		}
	}
}

// Sched aggregates wakeup delay and on-CPU time.
func Sched(vms []identity.VM, byPID map[uint32]Counters, vm string) []SchedRow {
	var out []SchedRow
	for _, b := range filter(group(vms, byPID), vm) {
		out = append(out, SchedRow{
			VM: b.name, OnCPUNs: b.c.OnCPUNs, WakeupDelayNs: b.c.WakeupDelayNs,
			WakeupCount: b.c.WakeupCount, Measured: b.c.OnCPUNs+b.c.WakeupCount > 0,
			WakeupDelayP50Ns: hist.Percentile(b.c.SchedHist, 50),
			WakeupDelayP99Ns: hist.Percentile(b.c.SchedHist, 99),
			WakeupHist:       b.c.SchedHist,
		})
	}
	return out
}

// ThreadRow is one QEMU thread's scheduler counters, so a slow vCPU can be told
// apart from a slow iothread. Role is inferred from the thread's comm.
type ThreadRow struct {
	VM               string `json:"vm"`
	TID              int    `json:"tid"`
	Comm             string `json:"comm,omitempty"`
	Role             string `json:"role"`
	OnCPUNs          uint64 `json:"onCpuNs"`
	WakeupDelayNs    uint64 `json:"wakeupDelayNs"`
	WakeupCount      uint64 `json:"wakeupCount"`
	WakeupDelayP99Ns uint64 `json:"wakeupDelayP99Ns"`
}

// SchedThreads breaks the scheduler counters down by QEMU thread. A thread with
// no counters yet is left out rather than shown as zero.
func SchedThreads(vms []identity.VM, byPID map[uint32]Counters, vm string) []ThreadRow {
	var out []ThreadRow
	for _, v := range vms {
		if vm != "" && v.Name != vm {
			continue
		}
		info := v.ThreadInfo
		if len(info) == 0 {
			for _, tid := range v.Threads {
				info = append(info, identity.Thread{TID: tid, Role: "unknown"})
			}
		}
		for _, t := range info {
			c, ok := byPID[uint32(t.TID)]
			if !ok {
				continue
			}
			out = append(out, ThreadRow{
				VM: v.Name, TID: t.TID, Comm: t.Comm, Role: t.Role,
				OnCPUNs: c.OnCPUNs, WakeupDelayNs: c.WakeupDelayNs, WakeupCount: c.WakeupCount,
				WakeupDelayP99Ns: hist.Percentile(c.SchedHist, 99),
			})
		}
	}
	return out
}

// Block computes p50 and p99 from the log2 histogram.
func Block(vms []identity.VM, byPID map[uint32]Counters, vm string) []BlockRow {
	var out []BlockRow
	for _, b := range filter(group(vms, byPID), vm) {
		out = append(out, BlockRow{
			VM: b.name, Issues: b.c.BlockIssues,
			ReadP50Ns: hist.Percentile(b.c.BlockRead, 50), ReadP99Ns: hist.Percentile(b.c.BlockRead, 99),
			WriteP50Ns: hist.Percentile(b.c.BlockWrite, 50), WriteP99Ns: hist.Percentile(b.c.BlockWrite, 99),
			ReadMaxNs: b.c.BlockReadMax, WriteMaxNs: b.c.BlockWriteMax,
			ReadOps: b.c.BlockReadOps, WriteOps: b.c.BlockWriteOps,
			ReadBytes: b.c.BlockReadBytes, WriteBytes: b.c.BlockWriteBytes,
			ReadHist: b.c.BlockRead, WriteHist: b.c.BlockWrite,
			Measured: b.c.BlockIssues > 0,
		})
	}
	return out
}

// Net is host TCP observed on the QEMU process. guest_attributed is always false.
func Net(vms []identity.VM, byPID map[uint32]Counters, vm string) []NetRow {
	var out []NetRow
	for _, b := range filter(group(vms, byPID), vm) {
		attr := "unattributed"
		note := "Not a QEMU thread. Not guest traffic."
		if b.name != Host {
			attr = "qemu-process"
			note = "Connects and retransmits from the QEMU process, not the guest. Tap/TCX attribution is not attached."
		}
		out = append(out, NetRow{
			VM: b.name, Connects: b.c.Connects, Retransmits: b.c.Retransmits,
			Attribution: attr, GuestAttributed: false, Note: note,
		})
	}
	return out
}

// Delta is what accumulated between base and cur: the counters over a window. A
// counter that went backwards (a thread that exited and a new one took its id, or
// an entry that was evicted and re-created) has been reset, so what cur holds is
// what accumulated since the reset, and that is used as-is instead of a negative
// or enormous difference.
func Delta(cur, base Counters) Counters {
	d := Counters{
		Entries: sub(cur.Entries, base.Entries), MMIO: sub(cur.MMIO, base.MMIO), PIO: sub(cur.PIO, base.PIO),
		OnCPUNs: sub(cur.OnCPUNs, base.OnCPUNs), WakeupDelayNs: sub(cur.WakeupDelayNs, base.WakeupDelayNs),
		WakeupCount:     sub(cur.WakeupCount, base.WakeupCount),
		BlockIssues:     sub(cur.BlockIssues, base.BlockIssues),
		BlockReadOps:    sub(cur.BlockReadOps, base.BlockReadOps),
		BlockWriteOps:   sub(cur.BlockWriteOps, base.BlockWriteOps),
		BlockReadBytes:  sub(cur.BlockReadBytes, base.BlockReadBytes),
		BlockWriteBytes: sub(cur.BlockWriteBytes, base.BlockWriteBytes),
		Connects:        sub(cur.Connects, base.Connects), Retransmits: sub(cur.Retransmits, base.Retransmits),
		// A maximum is not a rate: it cannot be subtracted, and the window's own
		// maximum is not known. Report the lifetime one rather than a wrong number.
		BlockReadMax: cur.BlockReadMax, BlockWriteMax: cur.BlockWriteMax,
	}
	d.Exits = subMap(cur.Exits, base.Exits)
	d.ExitNs = subMap(cur.ExitNs, base.ExitNs)
	d.KVMLat = subHist(cur.KVMLat, base.KVMLat)
	d.SchedHist = subHist(cur.SchedHist, base.SchedHist)
	d.BlockRead = subHist(cur.BlockRead, base.BlockRead)
	d.BlockWrite = subHist(cur.BlockWrite, base.BlockWrite)
	return d
}

func sub(cur, base uint64) uint64 {
	if cur < base {
		return cur
	}
	return cur - base
}

func subMap(cur, base map[uint32]uint64) map[uint32]uint64 {
	if cur == nil {
		return nil
	}
	out := make(map[uint32]uint64, len(cur))
	for k, v := range cur {
		out[k] = sub(v, base[k])
	}
	return out
}

func subHist(cur, base []uint64) []uint64 {
	if cur == nil {
		return nil
	}
	out := make([]uint64, len(cur))
	for i, v := range cur {
		var b uint64
		if i < len(base) {
			b = base[i]
		}
		out[i] = sub(v, b)
	}
	return out
}

// Clone copies a Counters so a later change to the original cannot alter it.
func (c Counters) Clone() Counters {
	out := c
	out.Exits = subMap(c.Exits, nil)
	out.ExitNs = subMap(c.ExitNs, nil)
	out.KVMLat = append([]uint64(nil), c.KVMLat...)
	out.SchedHist = append([]uint64(nil), c.SchedHist...)
	out.BlockRead = append([]uint64(nil), c.BlockRead...)
	out.BlockWrite = append([]uint64(nil), c.BlockWrite...)
	return out
}

// TapTotals are one VM's cumulative counters that come from its taps, not from the per-thread maps: what
// the threshold rules read for guest traffic. A field is only meaningful while its OK flag is set: a
// program that is not measuring has no zero to report.
type TapTotals struct {
	ForeignDrops uint64 // packets the kernel dropped on the taps that Shukra did not (excluding a full queue)
	DropsOK      bool
	OutRefused   uint64 // the guest's connections that were refused
	OutTimeout   uint64 // the guest's connections that were never answered
	InSyn        uint64 // connections attempted to the guest
	OutcomesOK   bool
}
