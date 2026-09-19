// Package aggregate folds per-PID counters onto discovered QEMU virtual machines.
// PIDs that are not in a VM thread group stay in the host rollup. They are never given a fake VM name.
package aggregate

import (
	"github.com/zyvorai/shukra/internal/hist"
	"github.com/zyvorai/shukra/internal/identity"
)

const Host = "_host"

// Counters are scraped from maps, or supplied by tests. They are not guest metrics.
type Counters struct {
	Exits         map[uint32]uint64
	Entries       uint64
	MMIO          uint64
	PIO           uint64
	OnCPUNs       uint64
	WakeupDelayNs uint64
	WakeupCount   uint64
	BlockRead     []uint64
	BlockWrite    []uint64
	BlockReadMax  uint64
	BlockWriteMax uint64
	BlockIssues   uint64
	Connects      uint64
	Retransmits   uint64
}

type Reason struct {
	Reason uint32 `json:"reason"`
	Count  uint64 `json:"count"`
}

type KVMRow struct {
	VM       string   `json:"vm"`
	Runtime  string   `json:"runtime,omitempty"`
	Exits    uint64   `json:"exits"`
	Entries  uint64   `json:"entries"`
	MMIO     uint64   `json:"mmio"`
	PIO      uint64   `json:"pio"`
	Top      []Reason `json:"topReasons"`
	Measured bool     `json:"measured"`
}

type SchedRow struct {
	VM            string `json:"vm"`
	OnCPUNs       uint64 `json:"onCpuNs"`
	WakeupDelayNs uint64 `json:"wakeupDelayNs"`
	WakeupCount   uint64 `json:"wakeupCount"`
	Measured      bool   `json:"measured"`
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
	Measured   bool   `json:"measured"`
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
	dst.Entries += src.Entries
	dst.MMIO += src.MMIO
	dst.PIO += src.PIO
	dst.OnCPUNs += src.OnCPUNs
	dst.WakeupDelayNs += src.WakeupDelayNs
	dst.WakeupCount += src.WakeupCount
	dst.BlockRead = addHist(dst.BlockRead, src.BlockRead)
	dst.BlockWrite = addHist(dst.BlockWrite, src.BlockWrite)
	if src.BlockReadMax > dst.BlockReadMax {
		dst.BlockReadMax = src.BlockReadMax
	}
	if src.BlockWriteMax > dst.BlockWriteMax {
		dst.BlockWriteMax = src.BlockWriteMax
	}
	dst.BlockIssues += src.BlockIssues
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

// KVM aggregates exit reasons. Top is the three largest reasons.
func KVM(vms []identity.VM, byPID map[uint32]Counters, vm string) []KVMRow {
	var out []KVMRow
	for _, b := range filter(group(vms, byPID), vm) {
		var exits uint64
		var top []Reason
		for reason, n := range b.c.Exits {
			exits += n
			top = append(top, Reason{Reason: reason, Count: n})
		}
		sortReasons(top)
		if len(top) > 3 {
			top = top[:3]
		}
		out = append(out, KVMRow{
			VM: b.name, Runtime: b.runtime, Exits: exits, Entries: b.c.Entries,
			MMIO: b.c.MMIO, PIO: b.c.PIO, Top: top, Measured: exits+b.c.Entries+b.c.MMIO+b.c.PIO > 0,
		})
	}
	return out
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
		})
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
