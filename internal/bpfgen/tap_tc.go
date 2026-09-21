//go:build linux && shukrabpf

package bpfgen

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// TCPriority is the clsact filter priority. A later filter (a higher number)
// still runs when Shukra passes a packet, because the classic program returns
// TC_ACT_PIPE rather than TC_ACT_OK.
const TCPriority uint16 = 50

const (
	tcNameFrom = "shukra-from"
	tcNameTo   = "shukra-to"
)

func ingressParent() uint32 { return core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress) }
func egressParent() uint32  { return core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress) }

func qdiscMark(ifindex uint32) string {
	return filepath.Join(TapPinDir, fmt.Sprintf("qdisc-%d", ifindex))
}

func openTC() (*tc.Tc, error) {
	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, err
	}
	if err := rtnl.SetOption(netlink.ExtendedAcknowledge, true); err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
		// Older kernels omit the option. The qdisc calls still work.
		_ = err
	}
	return rtnl, nil
}

func clsactObject(ifindex uint32) tc.Object {
	return tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Handle:  core.BuildHandle(tc.HandleRoot, 0),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{Kind: "clsact"},
	}
}

func exists(err error) bool {
	return err != nil && (errors.Is(err, unix.EEXIST) || os.IsExist(err) || strings.Contains(err.Error(), "file exists"))
}

// ensureClsact adds clsact or reuses one that is already there. made is true
// only when this call created it. A marker file remembers that across restarts
// so a later detach can delete the qdisc if no other filter remains.
func ensureClsact(rtnl *tc.Tc, ifindex uint32) (bool, error) {
	q := clsactObject(ifindex)
	err := rtnl.Qdisc().Add(&q)
	if err == nil {
		_ = os.WriteFile(qdiscMark(ifindex), []byte("clsact\n"), 0o644)
		return true, nil
	}
	if exists(err) {
		return false, nil
	}
	return false, fmt.Errorf("clsact: %w", err)
}

func bpfFilter(ifindex uint32, ingress bool, fd int, name string) tc.Object {
	parent := egressParent()
	if ingress {
		parent = ingressParent()
	}
	fdu := uint32(fd)
	flags := uint32(tc.BpfActDirect)
	nm := name
	return tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Parent:  parent,
			Info:    core.FilterInfo(TCPriority, unix.ETH_P_ALL),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF:  &tc.Bpf{FD: &fdu, Name: &nm, Flags: &flags},
		},
	}
}

func putFilter(rtnl *tc.Tc, ifindex uint32, ingress bool, fd int, name string) error {
	if fd < 0 {
		return errors.New("bpf program has no file descriptor")
	}
	obj := bpfFilter(ifindex, ingress, fd, name)
	if err := rtnl.Filter().Replace(&obj); err != nil {
		return fmt.Errorf("filter %s: %w", name, err)
	}
	return nil
}

func removeNamed(rtnl *tc.Tc, ifindex uint32, name string) {
	for _, parent := range []uint32{ingressParent(), egressParent()} {
		objs, err := rtnl.Filter().Get(&tc.Msg{Ifindex: ifindex, Parent: parent})
		if err != nil {
			continue
		}
		for _, o := range objs {
			if o.BPF == nil || o.BPF.Name == nil || *o.BPF.Name != name {
				continue
			}
			del := tc.Object{
				Msg: tc.Msg{
					Family: unix.AF_UNSPEC, Ifindex: ifindex,
					Parent: o.Msg.Parent, Info: o.Msg.Info, Handle: o.Msg.Handle,
				},
				Attribute: tc.Attribute{Kind: "bpf"},
			}
			_ = rtnl.Filter().Delete(&del)
		}
	}
}

func shukraName(o tc.Object) bool {
	if o.BPF == nil || o.BPF.Name == nil {
		return false
	}
	return *o.BPF.Name == tcNameFrom || *o.BPF.Name == tcNameTo
}

func countOthers(rtnl *tc.Tc, ifindex uint32) int {
	n := 0
	for _, parent := range []uint32{ingressParent(), egressParent()} {
		objs, err := rtnl.Filter().Get(&tc.Msg{Ifindex: ifindex, Parent: parent})
		if err != nil {
			continue
		}
		for _, o := range objs {
			if o.Attribute.Kind == "" || shukraName(o) {
				continue
			}
			n++
		}
	}
	return n
}

// attachTCLocked installs the classic sched_cls programs. The caller holds tapMgr.mu.
func attachTCLocked(name string, ifindex uint32) error {
	from := tapMgr.coll.Programs["shukra_tap_from_guest_tc"]
	to := tapMgr.coll.Programs["shukra_tap_to_guest_tc"]
	if from == nil || to == nil {
		return errors.New("this build has no clsact programs (run make generate)")
	}
	rtnl, err := openTC()
	if err != nil {
		return err
	}
	defer rtnl.Close()
	made, err := ensureClsact(rtnl, ifindex)
	if err != nil {
		return err
	}
	if err := putFilter(rtnl, ifindex, true, from.FD(), tcNameFrom); err != nil {
		return err
	}
	if err := putFilter(rtnl, ifindex, false, to.FD(), tcNameTo); err != nil {
		removeNamed(rtnl, ifindex, tcNameFrom)
		return err
	}
	tapMgr.taps[name] = &tapLinks{ifindex: ifindex, hook: "tc", madeQdisc: made}
	tapMgr.hook = "tc"
	tapMgr.others = countOthers(rtnl, ifindex)
	tapMgr.lastErr = ""
	return nil
}

func detachTC(ifindex uint32, made bool) {
	rtnl, err := openTC()
	if err != nil {
		return
	}
	defer rtnl.Close()
	removeNamed(rtnl, ifindex, tcNameFrom)
	removeNamed(rtnl, ifindex, tcNameTo)
	if !made && !qdiscMarked(ifindex) {
		return
	}
	if countOthers(rtnl, ifindex) != 0 {
		return
	}
	q := clsactObject(ifindex)
	_ = rtnl.Qdisc().Delete(&q)
	_ = os.Remove(qdiscMark(ifindex))
}

func qdiscMarked(ifindex uint32) bool {
	_, err := os.Stat(qdiscMark(ifindex))
	return err == nil
}

// dropOrphanTC removes Shukra filters from interfaces that are no longer wanted.
// It deletes clsact only when this process created it and nothing else remains.
func dropOrphanTC(want map[string]bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	rtnl, err := openTC()
	if err != nil {
		return
	}
	defer rtnl.Close()
	for _, iface := range ifaces {
		if want[iface.Name] {
			continue
		}
		idx := uint32(iface.Index)
		owned := false
		for _, parent := range []uint32{ingressParent(), egressParent()} {
			objs, err := rtnl.Filter().Get(&tc.Msg{Ifindex: idx, Parent: parent})
			if err != nil {
				continue
			}
			for _, o := range objs {
				if shukraName(o) {
					owned = true
				}
			}
		}
		if !owned {
			continue
		}
		removeNamed(rtnl, idx, tcNameFrom)
		removeNamed(rtnl, idx, tcNameTo)
		if qdiscMarked(idx) && countOthers(rtnl, idx) == 0 {
			q := clsactObject(idx)
			_ = rtnl.Qdisc().Delete(&q)
			_ = os.Remove(qdiscMark(idx))
		}
	}
}

// TapAttachInfo reports the hook in use. priority and others are meaningful for tc.
func TapAttachInfo() (hook string, priority, others int) {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	hook = tapMgr.hook
	if hook == "" {
		for _, t := range tapMgr.taps {
			if t.hook != "" {
				hook = t.hook
				break
			}
		}
	}
	if hook == "tc" {
		return "tc", int(TCPriority), tapMgr.others
	}
	if hook == "tcx" {
		return "tcx", 0, 0
	}
	return "", 0, 0
}

// TapLastError is the most recent attach failure, including a host-only miss.
func TapLastError() string {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	return tapMgr.lastErr
}
