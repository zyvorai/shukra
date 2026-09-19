package aggregate

// vmxExitNames are the basic exit reasons from the Intel SDM (appendix C), which
// is what KVM's kvm_exit tracepoint reports on an Intel host.
var vmxExitNames = map[uint32]string{
	0: "exception_nmi", 1: "external_interrupt", 2: "triple_fault", 3: "init_signal", 4: "sipi",
	5: "io_smi", 6: "other_smi", 7: "interrupt_window", 8: "nmi_window", 9: "task_switch",
	10: "cpuid", 11: "getsec", 12: "hlt", 13: "invd", 14: "invlpg", 15: "rdpmc", 16: "rdtsc",
	17: "rsm", 18: "vmcall", 19: "vmclear", 20: "vmlaunch", 21: "vmptrld", 22: "vmptrst",
	23: "vmread", 24: "vmresume", 25: "vmwrite", 26: "vmxoff", 27: "vmxon", 28: "cr_access",
	29: "dr_access", 30: "io_instruction", 31: "rdmsr", 32: "wrmsr", 33: "invalid_guest_state",
	34: "msr_load_fail", 36: "mwait", 37: "monitor_trap_flag", 39: "monitor", 40: "pause",
	41: "machine_check", 43: "tpr_below_threshold", 44: "apic_access", 45: "virtualized_eoi",
	46: "gdtr_idtr_access", 47: "ldtr_tr_access", 48: "ept_violation", 49: "ept_misconfig",
	50: "invept", 51: "rdtscp", 52: "preemption_timer", 53: "invvpid", 54: "wbinvd",
	55: "xsetbv", 56: "apic_write", 57: "rdrand", 58: "invpcid", 59: "vmfunc", 60: "encls",
	61: "rdseed", 62: "pml_full", 63: "xsaves", 64: "xrstors", 67: "umwait", 68: "tpause",
	69: "loadiwkey",
}

// ExitName names a KVM exit reason for the CPU vendor it was read on. It returns
// "" when it cannot say, and that is deliberate: AMD's SVM exit codes reuse small
// numbers for other things, and arm64 reports an exception class, so applying the
// Intel table there would give a confident wrong name. Flag bits above the low 16
// (a failed VM entry sets bit 31) are ignored for the lookup.
func ExitName(vendor string, reason uint32) string {
	if vendor != "GenuineIntel" {
		return ""
	}
	return vmxExitNames[reason&0xffff]
}

// NameReasons fills in Name on every listed reason of rows.
func NameReasons(rows []KVMRow, vendor string) {
	for i := range rows {
		for _, list := range [][]Reason{rows[i].Top, rows[i].TopByTime, rows[i].AllReasons} {
			for j := range list {
				list[j].Name = ExitName(vendor, list[j].Reason)
			}
		}
	}
}
