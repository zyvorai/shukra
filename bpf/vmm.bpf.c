//go:build ignore

/* VMM tripwires. A QEMU process in steady state opens no files and never calls ptrace, mount, unshare, setns
   or the module and kexec calls: it has its disk images open already, and talks to the guest through memory.
   So when one does (or a process it started does), something is wrong: a guest that escaped into the VMM,
   or an operator with a shell in it. This program reports those calls, for the processes that are VMMs and
   what descends from them, and for no one else.

   The tracepoints fire for every process on the host, so the first thing each does is find out whether the
   caller is a VMM: one lookup for itself and up to three ancestors, which is all a shell and the program it
   runs need. A host that is not a VMM's costs a few map lookups and returns. The path of an open is
   copied out as it was given, and userspace decides which are sensitive, so the list can change without a
   new program; the kernel only limits how many a VMM can report a second.

   It is a tripwire and not a sandbox. The path is read when the call starts, so a path that is changed after
   that is not seen; a relative path is reported as it was given; and a process that does none of these
   things is not seen at all. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* At most this many reported calls per VMM per second. A VMM that does more is flooding, which is itself
   reported (VMM_FLOOD) once the second is over, with how many were not. */
#define VMM_PER_SEC 300
#define VMM_PATH 256

/* What was called. The numbers are this program's own and not the architecture's syscall numbers, so they mean
   the same everywhere. internal/observe/vmm.go mirrors them. */
#define VMM_OPENAT 1
#define VMM_OPENAT2 2
#define VMM_OPEN 3
#define VMM_PTRACE 10
#define VMM_PROCESS_VM_WRITEV 11
#define VMM_PROCESS_VM_READV 12
#define VMM_MOUNT 13
#define VMM_UNSHARE 14
#define VMM_SETNS 15
#define VMM_INIT_MODULE 16
#define VMM_FINIT_MODULE 17
#define VMM_KEXEC_LOAD 18
#define VMM_KEXEC_FILE_LOAD 19
#define VMM_FLOOD 255

#define AT_FDCWD_ -100

/* Decoded by offset in internal/observe/vmm.go. Every field is placed explicitly. */
struct vmm_event {
	__u64 ts_ns;         /* 0 */
	__u32 root;          /* 8: the VMM this is, or descends from */
	__u32 pid;           /* 12: the process that made the call */
	__u32 tid;           /* 16: and its thread */
	__u32 call;          /* 20: VMM_* */
	__s32 dfd;           /* 24: the directory an open's path is relative to */
	__u32 flags;         /* 28: an open's flags */
	__u64 arg0;          /* 32: the call's first argument, or for a flood how many calls were not reported */
	__u64 arg1;          /* 40: and its second */
	__u16 pathlen;       /* 48: bytes of path that are the caller's, with the NUL; 0 when it could not be read */
	__u8 pad[6];         /* 50 */
	char comm[16];       /* 56 */
	char path[VMM_PATH]; /* 72 */
};                           /* 328 */

_Static_assert(sizeof(struct vmm_event) == 328, "vmm_event layout changed: update internal/observe/vmm.go");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} vmm_events SEC(".maps");

/* The VMMs: the tgids of QEMU (and other VMM) processes. Userspace keeps it to what a scan of /proc finds. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} vmm_watched SEC(".maps");

struct vmm_rate {
	__u64 window_ns;
	__u64 count;
	__u64 dropped;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct vmm_rate);
} vmm_rate SEC(".maps");

/* The VMM the caller is, or descends from through at most three parents: a shell started by a VMM, and the
   program the shell runs. 0 when it is neither. */
static __always_inline __u32 vmm_root(void) {
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (bpf_map_lookup_elem(&vmm_watched, &tgid))
		return tgid;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
#pragma unroll
	for (int i = 0; i < 3; i++) {
		t = BPF_CORE_READ(t, real_parent);
		if (!t)
			return 0;
		__u32 g = BPF_CORE_READ(t, tgid);
		if (g <= 1)
			return 0; /* init: nothing above it is a VMM */
		if (bpf_map_lookup_elem(&vmm_watched, &g))
			return g;
	}
	return 0;
}

/* Whether this VMM may report another call this second. When the previous second had calls that were not
   reported, dropped says how many, once, so a flood is not silent. */
static __always_inline int vmm_allow(__u32 root, __u64 *dropped) {
	__u64 now = bpf_ktime_get_ns();
	struct vmm_rate *r = bpf_map_lookup_elem(&vmm_rate, &root);
	if (!r) {
		struct vmm_rate fresh = {.window_ns = now};
		bpf_map_update_elem(&vmm_rate, &root, &fresh, BPF_NOEXIST);
		r = bpf_map_lookup_elem(&vmm_rate, &root);
		if (!r)
			return 0;
	}
	if (now - r->window_ns >= 1000000000ull) {
		*dropped = r->dropped;
		r->window_ns = now;
		r->count = 0;
		r->dropped = 0;
	}
	if (__sync_fetch_and_add(&r->count, 1) < VMM_PER_SEC)
		return 1;
	__sync_fetch_and_add(&r->dropped, 1);
	return 0;
}

/* Reserve a record for a call by the current task, with everything but the path filled in. Only the header is
   cleared: the path is 256 bytes and only pathlen of them are ever read. */
static __always_inline struct vmm_event *vmm_begin(__u32 root, __u32 call) {
	struct vmm_event *e = bpf_ringbuf_reserve(&vmm_events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, __builtin_offsetof(struct vmm_event, path));
	__u64 pt = bpf_get_current_pid_tgid();
	e->ts_ns = bpf_ktime_get_ns();
	e->root = root;
	e->pid = pt >> 32;
	e->tid = (__u32)pt;
	e->call = call;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

static __always_inline void vmm_flood(__u32 root, __u64 dropped) {
	struct vmm_event *e = vmm_begin(root, VMM_FLOOD);
	if (!e)
		return;
	e->arg0 = dropped;
	bpf_ringbuf_submit(e, 0);
}

/* A file the VMM (or something it started) opens. */
static __always_inline int vmm_open(__u32 call, long dfd, const char *filename, long flags) {
	__u32 root = vmm_root();
	if (!root)
		return 0;
	__u64 dropped = 0;
	if (!vmm_allow(root, &dropped))
		return 0;
	if (dropped)
		vmm_flood(root, dropped);
	struct vmm_event *e = vmm_begin(root, call);
	if (!e)
		return 0;
	e->dfd = (__s32)dfd;
	e->flags = (__u32)flags;
	long n = bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
	if (n > 0)
		e->pathlen = (__u16)n;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* A call that has no path to report: which one, and its first two arguments. */
static __always_inline int vmm_call(__u32 call, __u64 arg0, __u64 arg1) {
	__u32 root = vmm_root();
	if (!root)
		return 0;
	__u64 dropped = 0;
	if (!vmm_allow(root, &dropped))
		return 0;
	if (dropped)
		vmm_flood(root, dropped);
	struct vmm_event *e = vmm_begin(root, call);
	if (!e)
		return 0;
	e->arg0 = arg0;
	e->arg1 = arg1;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int vmm_openat(struct trace_event_raw_sys_enter *ctx) {
	return vmm_open(VMM_OPENAT, ctx->args[0], (const char *)ctx->args[1], ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int vmm_openat2(struct trace_event_raw_sys_enter *ctx) {
	return vmm_open(VMM_OPENAT2, ctx->args[0], (const char *)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_enter_open")
int vmm_open_legacy(struct trace_event_raw_sys_enter *ctx) {
	return vmm_open(VMM_OPEN, AT_FDCWD_, (const char *)ctx->args[0], ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int vmm_ptrace(struct trace_event_raw_sys_enter *ctx) {
	return vmm_call(VMM_PTRACE, ctx->args[0], ctx->args[1]); /* the request, and the pid it is for */
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int vmm_process_vm_writev(struct trace_event_raw_sys_enter *ctx) {
	return vmm_call(VMM_PROCESS_VM_WRITEV, ctx->args[0], 0); /* the pid whose memory it writes */
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int vmm_process_vm_readv(struct trace_event_raw_sys_enter *ctx) {
	return vmm_call(VMM_PROCESS_VM_READV, ctx->args[0], 0);
}

SEC("tracepoint/syscalls/sys_enter_mount")
int vmm_mount(struct trace_event_raw_sys_enter *ctx) {
	return vmm_call(VMM_MOUNT, ctx->args[3], 0); /* the mount flags */
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int vmm_unshare(struct trace_event_raw_sys_enter *ctx) {
	return vmm_call(VMM_UNSHARE, ctx->args[0], 0); /* which namespaces */
}

SEC("tracepoint/syscalls/sys_enter_setns")
int vmm_setns(struct trace_event_raw_sys_enter *ctx) {
	return vmm_call(VMM_SETNS, ctx->args[0], ctx->args[1]); /* the fd of the namespace, and its type */
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int vmm_init_module(struct trace_event_raw_sys_enter *ctx) {
	return vmm_call(VMM_INIT_MODULE, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int vmm_finit_module(struct trace_event_raw_sys_enter *ctx) {
	return vmm_call(VMM_FINIT_MODULE, ctx->args[0], ctx->args[2]); /* the module's fd, and the flags */
}

SEC("tracepoint/syscalls/sys_enter_kexec_load")
int vmm_kexec_load(struct trace_event_raw_sys_enter *ctx) {
	return vmm_call(VMM_KEXEC_LOAD, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_kexec_file_load")
int vmm_kexec_file_load(struct trace_event_raw_sys_enter *ctx) {
	return vmm_call(VMM_KEXEC_FILE_LOAD, 0, 0);
}
