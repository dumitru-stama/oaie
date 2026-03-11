/* OAIE eBPF tracer — consolidated BPF programs.
 *
 * All four tracepoint programs in a single object file so they share
 * the ring buffer map and target_cgroup filter map.
 *
 * Programs:
 *   oaie_trace_exec    — tracepoint/sched/sched_process_exec
 *   oaie_trace_exit    — tracepoint/sched/sched_process_exit
 *   oaie_trace_open    — tracepoint/syscalls/sys_enter_openat
 *   oaie_trace_connect — tracepoint/syscalls/sys_enter_connect
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "oaie_events.h"

/* ── Shared maps ── */

/* Ring buffer for delivering events to userspace. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1048576); /* 1MB default, overridable at load */
} events SEC(".maps");

/* Array map with a single entry: the cgroup ID to filter on.
 * Value 0 means "accept all" (no filtering). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_cgroup SEC(".maps");

/* ── Shared helpers ── */

/* Check if the current task belongs to the target cgroup.
 * Returns 1 if it matches (or no filter is set), 0 otherwise. */
static __always_inline int cgroup_match(void)
{
    __u32 key = 0;
    __u64 *target = bpf_map_lookup_elem(&target_cgroup, &key);
    if (!target || *target == 0)
        return 1; /* No filter set — accept all. */
    return bpf_get_current_cgroup_id() == *target;
}

/* ── Program 1: Process exec ── */

SEC("tracepoint/sched/sched_process_exec")
int oaie_trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    if (!cgroup_match())
        return 0;

    struct oaie_raw_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    /* Zero entire payload to prevent kernel stack info leak. */
    __builtin_memset(evt->payload, 0, sizeof(evt->payload));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    evt->event_type = OAIE_EVENT_EXEC;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);
    evt->_pad = 0;
    evt->ts_ns = bpf_ktime_get_ns();
    evt->cgroup_id = bpf_get_current_cgroup_id();

    /* Read filename from the tracepoint context.
     * sched_process_exec provides the filename via ctx->__data_loc_filename. */
    struct oaie_exec_payload *p = (struct oaie_exec_payload *)evt->payload;
    unsigned short __offset = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(p->filename, sizeof(p->filename),
                       (void *)ctx + __offset);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ── Program 2: Process exit ── */

SEC("tracepoint/sched/sched_process_exit")
int oaie_trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    if (!cgroup_match())
        return 0;

    struct oaie_raw_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    /* Zero entire payload to prevent kernel stack info leak. */
    __builtin_memset(evt->payload, 0, sizeof(evt->payload));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    evt->event_type = OAIE_EVENT_EXIT;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);
    evt->_pad = 0;
    evt->ts_ns = bpf_ktime_get_ns();
    evt->cgroup_id = bpf_get_current_cgroup_id();

    /* Extract exit_code from task_struct.
     * The kernel packs the exit code as: (exit_code << 8) | signal.
     * We split them for the userspace consumer. */
    __u32 raw_exit = BPF_CORE_READ(task, exit_code);
    struct oaie_exit_payload *p = (struct oaie_exit_payload *)evt->payload;
    p->exit_code = (raw_exit >> 8) & 0xFF;
    p->signal = raw_exit & 0x7F;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ── Program 3: File open ── */

/* Tracepoint args for sys_enter_openat. */
struct sys_enter_openat_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           __syscall_nr;
    long           dfd;
    const char    *filename;
    long           flags;
    long           mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int oaie_trace_open(struct sys_enter_openat_args *ctx)
{
    if (!cgroup_match())
        return 0;

    struct oaie_raw_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    /* Zero entire payload to prevent kernel stack info leak. */
    __builtin_memset(evt->payload, 0, sizeof(evt->payload));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    evt->event_type = OAIE_EVENT_OPEN;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);
    evt->_pad = 0;
    evt->ts_ns = bpf_ktime_get_ns();
    evt->cgroup_id = bpf_get_current_cgroup_id();

    struct oaie_open_payload *p = (struct oaie_open_payload *)evt->payload;
    p->flags = (__u32)ctx->flags;

    /* Read filename from userspace. */
    bpf_probe_read_user_str(p->filename, sizeof(p->filename), ctx->filename);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ── Program 4: Network connect ── */

/* Tracepoint args for sys_enter_connect. */
struct sys_enter_connect_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           __syscall_nr;
    long           fd;
    const void    *uservaddr;
    long           addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int oaie_trace_connect(struct sys_enter_connect_args *ctx)
{
    if (!cgroup_match())
        return 0;

    struct oaie_raw_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    /* Zero entire payload to prevent kernel stack info leak. */
    __builtin_memset(evt->payload, 0, sizeof(evt->payload));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    evt->event_type = OAIE_EVENT_CONNECT;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->ppid = BPF_CORE_READ(task, real_parent, tgid);
    evt->_pad = 0;
    evt->ts_ns = bpf_ktime_get_ns();
    evt->cgroup_id = bpf_get_current_cgroup_id();

    struct oaie_connect_payload *p = (struct oaie_connect_payload *)evt->payload;

    long addrlen = ctx->addrlen;
    if (addrlen <= 0)
        goto submit;

    /* Read sa_family (2 bytes) from userspace. */
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), ctx->uservaddr);
    p->family = family;

    if (family == 2 /* AF_INET */ && addrlen >= 8) {
        /* struct sockaddr_in: family(2) + port(2) + addr(4) = 8 bytes.
         * All read sizes are constants — verifier-safe. */
        __u8 sa_inet[8];
        bpf_probe_read_user(sa_inet, sizeof(sa_inet), ctx->uservaddr);
        p->port = *(__u16 *)(sa_inet + 2);
        __builtin_memcpy(p->addr, sa_inet + 4, 4);
    } else if (family == 10 /* AF_INET6 */ && addrlen >= 28) {
        /* struct sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16) = 28 bytes. */
        __u8 sa_inet6[28];
        bpf_probe_read_user(sa_inet6, sizeof(sa_inet6), ctx->uservaddr);
        p->port = *(__u16 *)(sa_inet6 + 2);
        __builtin_memcpy(p->addr, sa_inet6 + 8, 16);
    } else if (family == 1 /* AF_UNIX */ && addrlen > 2) {
        /* struct sockaddr_un: family(2) + path (up to 108).
         * Read with constant max size — verifier-safe. Payload pre-zeroed. */
        bpf_probe_read_user(p->addr, 108, (const char *)ctx->uservaddr + 2);
    }

submit:
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
