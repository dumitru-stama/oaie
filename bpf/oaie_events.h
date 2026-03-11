/* OAIE BPF event definitions — shared between BPF programs and Rust userspace.
 *
 * This header MUST be kept in sync with crates/oaie-bpf-common/src/lib.rs.
 * Any change here requires a corresponding change in the Rust types.
 */
#ifndef __OAIE_EVENTS_H
#define __OAIE_EVENTS_H

/* Event type discriminant. */
enum oaie_event_type {
    OAIE_EVENT_EXEC    = 1,
    OAIE_EVENT_EXIT    = 2,
    OAIE_EVENT_OPEN    = 3,
    OAIE_EVENT_CONNECT = 4,
};

/* Raw event structure written to the ring buffer.
 * Total size: 288 bytes (4+4+4+4+8+8+256).
 */
struct oaie_raw_event {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 _pad;
    __u64 ts_ns;
    __u64 cgroup_id;
    __u8  payload[256];
};

/* Payload for OAIE_EVENT_EXEC. */
struct oaie_exec_payload {
    char filename[256];
};

/* Payload for OAIE_EVENT_EXIT. */
struct oaie_exit_payload {
    __s32 exit_code;
    __s32 signal;
};

/* Payload for OAIE_EVENT_OPEN. */
struct oaie_open_payload {
    __u32 flags;
    __u32 _pad;
    char  filename[248];
};

/* Payload for OAIE_EVENT_CONNECT. */
struct oaie_connect_payload {
    __u16 family;
    __u16 port;
    __u8  _pad[4];
    __u8  addr[240];
};

#endif /* __OAIE_EVENTS_H */
