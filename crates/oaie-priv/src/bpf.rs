//! BPF program loader for the eBPF tracer.
//!
//! Loads a single pre-compiled BPF object file (embedded via `include_bytes!`)
//! containing all four tracepoint programs. Configures the shared ring buffer
//! and cgroup filter map, and attaches each program to its tracepoint.
//!
//! This module is only compiled with the `ebpf` feature flag.

use std::os::unix::io::{AsFd, AsRawFd, RawFd};

use libbpf_rs::{Link, MapCore, MapFlags, Object, ObjectBuilder};

/// Embedded pre-compiled BPF object file (consolidated, all 4 programs).
const TRACER_OBJ: &[u8] = include_bytes!("../../../bpf/prebuilt/oaie_tracer.bpf.o");

/// Handles to loaded BPF programs, maps, and links.
///
/// All file descriptors are owned by this struct. Dropping it closes
/// everything and detaches the tracepoint probes.
pub struct BpfHandles {
    /// Ring buffer map FD — passed to the unprivileged consumer.
    pub ring_buffer_fd: RawFd,
    /// Tracepoint link FDs — kept alive so probes stay attached.
    pub link_fds: Vec<RawFd>,
    /// Owned object — must stay alive to keep FDs valid.
    _object: Object,
    /// Owned links — must stay alive to keep tracepoints attached.
    _links: Vec<Link>,
}

impl Drop for BpfHandles {
    fn drop(&mut self) {
        // Links and objects are dropped automatically by libbpf-rs,
        // which closes their FDs and detaches probes.
    }
}

/// Load all BPF programs, configure maps, and attach to tracepoints.
///
/// `cgroup_id` is written to the `target_cgroup` array map so programs
/// only emit events for processes in the specified cgroup.
///
/// `ring_buf_size` overrides the default 1MB ring buffer size. Must be
/// a power of 2 between 256KB and 4MB (validated by caller).
///
/// Returns `BpfHandles` with the ring buffer FD and link FDs.
pub fn load_and_attach(cgroup_id: u64, ring_buf_size: u32) -> Result<BpfHandles, String> {
    let mut builder = ObjectBuilder::default();

    let mut open_obj = builder.open_memory(TRACER_OBJ).map_err(|e| {
        format!("failed to open BPF object: {e}")
    })?;

    // Override ring buffer size before loading.
    // OpenMapMut::name() returns &OsStr, compare via str conversion.
    if let Some(mut map) = open_obj.maps_mut().find(|m| m.name().to_str() == Some("events")) {
        map.set_max_entries(ring_buf_size).map_err(|e| {
            format!("failed to set ring buffer size to {ring_buf_size}: {e}")
        })?;
    }

    let mut obj = open_obj.load().map_err(|e| {
        format!("failed to load BPF object: {e}")
    })?;

    // Write cgroup_id to the target_cgroup array map.
    {
        let map = obj.maps_mut()
            .find(|m| m.name().to_str() == Some("target_cgroup"))
            .ok_or_else(|| "target_cgroup map not found".to_string())?;
        let key = 0u32.to_ne_bytes();
        let value = cgroup_id.to_ne_bytes();
        map.update(&key, &value, MapFlags::ANY).map_err(|e| {
            format!("failed to set target_cgroup: {e}")
        })?;
    }

    // Get the ring buffer map FD.
    let ring_buffer_fd = obj
        .maps_mut()
        .find(|m| m.name().to_str() == Some("events"))
        .ok_or_else(|| "ring buffer map 'events' not found".to_string())?
        .as_fd()
        .as_raw_fd();

    // Attach all four programs to their tracepoints.
    let prog_names = [
        "oaie_trace_exec",
        "oaie_trace_exit",
        "oaie_trace_open",
        "oaie_trace_connect",
    ];

    let mut links = Vec::new();
    for prog_name in &prog_names {
        let prog = obj.progs_mut()
            .find(|p| p.name().to_str() == Some(*prog_name))
            .ok_or_else(|| format!("BPF program '{prog_name}' not found"))?;

        let link = prog.attach().map_err(|e| {
            format!("failed to attach {prog_name}: {e}")
        })?;

        links.push(link);
    }

    // Collect link FDs for passing to the client.
    let link_fds: Vec<RawFd> = links
        .iter()
        .map(|l: &Link| l.as_fd().as_raw_fd())
        .collect();

    Ok(BpfHandles {
        ring_buffer_fd,
        link_fds,
        _object: obj,
        _links: links,
    })
}
