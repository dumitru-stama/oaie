//! Event summarizer — distills a trace into human-readable summaries.
//!
//! Provides a streaming `StreamingSummarizer` that processes events one at a time,
//! plus a backward-compatible `summarize_events(&[OaieEvent])` wrapper.
//!
//! Features:
//! - File categorization (Input, Output, SystemLib, Config, etc.)
//! - Noise filtering (libc internals, /proc/self, /dev, locale data)
//! - Directory grouping for display (collapse dirs with many files)
//! - Process tree with exit codes and depths
//! - Suspicious activity classification (23 categories)
//! - Network connect tracking with succeeded/denied status

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::event::{EventDetail, EventType, OaieEvent};

// ── Public types ──

/// Summary of observed events, produced by [`StreamingSummarizer::finish()`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummary {
    /// Files that were successfully read.
    pub files_read: Vec<FileAccessEntry>,
    /// Files that were successfully written.
    pub files_written: Vec<FileAccessEntry>,
    /// Files where access was denied (non-zero result).
    pub file_access_denied: Vec<FileAccessEntry>,
    /// Successful network connects.
    pub net_connects: Vec<NetConnectEntry>,
    /// Denied network connects (non-zero result).
    pub net_denied: Vec<NetConnectEntry>,
    /// DNS queries observed (sendto to UDP port 53 with parsed domain names).
    #[serde(default)]
    pub dns_queries: Vec<DnsQueryEntry>,
    /// Process tree reconstructed from exec/exit events.
    pub process_tree: Vec<ProcessNode>,
    /// Suspicious activity detected from SecurityRelevant events.
    pub suspicious_activity: Vec<SuspiciousEntry>,
    /// Total number of events processed.
    pub total_events: u64,
    /// Total file-related events (FileOpen + FileStat).
    pub total_file_events: u64,
    /// Total network-related events.
    pub total_net_events: u64,
    /// Total exec events.
    pub total_exec_events: u64,
    /// Number of unique files read.
    pub unique_files_read: u64,
    /// Number of unique files written.
    pub unique_files_written: u64,
    /// Trace duration in nanoseconds (last event ts - first event ts).
    pub trace_duration_ns: u64,
}

/// A file access entry with path, count, and category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccessEntry {
    /// Filesystem path.
    pub path: String,
    /// Number of times this path was accessed.
    pub count: u32,
    /// Category assigned by path prefix.
    pub category: FileCategory,
}

/// File category determined by path prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileCategory {
    /// Files under /in/ or input directories.
    Input,
    /// Files under /out/ or output directories.
    Output,
    /// Shared libraries under /usr/lib/ or /lib/.
    SystemLib,
    /// System binaries under /usr/bin/, /bin/, /usr/sbin/, /sbin/.
    SystemBin,
    /// Configuration files under /etc/.
    Config,
    /// /proc filesystem entries.
    Proc,
    /// Anything that doesn't match other categories.
    Other,
}

impl std::fmt::Display for FileCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileCategory::Input => write!(f, "Input"),
            FileCategory::Output => write!(f, "Output"),
            FileCategory::SystemLib => write!(f, "Lib"),
            FileCategory::SystemBin => write!(f, "Bin"),
            FileCategory::Config => write!(f, "Config"),
            FileCategory::Proc => write!(f, "Proc"),
            FileCategory::Other => write!(f, "Other"),
        }
    }
}

/// A DNS query entry parsed from sendto to port 53.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryEntry {
    /// Domain name being queried (e.g. "www.google.com").
    pub name: String,
    /// DNS server address (e.g. "8.8.8.8:53").
    pub server: String,
    /// Number of times this domain was queried.
    pub count: u32,
}

/// A network connect entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConnectEntry {
    /// Address string (e.g. "93.184.216.34:80" or "/var/run/sock").
    pub address: String,
    /// Address family (AF_INET, AF_INET6, AF_UNIX, AF_NETLINK).
    pub family: String,
    /// Number of connect attempts to this address.
    pub count: u32,
    /// Whether the connection succeeded.
    pub succeeded: bool,
}

/// A process in the observed process tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Command name (first argv element or filename).
    pub command: String,
    /// Full argument vector.
    pub args: Vec<String>,
    /// Depth in the process tree (0 = root).
    pub depth: usize,
    /// Exit code, filled from ProcessExit events.
    pub exit_code: Option<i32>,
}

/// Category of suspicious activity, mapped from SecurityRelevant syscall names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SuspiciousCategory {
    /// io_uring detected — trace has blind spots.
    IoUringSetup,
    /// memfd_create — fileless execution preparation.
    MemfdCreate,
    /// execveat — file descriptor execution.
    Execveat,
    /// Fileless exec detected (memfd_create + execveat AT_EMPTY_PATH).
    FilelessExec,
    /// mount/umount attempted.
    MountAttempt,
    /// ptrace attempted (anti-debug or tracer interference).
    PtraceAttempt,
    /// Nested user namespace attempted.
    NestedUserns,
    /// Kernel module loading attempted.
    KernelModule,
    /// userfaultfd in kernel mode (exploit technique).
    UserfaultfdKernel,
    /// userfaultfd in user mode.
    UserfaultfdUser,
    /// Cross-process memory access (process_vm_readv/writev).
    CrossProcessMemory,
    /// vmsplice with SPLICE_F_GIFT (Dirty Pipe class).
    VmspliceGift,
    /// pidfd_send_signal — signal via process descriptor.
    PidfdSignal,
    /// kcmp — kernel compare between processes.
    Kcmp,
    /// prctl dangerous subcommands (SET_MM, SET_CHILD_SUBREAPER, etc.).
    PrctlDangerous,
    /// seccomp installation attempt.
    SeccompInstall,
    /// Dangerous socket type (AF_PACKET, SOCK_RAW, etc.).
    DangerousSocket,
    /// Speculation control manipulation.
    SpeculationControl,
    /// clone3 with CLONE_INTO_CGROUP.
    CloneIntoCgroup,
    /// AF_NETLINK access (detected from NetConnect events).
    NetlinkAccess,
    /// swapon/swapoff attempted.
    SwapManipulation,
    /// pivot_root / chroot attempted.
    RootChange,
    /// Other security-relevant syscall.
    Other,
}

impl std::fmt::Display for SuspiciousCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoUringSetup => write!(f, "io_uring setup (trace blind spot)"),
            Self::MemfdCreate => write!(f, "memfd_create (fileless exec prep)"),
            Self::Execveat => write!(f, "execveat (fd-based execution)"),
            Self::FilelessExec => write!(f, "fileless execution detected"),
            Self::MountAttempt => write!(f, "mount/umount attempt"),
            Self::PtraceAttempt => write!(f, "ptrace attempt"),
            Self::NestedUserns => write!(f, "nested user namespace attempt"),
            Self::KernelModule => write!(f, "kernel module loading"),
            Self::UserfaultfdKernel => write!(f, "userfaultfd (kernel mode)"),
            Self::UserfaultfdUser => write!(f, "userfaultfd (user mode)"),
            Self::CrossProcessMemory => write!(f, "cross-process memory access"),
            Self::VmspliceGift => write!(f, "vmsplice SPLICE_F_GIFT (Dirty Pipe class)"),
            Self::PidfdSignal => write!(f, "pidfd_send_signal"),
            Self::Kcmp => write!(f, "kcmp (kernel compare)"),
            Self::PrctlDangerous => write!(f, "prctl dangerous subcommand"),
            Self::SeccompInstall => write!(f, "seccomp installation"),
            Self::DangerousSocket => write!(f, "dangerous socket type"),
            Self::SpeculationControl => write!(f, "speculation control"),
            Self::CloneIntoCgroup => write!(f, "clone3 into cgroup"),
            Self::NetlinkAccess => write!(f, "AF_NETLINK access"),
            Self::SwapManipulation => write!(f, "swap manipulation"),
            Self::RootChange => write!(f, "pivot_root/chroot"),
            Self::Other => write!(f, "security-relevant syscall"),
        }
    }
}

/// A suspicious activity entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousEntry {
    /// Category of the suspicious activity.
    pub category: SuspiciousCategory,
    /// PID that triggered this activity.
    pub pid: u32,
    /// Number of times this was observed.
    pub count: u32,
    /// Human-readable detail string.
    pub detail: String,
}

/// Display entry for grouped file listing.
#[derive(Debug, Clone)]
pub enum DisplayEntry {
    /// Individual file entry.
    File(FileAccessEntry),
    /// Collapsed directory entry.
    Directory {
        /// Directory path.
        path: String,
        /// Number of files in this directory.
        file_count: usize,
        /// Total accesses across all files.
        total_accesses: u32,
    },
}

/// Maximum unique entries in the suspicious activity and DNS query maps.
/// Prevents unbounded memory growth from processes that produce unique details.
const MAX_MAP_ENTRIES: usize = 10_000;

// ── StreamingSummarizer ──

/// Stateful event processor that builds a [`TraceSummary`] incrementally.
///
/// Usage:
/// ```ignore
/// let mut s = StreamingSummarizer::new();
/// for event in events { s.ingest(&event); }
/// let summary = s.finish();
/// ```
pub struct StreamingSummarizer {
    /// Files read: path → (count, flags).
    files_read: HashMap<String, u32>,
    /// Files written: path → count.
    files_written: HashMap<String, u32>,
    /// Files denied: path → count.
    files_denied: HashMap<String, u32>,
    /// Network connects: (address, family) → (count, succeeded).
    net_connects: HashMap<(String, String), (u32, bool)>,
    /// Network denied: (address, family) → count.
    net_denied: HashMap<(String, String), u32>,
    /// DNS queries: domain name → (server, count).
    dns_queries: HashMap<String, (String, u32)>,
    /// Processes: pid → (ppid, command, args).
    processes: HashMap<u32, (u32, String, Vec<String>)>,
    /// Process exit codes: pid → exit_code.
    exit_codes: HashMap<u32, i32>,
    /// Suspicious activity: (category, pid, detail) → count.
    suspicious: HashMap<(SuspiciousCategory, u32, String), u32>,
    /// First event timestamp seen.
    first_ts: u64,
    /// Last event timestamp seen.
    last_ts: u64,
    /// Counters.
    total_events: u64,
    total_file_events: u64,
    total_net_events: u64,
    total_exec_events: u64,
}

impl StreamingSummarizer {
    /// Create a new empty summarizer.
    pub fn new() -> Self {
        Self {
            files_read: HashMap::new(),
            files_written: HashMap::new(),
            files_denied: HashMap::new(),
            net_connects: HashMap::new(),
            net_denied: HashMap::new(),
            dns_queries: HashMap::new(),
            processes: HashMap::new(),
            exit_codes: HashMap::new(),
            suspicious: HashMap::new(),
            first_ts: 0,
            last_ts: 0,
            total_events: 0,
            total_file_events: 0,
            total_net_events: 0,
            total_exec_events: 0,
        }
    }

    /// Process a single event, updating internal state.
    pub fn ingest(&mut self, event: &OaieEvent) {
        self.total_events += 1;

        if self.total_events == 1 {
            self.first_ts = event.ts_ns;
        }
        self.last_ts = event.ts_ns;

        match (&event.event_type, &event.detail) {
            (EventType::FileOpen, EventDetail::FileAccess { path, flags, result }) => {
                self.total_file_events += 1;
                // Never noise-filter writes: the noise list targets dynamic-
                // loader READ noise, and the tracee chooses the pathname
                // string freely (dirfd is not resolved).
                if !is_write_flag(*flags) && is_noise_path(path) {
                    return;
                }
                // result > 0, not != 0: the eBPF backend emits -1 for
                // "not captured" (sys_enter hook, return value unknown).
                // Treating -1 as a failure would mark every file under
                // --trace=ebpf as denied; presume-success is correct here.
                // See event.rs FileAccess.result doc.
                let target = if *result > 0 {
                    &mut self.files_denied
                } else if is_write_flag(*flags) {
                    &mut self.files_written
                } else {
                    &mut self.files_read
                };
                if let Some(count) = target.get_mut(path) {
                    *count += 1;
                } else if target.len() < MAX_MAP_ENTRIES {
                    target.insert(path.clone(), 1);
                }
            }
            (EventType::FileStat, EventDetail::FileStat { .. }) => {
                self.total_file_events += 1;
            }
            (EventType::NetConnect, EventDetail::NetConnect { address, family, result }) => {
                self.total_net_events += 1;

                // AF_NETLINK detected from NetConnect events.
                if family == "AF_NETLINK" {
                    let key = (SuspiciousCategory::NetlinkAccess, event.pid, format!("AF_NETLINK connect to {address}"));
                    if let Some(count) = self.suspicious.get_mut(&key) {
                        *count += 1;
                    } else if self.suspicious.len() < MAX_MAP_ENTRIES {
                        self.suspicious.insert(key, 1);
                    }
                }

                let key = (address.clone(), family.clone());
                // <= 0 buckets eBPF's -1 (not-captured) with success.
                // Same rationale as the FileAccess result check above.
                if *result <= 0 {
                    if let Some(entry) = self.net_connects.get_mut(&key) {
                        entry.0 += 1;
                    } else if self.net_connects.len() < MAX_MAP_ENTRIES {
                        self.net_connects.insert(key, (1, true));
                    }
                } else if let Some(count) = self.net_denied.get_mut(&key) {
                    *count += 1;
                } else if self.net_denied.len() < MAX_MAP_ENTRIES {
                    self.net_denied.insert(key, 1);
                }
            }
            (EventType::DnsQuery, EventDetail::DnsQuery { name, server, result }) => {
                self.total_net_events += 1;
                if *result == 0 {
                    if let Some(entry) = self.dns_queries.get_mut(name) {
                        entry.1 += 1;
                    } else if self.dns_queries.len() < MAX_MAP_ENTRIES {
                        self.dns_queries.insert(name.clone(), (server.clone(), 1));
                    }
                }
            }
            (EventType::ProcessExec, EventDetail::Exec { filename, argv }) => {
                self.total_exec_events += 1;
                let cmd = argv.first().cloned().unwrap_or_else(|| filename.clone());
                let ppid = event.ppid.unwrap_or(0);
                self.processes.insert(event.pid, (ppid, cmd, argv.clone()));
            }
            (EventType::ProcessExit, EventDetail::Exit { exit_code, .. }) => {
                self.exit_codes.insert(event.pid, *exit_code);
            }
            (EventType::SecurityRelevant, EventDetail::SecurityRelevant { syscall, .. }) => {
                let category = classify_suspicious(syscall);
                let detail = format_suspicious_detail(syscall, event.pid);
                let key = (category, event.pid, detail);
                if let Some(count) = self.suspicious.get_mut(&key) {
                    *count += 1;
                } else if self.suspicious.len() < MAX_MAP_ENTRIES {
                    self.suspicious.insert(key, 1);
                }
            }
            _ => {}
        }
    }

    /// Consume the summarizer and produce the final [`TraceSummary`].
    pub fn finish(self) -> TraceSummary {
        let files_read = sort_and_categorize(self.files_read);
        let files_written = sort_and_categorize(self.files_written);
        let file_access_denied = sort_and_categorize(self.files_denied);

        let unique_files_read = files_read.len() as u64;
        let unique_files_written = files_written.len() as u64;

        let mut net_connects: Vec<NetConnectEntry> = self.net_connects
            .into_iter()
            .map(|((address, family), (count, succeeded))| NetConnectEntry {
                address,
                family,
                count,
                succeeded,
            })
            .collect();
        net_connects.sort_by_key(|b| std::cmp::Reverse(b.count));

        let mut net_denied: Vec<NetConnectEntry> = self.net_denied
            .into_iter()
            .map(|((address, family), count)| NetConnectEntry {
                address,
                family,
                count,
                succeeded: false,
            })
            .collect();
        net_denied.sort_by_key(|b| std::cmp::Reverse(b.count));

        let mut dns_queries: Vec<DnsQueryEntry> = self.dns_queries
            .into_iter()
            .map(|(name, (server, count))| DnsQueryEntry { name, server, count })
            .collect();
        dns_queries.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));

        let process_tree = build_process_tree(&self.processes, &self.exit_codes);

        let mut suspicious_activity: Vec<SuspiciousEntry> = self.suspicious
            .into_iter()
            .map(|((category, pid, detail), count)| SuspiciousEntry {
                category,
                pid,
                count,
                detail,
            })
            .collect();
        // Sort by count descending, then category display string.
        suspicious_activity.sort_by(|a, b| {
            b.count.cmp(&a.count).then(a.category.to_string().cmp(&b.category.to_string()))
        });

        let trace_duration_ns = self.last_ts.saturating_sub(self.first_ts);

        TraceSummary {
            files_read,
            files_written,
            file_access_denied,
            net_connects,
            net_denied,
            dns_queries,
            process_tree,
            suspicious_activity,
            total_events: self.total_events,
            total_file_events: self.total_file_events,
            total_net_events: self.total_net_events,
            total_exec_events: self.total_exec_events,
            unique_files_read,
            unique_files_written,
            trace_duration_ns,
        }
    }
}

impl Default for StreamingSummarizer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Backward-compatible wrapper ──

/// Build a summary from a slice of events.
///
/// Convenience wrapper around [`StreamingSummarizer`] for small traces
/// that are already loaded into memory.
pub fn summarize_events(events: &[OaieEvent]) -> TraceSummary {
    let mut s = StreamingSummarizer::new();
    for event in events {
        s.ingest(event);
    }
    s.finish()
}

// ── File categorization ──

/// Assign a [`FileCategory`] based on path prefix.
fn categorize_path(path: &str) -> FileCategory {
    if path.starts_with("/in/") || path.starts_with("/input/") {
        FileCategory::Input
    } else if path.starts_with("/out/") || path.starts_with("/output/") {
        FileCategory::Output
    } else if path.starts_with("/usr/lib/")
        || path.starts_with("/lib/")
        || path.starts_with("/lib64/")
        || is_shared_library(path)
    {
        FileCategory::SystemLib
    } else if path.starts_with("/usr/bin/")
        || path.starts_with("/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/sbin/")
    {
        FileCategory::SystemBin
    } else if path.starts_with("/etc/") {
        FileCategory::Config
    } else if path.starts_with("/proc/") {
        FileCategory::Proc
    } else {
        FileCategory::Other
    }
}

/// Sort file access entries by count descending and assign categories.
fn sort_and_categorize(map: HashMap<String, u32>) -> Vec<FileAccessEntry> {
    let mut entries: Vec<FileAccessEntry> = map
        .into_iter()
        .map(|(path, count)| {
            let category = categorize_path(&path);
            FileAccessEntry { path, count, category }
        })
        .collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count).then(a.path.cmp(&b.path)));
    entries
}

// ── Display grouping ──

/// Group file entries by directory when a directory has more than `max_individual` files.
///
/// Entries in directories with few files are shown individually.
/// Directories with many files are collapsed into a single directory entry.
pub fn group_by_directory(entries: &[FileAccessEntry], max_individual: usize) -> Vec<DisplayEntry> {
    let mut dir_counts: HashMap<String, (usize, u32)> = HashMap::new();

    for entry in entries {
        let dir = parent_dir(&entry.path);
        let e = dir_counts.entry(dir).or_insert((0, 0));
        e.0 += 1;
        e.1 += entry.count;
    }

    let mut result = Vec::new();

    for entry in entries {
        let dir = parent_dir(&entry.path);
        if let Some(&(file_count, total_accesses)) = dir_counts.get(&dir) {
            if file_count > max_individual {
                // Only add the directory entry once.
                if !result.iter().any(|d| matches!(d, DisplayEntry::Directory { path, .. } if *path == dir)) {
                    result.push(DisplayEntry::Directory {
                        path: dir,
                        file_count,
                        total_accesses,
                    });
                }
            } else {
                result.push(DisplayEntry::File(entry.clone()));
            }
        }
    }

    result
}

/// Extract parent directory from a path.
fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(pos) if pos > 0 => path[..pos].to_string(),
        _ => "/".to_string(),
    }
}

// ── Noise filtering ──

/// Filter out noise paths that every process touches.
///
/// These are libc/linker internals, /proc/self metadata, /dev nodes,
/// locale data, and NSS libraries that would clutter the summary
/// without providing useful information.
fn is_noise_path(path: &str) -> bool {
    // The path string is whatever the tracee passed to openat(); it is NOT
    // canonicalized. A tracee can hide a real read by prefixing it with a
    // noise prefix and dot-dotting back out: "/dev/../etc/shadow" matches
    // the "/dev/" prefix below but resolves to /etc/shadow. Never noise-
    // filter a path with parent-dir traversal — record it and let the
    // operator decide. (Writes are already excluded from noise filtering
    // at the caller; this closes the read direction.)
    if path.contains("/../") || path.ends_with("/..") {
        return false;
    }
    if path.starts_with("/proc/self")
        || path.starts_with("/proc/thread-self")
        || path.starts_with("/proc/filesystems")
        || path.starts_with("/proc/stat")
        || path.starts_with("/dev/")
        || path.starts_with("/etc/ld.so")
        || path == "/etc/nsswitch.conf"
        || path == "/etc/passwd"
        || path == "/etc/group"
        || path == "/etc/localtime"
        || path.contains("/locale/")
        || path.contains("/gconv/")
        || path.contains("/glibc-hwcaps/")
        || path == "/var/run/nscd/socket"
    {
        return true;
    }
    // Check library names against the filename component only, to avoid
    // false positives like "/in/analyze_libc.so_notes.txt".
    let filename = path.rsplit('/').next().unwrap_or(path);
    filename.contains("libc.so")
        || filename.starts_with("libpthread")
        || filename.starts_with("libdl.so")
        || filename.starts_with("libm.so")
        || filename.starts_with("librt.so")
        || filename.starts_with("ld-linux")
        || filename.starts_with("libnss_")
        || filename.starts_with("libresolv")
}

/// Check if a path refers to a shared library (.so or .so.N.N.N).
///
/// Uses the filename component to avoid false positives like
/// `/in/resolve.socket` matching `.contains(".so")`.
fn is_shared_library(path: &str) -> bool {
    let filename = match path.rsplit('/').next() {
        Some(f) => f,
        None => path,
    };
    // Match "libfoo.so", "libfoo.so.6", "libfoo.so.6.1.2"
    filename.contains(".so.") || filename.ends_with(".so")
}

/// Detect write flags in open(2) flags value.
/// O_WRONLY = 1, O_RDWR = 2 (on Linux, lowest 2 bits encode access mode).
fn is_write_flag(flags: u32) -> bool {
    let access_mode = flags & 0x03;
    access_mode == 1 || access_mode == 2
}

// ── Suspicious classification ──

/// Map a syscall name string (from SecurityRelevant events) to a category.
fn classify_suspicious(syscall: &str) -> SuspiciousCategory {
    match syscall {
        "io_uring_setup" | "io_uring_enter" | "io_uring_register" => SuspiciousCategory::IoUringSetup,
        "memfd_create" => SuspiciousCategory::MemfdCreate,
        "execveat" => SuspiciousCategory::Execveat,
        "fileless_exec_detected" => SuspiciousCategory::FilelessExec,
        "mount" | "umount2" => SuspiciousCategory::MountAttempt,
        "ptrace" | "ptrace_traceme" => SuspiciousCategory::PtraceAttempt,
        "nested_userns_attempt" | "nested_userns_via_clone" | "nested_userns_via_clone3" => SuspiciousCategory::NestedUserns,
        "init_module" | "finit_module" | "delete_module" => SuspiciousCategory::KernelModule,
        "userfaultfd_kernel_mode" => SuspiciousCategory::UserfaultfdKernel,
        "userfaultfd_user_mode" | "userfaultfd" => SuspiciousCategory::UserfaultfdUser,
        s if s.starts_with("process_vm_readv") || s.starts_with("process_vm_writev") => SuspiciousCategory::CrossProcessMemory,
        "vmsplice_splice_f_gift" | "vmsplice" => SuspiciousCategory::VmspliceGift,
        s if s.starts_with("pidfd_send_signal") => SuspiciousCategory::PidfdSignal,
        s if s.starts_with("kcmp") => SuspiciousCategory::Kcmp,
        "seccomp" | "prctl_set_seccomp" => SuspiciousCategory::SeccompInstall,
        s if s.starts_with("prctl_enable_speculation") => SuspiciousCategory::SpeculationControl,
        s if s.starts_with("prctl_") => SuspiciousCategory::PrctlDangerous,
        s if s.starts_with("socket_af_") || s == "socket_sock_raw" => SuspiciousCategory::DangerousSocket,
        "clone3_into_cgroup" => SuspiciousCategory::CloneIntoCgroup,
        "swapon" | "swapoff" => SuspiciousCategory::SwapManipulation,
        "pivot_root" | "chroot" => SuspiciousCategory::RootChange,
        "unshare" | "clone" | "clone3" => SuspiciousCategory::Other,
        _ => SuspiciousCategory::Other,
    }
}

/// Generate a human-readable detail string for a suspicious syscall.
fn format_suspicious_detail(syscall: &str, pid: u32) -> String {
    match syscall {
        "io_uring_setup" => format!("PID {pid} setup io_uring (trace has blind spots for async ops)"),
        "fileless_exec_detected" => format!("PID {pid} executed binary from memfd (fileless execution)"),
        "ptrace_traceme" => format!("PID {pid} attempted PTRACE_TRACEME (anti-debugging)"),
        "userfaultfd_kernel_mode" => format!("PID {pid} userfaultfd without UFFD_USER_MODE_ONLY (kernel exploit technique)"),
        s if s.starts_with("process_vm_readv") || s.starts_with("process_vm_writev") => {
            format!("PID {pid} cross-process memory access via {syscall}")
        }
        "vmsplice_splice_f_gift" => format!("PID {pid} vmsplice with SPLICE_F_GIFT (Dirty Pipe class vulnerability)"),
        _ => format!("PID {pid} attempted {syscall}"),
    }
}

// ── Process tree ──

/// Build a process tree from pid → (ppid, command, args) map, with exit codes.
///
/// Assigns depth values based on parent-child relationships.
/// Processes whose parent isn't in the map get depth 0 (root).
fn build_process_tree(
    processes: &HashMap<u32, (u32, String, Vec<String>)>,
    exit_codes: &HashMap<u32, i32>,
) -> Vec<ProcessNode> {
    if processes.is_empty() {
        return vec![];
    }

    let mut depths: HashMap<u32, usize> = HashMap::new();

    fn compute_depth(
        pid: u32,
        processes: &HashMap<u32, (u32, String, Vec<String>)>,
        depths: &mut HashMap<u32, usize>,
        visiting: &mut HashSet<u32>,
    ) -> usize {
        if let Some(&d) = depths.get(&pid) {
            return d;
        }
        // Cycle detection: if we're already visiting this pid, break the cycle.
        if !visiting.insert(pid) {
            depths.insert(pid, 0);
            return 0;
        }
        let depth = if let Some(&(ppid, _, _)) = processes.get(&pid) {
            if ppid == 0 || ppid == pid || !processes.contains_key(&ppid) {
                0
            } else {
                compute_depth(ppid, processes, depths, visiting) + 1
            }
        } else {
            0
        };
        visiting.remove(&pid);
        depths.insert(pid, depth);
        depth
    }

    let pids: Vec<u32> = processes.keys().copied().collect();
    let mut visiting = HashSet::new();
    for &pid in &pids {
        compute_depth(pid, processes, &mut depths, &mut visiting);
    }

    let mut tree: Vec<ProcessNode> = processes
        .iter()
        .map(|(&pid, (ppid, cmd, args))| ProcessNode {
            pid,
            ppid: *ppid,
            command: cmd.clone(),
            args: args.clone(),
            depth: depths.get(&pid).copied().unwrap_or(0),
            exit_code: exit_codes.get(&pid).copied(),
        })
        .collect();
    tree.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.pid.cmp(&b.pid)));

    tree
}
