//! Filesystem isolation via mount namespaces.
//!
//! Sets up a minimal root filesystem using `pivot_root`:
//! - `/in` (read-only): the tool's input data
//! - `/out` (read-write): where the tool writes results
//! - System libraries (read-only): /usr, /lib, /lib64, /bin, /sbin
//! - Minimal /dev: null, zero, urandom
//! - Masked /proc: kallsyms, kcore, keys, sysrq-trigger, etc. → /dev/null
//! - Tmpfs /tmp with noexec
//!
//! Called from the child process after `clone(CLONE_NEWNS)` and UID map setup.

use std::fs;
use std::path::Path;

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::{chdir, pivot_root};
use oaie_core::error::{OaieError, Result};
use oaie_core::policy::NetworkMode;

use crate::sandbox::SandboxConfig;

// ─── mount_setattr(2) — recursive bind-mount flag changes ───────────────────
//
// The classic `MS_BIND|MS_REMOUNT|MS_REC` pattern doesn't recursively flip
// flags: Linux IGNORES MS_REC during remount — fs/namespace.c's
// do_remount() touches one mount, period.
//
// Concretely: bind_mount_ro_nopriv("/usr") with MS_BIND|MS_REC correctly
// bind-mounts /usr AND every submount under it (e.g. /usr/local on a
// separate fs). Then MS_REMOUNT|MS_REC|MS_RDONLY makes ONLY the top-level
// /usr read-only. /usr/local enters the sandbox with the host superblock's
// flags — writable, possibly with exec/suid/dev.
//
// LATENT on hosts with no submounts under SYSTEM_RO_DIRS. Loud on a host
// with separate /usr/local: the workload writes to /usr/local inside the
// sandbox, which is the same inode as host /usr/local. With exec inherited
// (bind_mount_ro_nopriv deliberately skips NOEXEC for system dirs), that's
// write+exec into a host-trusted path.
//
// mount_setattr(2) with AT_RECURSIVE is the kernel's answer (≥5.12). nix
// doesn't expose it. The struct and constants below are the uapi shape from
// linux/mount.h; the syscall number is in libc.
//
// Called from inside the child after CLONE_NEWNS, BEFORE seccomp install —
// mount_setattr is in seccomp's ERRNO tier so the workload gets EPERM,
// but setup_mounts() runs unfiltered.

#[repr(C)]
#[derive(Default)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

// linux/mount.h. Not in libc as named constants (libc has the syscall
// number but not the flag values — they're recent enough that bindings
// lag). Values verified against the 6.8 uapi header.
const AT_RECURSIVE: u32 = 0x8000;
const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;

/// Recursively set mount attributes on `target` and every submount.
///
/// `attr_set` is a mask of MOUNT_ATTR_* bits to turn on. There's no
/// `attr_clr` parameter because every caller here is HARDENING (RO,
/// nodev, nosuid, noexec) — clearing flags would be a different threat
/// model. If a future caller needs to clear, add the parameter then.
///
/// On kernels <5.12 mount_setattr returns ENOSYS. The fallback (walk
/// /proc/self/mountinfo, remount each child individually) is NOT
/// implemented — this codebase already requires Landlock (5.13) and
/// the seccomp filter shape assumes ≥5.10, so a kernel old enough to
/// lack mount_setattr fails earlier. The error path here is "kernel too
/// old, fail closed" not "kernel too old, fall through to non-recursive
/// remount and silently leave submounts writable". Failing is correct:
/// the alternative is the latent-on-this-host bug above being silent on
/// a different host where it ISN'T latent.
/// Mask a procfs magic symlink by mounting /dev/null on the symlink itself.
///
/// Classic mount(2) follows the symlink during target resolution and would
/// land on whatever it points at (e.g., mounting at /proc/1/exe would mount
/// at the supervisor binary's *host path*, not at the symlink). The new
/// mount API splits this into two steps: open_tree() creates a detached
/// clone of /dev/null, then move_mount() places it. move_mount's default
/// behavior (no MOVE_MOUNT_T_SYMLINKS flag) is to NOT follow the
/// destination symlink — the mount lands on the symlink's dentry, masking
/// the magic-symlink resolution.
///
/// Used for /proc/1/{exe,root,cwd}. PID namespacing renumbers PIDs; it
/// does not restrict reading PID 1's procfs entries — a workload at PID
/// N can `cat /proc/1/exe` and read the supervisor binary's full ELF
/// contents. Even when the binary itself isn't secret, /proc/1/exe is
/// an inode-level reopen primitive that landlock can't gate (same shape
/// as the /proc/1/fd/N case the fd mask closes). /proc/1/root is worse:
/// it resolves to the supervisor's root view (post-pivot but pre-mount-
/// namespace-narrowing) — a directory the workload's own /proc/self/root
/// does NOT see.
///
/// Linux ≥5.2 for open_tree/move_mount. We already require ≥5.12 for
/// mount_setattr above, so this is always available. Best-effort: ENOSYS
/// is logged-and-skipped (defense-in-depth, not the only layer — landlock
/// still applies to the resolved target if it's path-backed; this just
/// closes the inode-level bypass for anon-inode targets).
fn mask_symlink(dev_null: &str, target: &str) -> Result<()> {
    use std::ffi::CString;

    // open_tree(2) constants — not in libc 0.2 yet.
    const OPEN_TREE_CLONE: u32 = 1;
    // move_mount(2): from_pathname is "" so we need F_EMPTY_PATH.
    // T_SYMLINKS would follow the dest symlink (the bug we're fixing);
    // its absence makes move_mount land on the symlink dentry.
    const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x0000_0004;

    let src = CString::new(dev_null).map_err(|_| sandbox_err("mask_symlink: NUL in /dev/null path".into()))?;
    let dst = CString::new(target).map_err(|_| sandbox_err(format!("mask_symlink: NUL in target {target}")))?;
    let empty = CString::new("").unwrap(); // Cannot fail on "".

    // SYS_open_tree: dirfd, pathname, flags. Returns a detached mount fd.
    // OPEN_TREE_CLONE makes a copy rather than detaching the live mount —
    // we want /dev/null to stay where it is.
    let tree_fd = unsafe { libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, src.as_ptr(), (libc::O_CLOEXEC as u32) | OPEN_TREE_CLONE) };
    if tree_fd < 0 {
        let errno = nix::errno::Errno::last();
        if errno == nix::errno::Errno::ENOSYS {
            // Kernel <5.2. Already excluded by mount_setattr's ≥5.12
            // requirement, but if someone disables that path: log and
            // skip rather than fail the whole sandbox. The symlink stays
            // exposed; landlock is still in front of any path-backed
            // resolution. Better than not booting.
            eprintln!(
                "[oaie] mask_symlink({target}): open_tree ENOSYS, \
                 kernel <5.2 — magic symlink left unmasked"
            );
            return Ok(());
        }
        return Err(sandbox_err(format!("mask_symlink({target}): open_tree({dev_null}): {errno}")));
    }
    // Past this point we own tree_fd; close on every exit.
    let tree_fd = tree_fd as libc::c_int;

    // SYS_move_mount: from_dirfd, from_pathname, to_dirfd, to_pathname, flags.
    // F_EMPTY_PATH = "the source IS from_dirfd, ignore from_pathname".
    // No T_SYMLINKS = do not follow the destination symlink.
    let ret = unsafe { libc::syscall(libc::SYS_move_mount, tree_fd, empty.as_ptr(), libc::AT_FDCWD, dst.as_ptr(), MOVE_MOUNT_F_EMPTY_PATH) };
    let errno = if ret < 0 { Some(nix::errno::Errno::last()) } else { None };
    unsafe { libc::close(tree_fd) };

    if let Some(errno) = errno {
        return Err(sandbox_err(format!("mask_symlink({target}): move_mount: {errno}")));
    }
    Ok(())
}

fn mount_setattr_recursive(target: &str, attr_set: u64) -> Result<()> {
    use std::ffi::CString;
    let path = CString::new(target).map_err(|_| sandbox_err(format!("mount_setattr: NUL in path {target}")))?;
    let attr = MountAttr { attr_set, ..Default::default() };
    // dirfd=AT_FDCWD, path=target, flags=AT_RECURSIVE, &attr, sizeof(attr).
    // The size argument lets the kernel handle struct-version skew (it
    // zero-extends if userspace's struct is shorter than the kernel's).
    // We pass exactly sizeof(MountAttr) — the v0 struct, 32 bytes —
    // which every kernel that has mount_setattr at all accepts.
    let ret = unsafe { libc::syscall(libc::SYS_mount_setattr, libc::AT_FDCWD, path.as_ptr(), AT_RECURSIVE, &attr as *const MountAttr, std::mem::size_of::<MountAttr>()) };
    if ret < 0 {
        let errno = nix::errno::Errno::last();
        return Err(sandbox_err(format!(
            "mount_setattr({target}, recursive, set={attr_set:#x}): {errno}. \
             Kernel ≥5.12 required — older kernels can't recursively flip \
             bind-mount flags, so submounts would silently keep host \
             superblock flags (writable + exec) inside the sandbox."
        )));
    }
    Ok(())
}

/// Old root mount point (for pivot_root, then detached).
const OLD_ROOT_REL: &str = ".old-root";

/// /proc entries masked with /dev/null (sensitive kernel info).
// cpuinfo/meminfo/version are NOT masked. They leak host hardware info
// (CPU model, RAM size, kernel version) which is a fingerprinting concern,
// but masking them breaks too many real consumers: `nproc` parses cpuinfo,
// allocators size from meminfo, tools gate features on kernel version.
// Standard fallbacks (`sched_getaffinity`, `uname(2)`,
// /sys/devices/system/cpu/) cover most of these, but every consumer that
// reads /proc/cpuinfo or /proc/version directly would break. The info is
// also reachable through /sys/devices/system/cpu/ (which we DON'T mask),
// so hiding /proc/cpuinfo only is incomplete anyway.
pub const PROC_MASK_ENTRIES: &[&str] = &["kallsyms", "kcore", "keys", "sysrq-trigger", "timer_list", "interrupts", "softirqs", "modules", "kpagecount", "kpageflags", "kpagecgroup", "sched_debug", "kmsg"];

/// Masks applied to /proc/1/* and the literal path /proc/self/*.
///
/// IMPORTANT: these ONLY affect PID 1. /proc/self is a kernel symlink to
/// /proc/<caller-pid>; when a grandchild at PID N opens /proc/self/maps,
/// the kernel resolves to /proc/N/maps — which is NOT masked. The bind-
/// mount over /proc/self/maps shadows the symlink itself, but the open()
/// follows the symlink target before the mount is consulted.
///
/// THREAT MODEL — read this before touching the list:
///
/// PID 1 is either the workload itself (single-process model) or a
/// supervisor that spawned the workload (supervisor model). In the
/// supervisor case /proc/1/* is the SUPERVISOR's state, and the workload
/// reading it is a privilege-relative leak: the supervisor may hold fds
/// to host-side files (config, request envelopes, response channels),
/// have the orchestrator's request context in its environment, and have
/// its own memory layout. Every entry here must be safe under that model.
/// Notably, /proc/1/fd is a magic-symlink directory: open(/proc/1/fd/N)
/// reopens fd N by inode and bypasses the mount namespace; /proc/1/auxv
/// leaks the supervisor's ASLR base and stack-canary seed address.
///
/// THE MASK IS NOT THE PRIMARY DEFENSE. /proc/1/task/<TID>/* aliases
/// every entry here for every thread the supervisor spawns. The
/// hardcoded prefix list at setup_proc() can't enumerate them — the
/// thread set is dynamic. The actual barrier is the single tmpfs over
/// /proc/1/task (see setup_proc) which kills the whole subtree. THIS
/// list is the per-entry layer for the direct /proc/1/X paths, where
/// the alias-killer doesn't reach.
///
/// Deliberately NOT in the list: maps, smaps*, status, limits, cgroup,
/// numa_maps — these aren't effectively hidden from grandchildren anyway
/// (kernel resolves /proc/self → /proc/N before mount lookup), and Go/JVM
/// runtimes need /proc/self/maps to work.
///
/// Also NOT in the list: uid_map, gid_map, setgroups — PER-USERNS, not
/// per-PID, so /proc/1/uid_map and /proc/N/uid_map return identical
/// content. Masking PID 1's copy leaves N readable copies. They're
/// fingerprinting at most: writing to uid_map only works once and only
/// from the parent userns; reading tells you the mapping, which the
/// workload can also derive from stat(2) on any host-bind-mounted file.
pub const PROC_SELF_MASK_ENTRIES: &[&str] = &[
    "pagemap", // physical page frame numbers — KASLR bypass material
    "oom_score_adj",
    "oom_adj",       // OOM killer manipulation
    "timerslack_ns", // timing side-channel tuning
    "mem",           // read/write arbitrary process memory
    "mountinfo",
    "mounts",     // host mount layout — fingerprinting + escape recon
    "mountstats", // sibling of mountinfo with the same per-mount
    // fingerprinting surface.
    "environ", // supervisor's env vars — host orchestrator request
    // context lives here in the supervisor model
    "syscall",
    "stack",
    "wchan",     // live execution state — ASLR hints
    "autogroup", // scheduler group manipulation
    "fdinfo",    // fd metadata: pos, mnt_id, flags. Mildly useful.
    "fd",        // THE BIG ONE. Magic-symlink directory: open(/proc/1/fd/N)
    // reopens fd N's underlying file BY INODE, bypassing the
    // mount namespace. Any host-side file the supervisor has
    // open is reachable through here, regardless of where it
    // lives outside the sandbox.
    "auxv", // ELF auxiliary vector. AT_BASE = supervisor's interpreter
    // load address, AT_ENTRY = supervisor's entry point, both
    // ASLR'd — leaks the supervisor's address-space layout.
    // AT_RANDOM is the ADDRESS of 16 bytes of randomness on
    // the stack (libc reads this for canaries) — combined with
    // a /proc/1/mem read (already masked) it's the canary seed,
    // but even alone the address is a stack ASLR leak.
    // The workload's OWN auxv at
    // /proc/self/auxv is its own layout — fine — but in the
    // supervisor model that's PID 2's, not PID 1's, so this
    // mask doesn't break self-introspection.
    "ns", // namespace inode numbers — setns() targets. setns is in
    // seccomp's ERRNO tier so direct escape is blocked, but
    // the inodes are identifiers (fingerprinting) and a fd
    // opened on /proc/1/ns/mnt is a setns-capable handle if
    // any future syscall accepting ns fds slips the filter.
    "attr", // LSM label manipulation
    "io",   // I/O accounting — timing side channel
];

/// /proc/<supervisor>/* magic symlinks. These can't be in PROC_SELF_MASK_ENTRIES
/// because that loop bind-mounts /dev/null over each entry, and classic
/// mount(2) follows the symlink during target resolution — mounting at
/// /proc/1/exe would mount at whatever the symlink RESOLVES TO (the host
/// binary's real path), not at the symlink itself. These need the new
/// mount API (open_tree + move_mount without MOVE_MOUNT_T_SYMLINKS); see
/// `mask_symlink()`.
///
/// `exe`  — open(/proc/1/exe) reads the supervisor binary's full ELF.
///          PID namespacing renumbers PIDs but does not access-control,
///          so this must be masked explicitly.
/// `root` — supervisor's root view. Post-pivot_root, but the supervisor
///          (PID 1) has a wider view than the workload (PID 2+) does:
///          the supervisor's root is what setup_mounts BUILT, including
///          paths that landlock then narrows for the workload but not for
///          PID 1. /proc/1/root/<path> bypasses the workload's landlock
///          ruleset by resolving in PID 1's context.
/// `cwd`  — supervisor's working directory. Same shape, narrower scope.
pub const PROC_SYMLINK_MASK_ENTRIES: &[&str] = &["exe", "root", "cwd"];

/// /proc directories masked with RO tmpfs.
///
/// Note: `net` is NOT in this list. /proc/net is a symlink to `self/net`
/// (since Linux 2.6.25), not a directory: mount(2) would follow the
/// symlink during target resolution and land the tmpfs on /proc/1/net,
/// while the workload at PID N would still resolve /proc/net through the
/// intact symlink to its own unmasked /proc/N/net.
///
/// Real /proc/net protection comes from CLONE_NEWNET — a fresh netns has
/// empty per-pid net dirs. NetworkMode::Off uses CLONE_NEWNET;
/// NetworkMode::On deliberately exposes the host network and /proc/net
/// with it. If we ever need to hide it under NetworkMode::On, that's
/// `subset=pid` on the proc mount (kernel ≥5.8), not path masking.
pub const PROC_DIR_MASK: &[&str] = &["sys", "sysvipc", "bus", "irq", "acpi", "scsi", "fs", "tty"];

/// Device nodes bind-mounted from host.
pub const DEV_NODES: &[&str] = &["null", "zero", "random", "urandom"];

/// Host system directories mounted read-only (with execute permission).
pub const SYSTEM_RO_DIRS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin"];

/// Set up the isolated mount namespace.
///
/// Must be called in the child process inside a mount namespace (CLONE_NEWNS).
/// After this returns, `/` is the new tmpfs root and the old root is detached.
///
/// `root_path` must be a unique directory path (e.g. `/tmp/oaie-root-<pid>`)
/// to avoid collisions between concurrent OAIE invocations.
pub(crate) fn setup_mounts(config: &SandboxConfig, root_path: &str) -> Result<()> {
    let new_root = root_path;
    // 1. Make all existing mounts private so changes don't propagate to host.
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>).map_err(|e| sandbox_err(format!("MS_PRIVATE on /: {e}")))?;

    // 2. Create tmpfs new root.
    fs::create_dir_all(new_root).map_err(|e| sandbox_err(format!("create {new_root}: {e}")))?;
    mount(Some("tmpfs"), new_root, Some("tmpfs"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV, Some("size=64m,mode=0755")).map_err(|e| sandbox_err(format!("mount tmpfs on {new_root}: {e}")))?;

    // 3. Create directories inside new root.
    let dirs = ["in", "out", "proc", "dev", "tmp", "usr", "lib", "lib64", "bin", "sbin", "etc", OLD_ROOT_REL, "root"];
    for d in &dirs {
        let path = format!("{new_root}/{d}");
        fs::create_dir_all(&path).map_err(|e| sandbox_err(format!("create dir {path}: {e}")))?;
    }

    // 4. Bind mount /in (read-only) from config.input_dir.
    bind_mount_ro(&config.input_dir, &format!("{new_root}/in"))?;

    // 5. Bind mount /out (read-write) from config.output_dir.
    bind_mount_rw(&config.output_dir, &format!("{new_root}/out"))?;

    // 6. System libraries — RO, skip if source doesn't exist.
    for dir in SYSTEM_RO_DIRS {
        if Path::new(dir).exists() {
            let target = format!("{new_root}{dir}");
            bind_mount_ro_nopriv(dir, &target)?;
        }
    }

    // 7. Minimal /etc.
    write_minimal_etc(new_root, &config.network)?;

    // 8. /tmp tmpfs (noexec, nodev, nosuid).
    mount(Some("tmpfs"), &format!("{new_root}/tmp") as &str, Some("tmpfs"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, Some("size=64m,mode=1777")).map_err(|e| sandbox_err(format!("mount /tmp tmpfs: {e}")))?;

    // 9. /proc.
    if config.proc_mount {
        setup_proc(new_root)?;
    }

    // 10. Minimal /dev (includes specific PTY slave when interactive mode is active).
    setup_minimal_dev(new_root, config.pty_slave_path.as_deref())?;

    // 11. Extra RO mounts from config.
    for (i, path) in config.extra_ro.iter().enumerate() {
        let mount_point = format!("{new_root}/mnt/ro{i}");
        fs::create_dir_all(&mount_point).map_err(|e| sandbox_err(format!("create extra_ro mount point: {e}")))?;
        bind_mount_ro(path, &mount_point)?;
    }

    // 12. Extra RW mounts from config.
    for (i, path) in config.extra_rw.iter().enumerate() {
        let mount_point = format!("{new_root}/mnt/rw{i}");
        fs::create_dir_all(&mount_point).map_err(|e| sandbox_err(format!("create extra_rw mount point: {e}")))?;
        bind_mount_rw(path, &mount_point)?;
    }

    // 12b. Session mounts: named bind mounts for session mode (dispatch socket, artifacts).
    for sm in &config.session_mounts {
        // Validate target path: must be absolute and contain no parent-dir traversal.
        if !sm.target.starts_with('/') {
            return Err(sandbox_err(format!("session mount target must be absolute: {:?}", sm.target)));
        }
        if Path::new(&sm.target).components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(sandbox_err(format!("session mount target contains '..': {:?}", sm.target)));
        }
        let mount_point = format!("{new_root}{}", sm.target);
        // Defense-in-depth: reject reserved target paths that would conflict
        // with the sandbox's own mount layout.
        let reserved = ["/proc", "/sys", "/dev", "/.old-root", "/in", "/out"];
        if reserved.iter().any(|r| sm.target == *r || sm.target.starts_with(&format!("{r}/"))) {
            return Err(sandbox_err(format!("session mount target conflicts with reserved path: {:?}", sm.target)));
        }
        // Create parent directories for the target path.
        if let Some(parent) = Path::new(&mount_point).parent() {
            fs::create_dir_all(parent).map_err(|e| sandbox_err(format!("create session mount parent {}: {e}", parent.display())))?;
        }
        // For files (e.g. Unix sockets), create an empty file as the mount point.
        // For directories, create the directory.
        if sm.source.is_dir() {
            fs::create_dir_all(&mount_point).map_err(|e| sandbox_err(format!("create session mount dir {}: {e}", sm.target)))?;
        } else {
            fs::OpenOptions::new().write(true).create_new(true).open(&mount_point).map_err(|e| sandbox_err(format!("create session mount file {}: {e}", sm.target)))?;
        }
        // Verify the created mount point hasn't escaped via symlinks.
        let canonical = fs::canonicalize(&mount_point).map_err(|e| sandbox_err(format!("canonicalize session mount {}: {e}", sm.target)))?;
        if !canonical.starts_with(new_root) {
            return Err(sandbox_err(format!("session mount target resolves outside sandbox root: {:?} -> {:?}", sm.target, canonical)));
        }
        if sm.exec {
            // exec forces RO — see the field doc on SessionMount. nopriv
            // variant drops NOEXEC; it's what /usr and /bin use.
            bind_mount_ro_nopriv(&sm.source.display().to_string(), &mount_point)?;
        } else if sm.writable {
            bind_mount_rw(&sm.source, &mount_point)?;
        } else {
            bind_mount_ro(&sm.source, &mount_point)?;
        }
    }

    // 13. pivot_root: switch filesystem root.
    let old_root_path = format!("{new_root}/{OLD_ROOT_REL}");

    pivot_root(new_root, old_root_path.as_str()).map_err(|e| sandbox_err(format!("pivot_root: {e}")))?;

    chdir("/").map_err(|e| sandbox_err(format!("chdir /: {e}")))?;

    // 14. Unmount and remove old root.
    let old_root_in_new = format!("/{OLD_ROOT_REL}");
    umount2(old_root_in_new.as_str(), MntFlags::MNT_DETACH).map_err(|e| sandbox_err(format!("umount old root: {e}")))?;
    // rmdir may fail if busy — that's fine, MNT_DETACH handles the cleanup.
    let _ = fs::remove_dir(&old_root_in_new);

    // 15. Remount root filesystem as read-only.
    // /out, /tmp, and /root are separate mounts (bind and tmpfs respectively)
    // so they remain writable. This prevents writing executables to /.
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV, None::<&str>).map_err(|e| sandbox_err(format!("remount / read-only: {e}")))?;

    // 16. Writable HOME directory. Many tools (gcc, python, git, npm, etc.)
    // write dotfiles to $HOME. Mount a small tmpfs so programs don't fail.
    mount(Some("tmpfs"), "/root", Some("tmpfs"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, Some("size=16m,mode=0700")).map_err(|e| sandbox_err(format!("mount tmpfs on /root: {e}")))?;

    Ok(())
}

/// Bind mount a path read-only with NODEV + NOSUID + NOEXEC.
///
/// NOEXEC prevents execution from user-controlled directories. The sandbox
/// mounts system dirs (/usr, /bin, etc.) separately via `bind_mount_ro_nopriv`
/// which does NOT include NOEXEC since tools need to execute binaries from there.
///
/// Two-step: MS_BIND|MS_REC creates the recursive bind tree, then
/// mount_setattr(AT_RECURSIVE) flips flags on the WHOLE tree. The
/// previous MS_REMOUNT|MS_REC second step looked recursive but wasn't —
/// Linux ignores MS_REC during remount, so only the top mount got the
/// flags. See the mount_setattr_recursive doc for the full bug class.
fn bind_mount_ro(source: &Path, target: &str) -> Result<()> {
    mount(Some(source), target, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>).map_err(|e| sandbox_err(format!("bind mount {}: {e}", source.display())))?;

    mount_setattr_recursive(target, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC)
}

/// Bind mount a path read-write with NODEV + NOSUID + NOEXEC.
///
/// NOEXEC prevents a sandboxed process from writing a payload to the output
/// directory and executing it. On kernels without Landlock (< 5.13), this is
/// the only barrier preventing execution from /out.
///
/// Same two-step as bind_mount_ro, minus RDONLY. The setattr is still
/// recursive — a submount under a RW bind shouldn't get to keep its
/// host suid/dev/exec flags any more than one under a RO bind should.
fn bind_mount_rw(source: &Path, target: &str) -> Result<()> {
    mount(Some(source), target, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>).map_err(|e| sandbox_err(format!("bind mount RW {}: {e}", source.display())))?;

    mount_setattr_recursive(target, MOUNT_ATTR_NODEV | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC)
}

/// Bind mount read-only with NODEV + NOSUID for system directories.
/// Note: NOEXEC is NOT applied because sandboxed tools need to execute
/// binaries from these paths (/usr/bin, /bin, etc.).
///
/// This is the helper most exposed to the MS_REC bug: SYSTEM_RO_DIRS
/// (/usr, /lib, /lib64, /bin, /sbin) are exactly the paths most likely
/// to have submounts on a real host (separate /usr/local, /lib/firmware
/// from a different package, etc.). The recursive setattr makes "RO
/// nopriv" actually mean it for the whole tree, not just the top.
fn bind_mount_ro_nopriv(source: &str, target: &str) -> Result<()> {
    mount(Some(source), target, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>).map_err(|e| sandbox_err(format!("bind mount {source}: {e}")))?;

    mount_setattr_recursive(target, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOSUID)
}

/// Write minimal /etc files needed for basic operation.
///
/// DNS resolution depends on network mode:
/// - `On`: copy host's `/etc/resolv.conf` (full DNS)
/// - `Allowlist`: point to `127.0.0.53` for the DNS proxy (Week 27);
///   until then, copy host resolv.conf as a placeholder
/// - `Off`: stub with no nameservers
fn write_minimal_etc(new_root: &str, network: &NetworkMode) -> Result<()> {
    let etc = format!("{new_root}/etc");

    // passwd: root user only (UID 0 maps to our user outside).
    fs::write(format!("{etc}/passwd"), "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n").map_err(|e| sandbox_err(format!("write /etc/passwd: {e}")))?;

    // group: root group.
    fs::write(format!("{etc}/group"), "root:x:0:\nnogroup:x:65534:\n").map_err(|e| sandbox_err(format!("write /etc/group: {e}")))?;

    // nsswitch.conf: use files only (no LDAP/NIS lookups).
    fs::write(format!("{etc}/nsswitch.conf"), "passwd: files\ngroup: files\nhosts: files dns\n").map_err(|e| sandbox_err(format!("write /etc/nsswitch.conf: {e}")))?;

    // hosts + hostname. CLONE_NEWUTS gives us a COPY of the parent's
    // hostname — `hostname` inside returns it unchanged. But nsswitch
    // says `hosts: files dns`, and without /etc/hosts mapping the
    // hostname to 127.0.0.1, anything that resolves the local hostname
    // (Java InetAddress.getLocalHost(), logging frameworks during init,
    // various JVM startup paths) goes to DNS, times out (no network or
    // DNS doesn't know the box name), and throws. gethostname() is the
    // same value `hostname` would print; mapping it to loopback is what
    // every distro's default /etc/hosts does.
    let mut hostname_buf = [0u8; 256];
    let hostname = unsafe {
        if libc::gethostname(hostname_buf.as_mut_ptr() as *mut libc::c_char, hostname_buf.len()) == 0 {
            std::ffi::CStr::from_bytes_until_nul(&hostname_buf).ok().and_then(|c| c.to_str().ok()).unwrap_or("sandbox")
        } else {
            "sandbox"
        }
    };
    fs::write(format!("{etc}/hostname"), format!("{hostname}\n")).map_err(|e| sandbox_err(format!("write /etc/hostname: {e}")))?;
    fs::write(
        format!("{etc}/hosts"),
        format!(
            "127.0.0.1\tlocalhost {hostname}\n\
             ::1\tlocalhost ip6-localhost ip6-loopback\n"
        ),
    )
    .map_err(|e| sandbox_err(format!("write /etc/hosts: {e}")))?;

    // resolv.conf: depends on network mode.
    let resolv = match network {
        NetworkMode::On => {
            // Full network: copy host nameservers.
            let content = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
            if content.trim().is_empty() {
                "# no nameservers configured\n".to_string()
            } else {
                content
            }
        }
        NetworkMode::Allowlist(_) => {
            // Allowlist mode: DNS proxy binds on 127.0.0.53 inside the namespace.
            "nameserver 127.0.0.53\noptions timeout:2 attempts:3\n".to_string()
        }
        NetworkMode::Off => "# no nameservers configured\n".to_string(),
    };
    fs::write(format!("{etc}/resolv.conf"), resolv).map_err(|e| sandbox_err(format!("write /etc/resolv.conf: {e}")))?;

    Ok(())
}

/// Mount /proc and mask sensitive entries.
fn setup_proc(new_root: &str) -> Result<()> {
    let proc_target = format!("{new_root}/proc");

    mount(Some("proc"), &proc_target as &str, Some("proc"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, None::<&str>).map_err(|e| sandbox_err(format!("mount /proc: {e}")))?;

    // Mask sensitive /proc entries by bind-mounting /dev/null over them.
    let dev_null = format!("{new_root}/dev/null");
    // Ensure /dev/null exists first (we create it in setup_minimal_dev,
    // but proc setup runs before dev setup in sequence — create a temp one).
    if !Path::new(&dev_null).exists() {
        // Create a minimal /dev/null for masking. The real one is set up later.
        fs::write(&dev_null, "").map_err(|e| sandbox_err(format!("create temp /dev/null: {e}")))?;
        mount(Some("/dev/null"), &dev_null as &str, None::<&str>, MsFlags::MS_BIND, None::<&str>).map_err(|e| sandbox_err(format!("bind /dev/null for masking: {e}")))?;
    }

    for entry in PROC_MASK_ENTRIES {
        let path = format!("{proc_target}/{entry}");
        if Path::new(&path).exists() {
            mount(Some(dev_null.as_str()), &path as &str, None::<&str>, MsFlags::MS_BIND, None::<&str>).map_err(|e| sandbox_err(format!("mask /proc/{entry}: {e}")))?;
        }
    }

    // Mask /proc/self entries. Build prefixed paths from PROC_SELF_MASK_ENTRIES.
    // Magic symlinks (exe/root/cwd) are handled separately below — they
    // can't be in PROC_SELF_MASK_ENTRIES because this loop's bind-mount
    // would follow the symlink and land on the wrong target.
    for entry in PROC_SELF_MASK_ENTRIES {
        let self_path = format!("{proc_target}/self/{entry}");
        let p = Path::new(&self_path);
        if !p.exists() {
            continue;
        }
        if p.is_dir() {
            // Directory entries (e.g. fdinfo/) must be masked with a RO tmpfs,
            // not /dev/null (which is a file — bind-mounting a file over a dir
            // fails with ENOTDIR).
            mount(Some("tmpfs"), &self_path as &str, Some("tmpfs"), MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, Some("size=0,mode=0555")).map_err(|e| sandbox_err(format!("mask /proc/self/{entry}: {e}")))?;
        } else {
            mount(Some(dev_null.as_str()), &self_path as &str, None::<&str>, MsFlags::MS_BIND, None::<&str>).map_err(|e| sandbox_err(format!("mask /proc/self/{entry}: {e}")))?;
        }
    }

    // ── /proc/1/task: ONE tmpfs kills every thread alias ────────────────
    //
    // PID 1 may be multithreaded (any supervisor that spawns helper
    // threads), and /proc/1/task/<TID>/* exposes the same sensitive
    // procfs entries (environ, mountinfo, ns, pagemap, fd, auxv) as
    // /proc/1/* does. The per-entry mask loop below only covers the main
    // thread (TID 1); enumerating task/* at setup time races thread
    // creation. The structural fix is a tmpfs over /proc/1/task itself —
    // one mount, every TID alias gone.
    //
    // We do NOT add "task" to PROC_SELF_MASK_ENTRIES because that loop
    // also applies to /proc/self/, and /proc/self/task is the workload's
    // own thread directory (Go's goroutine walker, JVM thread monitors,
    // and `ps -T` all read it). This mount targets only the supervisor's
    // task subtree.
    //
    // Mounted BEFORE the prefix loop so the loop's "1/task/1" iteration
    // sees an empty tmpfs and skips cleanly. The "1/task/1" entry in the
    // prefix loop becomes redundant but stays as defense-in-depth in case
    // this tmpfs mount fails open.
    {
        let task_path = format!("{proc_target}/1/task");
        if Path::new(&task_path).is_dir() {
            mount(Some("tmpfs"), &task_path as &str, Some("tmpfs"), MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, Some("size=0,mode=0555")).map_err(|e| sandbox_err(format!("mask /proc/1/task: {e}")))?;
        }
    }

    // ── EXPERIMENT: default-deny /proc/1/ ───────────────────────────────
    //
    // OAIE_EXPERIMENT_PROC1_ALLOWLIST=1 replaces /proc/1/ with an empty
    // tmpfs, hiding every entry by default rather than chasing a denylist.
    // Only safe when there's a supervisor/workload split (PID 1 is the
    // supervisor, workload runs at PID 2+ with its own unmasked /proc/2):
    // a standalone workload at PID 1 would be hiding /proc/self from
    // itself, breaking dladdr / current_exe / allocator probes.
    //
    // The per-entry mask loop below still runs but no-ops under the
    // tmpfs (p.exists() returns false). If a supervisor turns out to
    // need a specific entry, bind-back here — but anything bound back is
    // visible to the workload too, so the "fix the supervisor" answer
    // usually wins.
    if std::env::var_os("OAIE_EXPERIMENT_PROC1_ALLOWLIST").is_some() {
        let pid1_path = format!("{proc_target}/1");
        mount(Some("tmpfs"), &pid1_path as &str, Some("tmpfs"), MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, Some("size=0,mode=0555")).map_err(|e| sandbox_err(format!("EXPERIMENT: tmpfs /proc/1: {e}")))?;

        // /proc/thread-self resolves through /proc/<calling-pid>/task/<tid>,
        // and /proc/self through /proc/<calling-pid>. Both collapse onto
        // the tmpfs since the calling PID is 1.

        eprintln!("[oaie] EXPERIMENT: /proc/1/ replaced with empty tmpfs (default-deny)");
    }

    // Per-entry masks for the direct /proc/{1,self,thread-self}/<entry>
    // paths. /proc/1/task/* is already gone (tmpfs above); "1/task/1"
    // stays in the prefix list as a no-op fall-through (defense in depth
    // if the tmpfs above fails open — which it shouldn't, but neither
    // should anything else in this file).
    //
    // fork() inside the sandbox creates PID 2 with its own /proc/2/* —
    // that alias set is unbounded and these masks don't reach it. That's
    // correct: PID 2's procfs describes the SANDBOXED child (post-
    // pivot_root, post-exec, the workload's own state), not the
    // supervisor or the host. The workload reading its own /proc/2/maps
    // learns what it already knows.
    for prefix in ["1", "thread-self", "1/task/1"] {
        for entry in PROC_SELF_MASK_ENTRIES {
            let path = format!("{proc_target}/{prefix}/{entry}");
            let p = Path::new(&path);
            if !p.exists() {
                continue;
            }
            if p.is_dir() {
                mount(Some("tmpfs"), &path as &str, Some("tmpfs"), MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, Some("size=0,mode=0555")).map_err(|e| sandbox_err(format!("mask /proc/{prefix}/{entry}: {e}")))?;
            } else {
                mount(Some(dev_null.as_str()), &path as &str, None::<&str>, MsFlags::MS_BIND, None::<&str>).map_err(|e| sandbox_err(format!("mask /proc/{prefix}/{entry}: {e}")))?;
            }
        }
    }

    // Magic symlinks: exe/root/cwd. Can't go in the loop above — that
    // bind-mounts /dev/null, and classic mount(2) follows the symlink
    // (would mount at the host binary, not the procfs entry). mask_symlink
    // uses move_mount without MOVE_MOUNT_T_SYMLINKS to land on the dentry.
    //
    // 1/task/1 is NOT in this prefix list: /proc/1/task got a tmpfs mounted
    // over it as a whole (see the task_path block above), so 1/task/1/exe
    // doesn't exist. self/exe is the workload's own binary (PID 2 in the
    // supervisor model) — fine to read — but if PID 1 IS the workload (a
    // bare `oaie run` with no separate executor) then self == 1 and the
    // mask is harmless. thread-self/exe is the calling thread's
    // /proc/<tid>/exe, same as self in the single-threaded case.
    //
    // symlink_metadata (lstat) not metadata (stat): we want to confirm the
    // ENTRY is a symlink, not check what it points at. Skip if it isn't —
    // a kernel that turns one of these into a regular file someday should
    // go through the regular mask loop, not move_mount.
    for prefix in ["1", "self", "thread-self"] {
        for entry in PROC_SYMLINK_MASK_ENTRIES {
            let path = format!("{proc_target}/{prefix}/{entry}");
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_symlink() => {
                    mask_symlink(&dev_null, &path)?;
                }
                _ => {} // Doesn't exist, or not a symlink. Skip.
            }
        }
    }

    // Mount RO tmpfs over /proc directories that leak host info or allow writes.
    // /proc/net leaks host network configuration (interfaces, routes, connections)
    // even inside a network namespace. /proc/tty reveals terminal info.
    for dir in PROC_DIR_MASK {
        let path = format!("{proc_target}/{dir}");
        if Path::new(&path).exists() {
            mount(Some("tmpfs"), &path as &str, Some("tmpfs"), MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, Some("size=0,mode=0555")).map_err(|e| sandbox_err(format!("mount RO tmpfs on /proc/{dir}: {e}")))?;
        }
    }

    Ok(())
}

/// Set up minimal /dev with null, zero, and urandom.
///
/// When `pty_slave_path` is `Some`, bind-mounts only that specific PTY slave
/// file (e.g. `/dev/pts/3`) into the sandbox. This is much more restrictive
/// than mounting the entire `/dev/pts` directory — only the allocated slave
/// is visible, and no `/dev/ptmx` is provided (preventing the sandbox from
/// allocating new PTYs).
fn setup_minimal_dev(new_root: &str, pty_slave_path: Option<&Path>) -> Result<()> {
    let dev = format!("{new_root}/dev");

    // Bind mount essential device nodes from host.
    for d in DEV_NODES {
        let source = format!("/dev/{d}");
        let target = format!("{dev}/{d}");
        if !Path::new(&target).exists() {
            fs::write(&target, "").map_err(|e| sandbox_err(format!("create /dev/{d}: {e}")))?;
        }
        mount(Some(source.as_str()), target.as_str(), None::<&str>, MsFlags::MS_BIND, None::<&str>).map_err(|e| sandbox_err(format!("bind mount /dev/{d}: {e}")))?;

        // Remount with NOSUID+NOEXEC but NOT read-only and NOT nodev. /dev/null
        // and /dev/zero must be writable — programs constantly write to /dev/null
        // (shell redirections, logging sinks, etc.) and writing to /dev/zero is a
        // valid no-op. MS_NODEV here would make the device node itself unopenable:
        // open("/dev/null", O_RDWR) → EACCES. Rust's libstd does exactly that
        // during startup (to replace closed fds 0/1/2) and aborts when it fails,
        // which manifested as every Rust binary — including oaie itself —
        // segfaulting under the sandbox. NODEV is for filesystems where device
        // nodes shouldn't be honored (/tmp, /home); a bind of an intentional
        // device node is the opposite case.
        mount(None::<&str>, target.as_str(), None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC, None::<&str>).map_err(|e| sandbox_err(format!("remount /dev/{d}: {e}")))?;
    }

    // Interactive mode: bind-mount only the specific PTY slave file.
    // The PTY master is allocated on the host's devpts before clone() — the slave
    // path (e.g. /dev/pts/3) must be accessible inside the sandbox. We mount only
    // that single file, not the entire /dev/pts directory, so the sandbox cannot
    // see other users' PTY slaves or allocate new PTYs via /dev/ptmx.
    if let Some(slave_path) = pty_slave_path {
        let slave_name = slave_path.file_name().ok_or_else(|| sandbox_err("PTY slave path has no filename".into()))?;

        // Create /dev/pts/ directory and the specific slave mount point.
        let pts_dir = format!("{dev}/pts");
        fs::create_dir_all(&pts_dir).map_err(|e| sandbox_err(format!("create /dev/pts: {e}")))?;
        let slave_target = format!("{pts_dir}/{}", slave_name.to_string_lossy());
        fs::write(&slave_target, "").map_err(|e| sandbox_err(format!("create PTY slave mount point: {e}")))?;

        // Bind mount the specific slave device file.
        let slave_source = slave_path.to_string_lossy();
        mount(Some(slave_source.as_ref()), slave_target.as_str(), None::<&str>, MsFlags::MS_BIND, None::<&str>).map_err(|e| sandbox_err(format!("bind mount PTY slave: {e}")))?;

        // Harden: NOSUID+NOEXEC on the slave mount (defense in depth — the
        // slave is a char device, not an executable, but belt-and-suspenders).
        mount(None::<&str>, slave_target.as_str(), None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC, None::<&str>).map_err(|e| sandbox_err(format!("remount PTY slave: {e}")))?;
    }

    // /dev/fd → /proc/self/fd. Bash process substitution `<(cmd)` expands
    // to /dev/fd/N; without the symlink, any shell script using process
    // substitution gets "/dev/fd/63: No such file".
    // /proc is already mounted (setup_proc ran earlier in the sequence).
    // The stdin/out/err symlinks are less critical but cheap and expected
    // by scripts that do `> /dev/stderr` etc. Best-effort: symlink failure
    // (EEXIST from a leftover, permissions) shouldn't abort sandbox setup.
    let _ = std::os::unix::fs::symlink("/proc/self/fd", format!("{dev}/fd"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/0", format!("{dev}/stdin"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/1", format!("{dev}/stdout"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/2", format!("{dev}/stderr"));

    // /dev/shm — POSIX shared memory (shm_open/mmap). Python multiprocessing
    // with the default 'fork' start method uses it for inter-process queues;
    // Chrome/Electron for compositor buffers; PostgreSQL client libs for
    // large-object transfer. Small tmpfs (64M) because legitimate use is
    // handles-to-mapped-regions, not bulk storage — a tool dumping gigabytes
    // here is either misusing it or trying to evade RLIMIT_FSIZE (which
    // doesn't apply to tmpfs). NOEXEC because executable memory should go
    // through memfd_create (gated by allow_memfd), not a world-writable
    // filesystem path.
    let shm = format!("{dev}/shm");
    fs::create_dir_all(&shm).map_err(|e| sandbox_err(format!("create /dev/shm: {e}")))?;
    mount(Some("tmpfs"), shm.as_str(), Some("tmpfs"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, Some("size=64M,mode=1777")).map_err(|e| sandbox_err(format!("mount /dev/shm tmpfs: {e}")))?;

    Ok(())
}

/// Shorthand constructor for `OaieError::SandboxError`.
fn sandbox_err(msg: String) -> OaieError {
    OaieError::SandboxError(msg)
}
