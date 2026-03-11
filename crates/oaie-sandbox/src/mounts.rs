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

/// Old root mount point (for pivot_root, then detached).
const OLD_ROOT_REL: &str = ".old-root";

/// /proc entries masked with /dev/null (sensitive kernel info).
pub const PROC_MASK_ENTRIES: &[&str] = &[
    "kallsyms", "kcore", "keys", "sysrq-trigger", "timer_list",
    "interrupts", "softirqs", "modules", "kpagecount", "kpageflags",
    "kpagecgroup", "sched_debug", "kmsg", "version", "cpuinfo", "meminfo",
];

/// /proc/self (and /proc/1) entries masked.
pub const PROC_SELF_MASK_ENTRIES: &[&str] = &[
    "pagemap", "oom_score_adj", "oom_adj", "timerslack_ns", "mem",
    "mountinfo", "mounts", "environ", "maps", "smaps", "smaps_rollup",
    "numa_maps", "status", "syscall", "stack", "wchan", "autogroup",
    "uid_map", "gid_map", "setgroups", "fdinfo", "limits", "cgroup",
    "ns", "attr", "io",
];

/// /proc directories masked with RO tmpfs.
pub const PROC_DIR_MASK: &[&str] = &[
    "sys", "sysvipc", "bus", "irq", "acpi", "scsi", "fs", "net", "tty",
];

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
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| sandbox_err(format!("MS_PRIVATE on /: {e}")))?;

    // 2. Create tmpfs new root.
    fs::create_dir_all(new_root)
        .map_err(|e| sandbox_err(format!("create {new_root}: {e}")))?;
    mount(
        Some("tmpfs"),
        new_root,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=64m,mode=0755"),
    )
    .map_err(|e| sandbox_err(format!("mount tmpfs on {new_root}: {e}")))?;

    // 3. Create directories inside new root.
    let dirs = [
        "in", "out", "proc", "dev", "tmp", "usr", "lib", "lib64", "bin", "sbin", "etc",
        OLD_ROOT_REL, "root",
    ];
    for d in &dirs {
        let path = format!("{new_root}/{d}");
        fs::create_dir_all(&path)
            .map_err(|e| sandbox_err(format!("create dir {path}: {e}")))?;
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
    mount(
        Some("tmpfs"),
        &format!("{new_root}/tmp") as &str,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("size=64m,mode=1777"),
    )
    .map_err(|e| sandbox_err(format!("mount /tmp tmpfs: {e}")))?;

    // 9. /proc.
    if config.proc_mount {
        setup_proc(new_root)?;
    }

    // 10. Minimal /dev (includes specific PTY slave when interactive mode is active).
    setup_minimal_dev(new_root, config.pty_slave_path.as_deref())?;

    // 11. Extra RO mounts from config.
    for (i, path) in config.extra_ro.iter().enumerate() {
        let mount_point = format!("{new_root}/mnt/ro{i}");
        fs::create_dir_all(&mount_point)
            .map_err(|e| sandbox_err(format!("create extra_ro mount point: {e}")))?;
        bind_mount_ro(path, &mount_point)?;
    }

    // 12. Extra RW mounts from config.
    for (i, path) in config.extra_rw.iter().enumerate() {
        let mount_point = format!("{new_root}/mnt/rw{i}");
        fs::create_dir_all(&mount_point)
            .map_err(|e| sandbox_err(format!("create extra_rw mount point: {e}")))?;
        bind_mount_rw(path, &mount_point)?;
    }

    // 12b. Session mounts: named bind mounts for session mode (dispatch socket, artifacts).
    for sm in &config.session_mounts {
        // Validate target path: must be absolute and contain no parent-dir traversal.
        if !sm.target.starts_with('/') {
            return Err(sandbox_err(format!(
                "session mount target must be absolute: {:?}",
                sm.target
            )));
        }
        if Path::new(&sm.target)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(sandbox_err(format!(
                "session mount target contains '..': {:?}",
                sm.target
            )));
        }
        let mount_point = format!("{new_root}{}", sm.target);
        // Create parent directories for the target path.
        if let Some(parent) = Path::new(&mount_point).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| sandbox_err(format!("create session mount parent {}: {e}", parent.display())))?;
        }
        // Defense-in-depth: reject reserved target paths that would conflict
        // with the sandbox's own mount layout.
        let reserved = ["/proc", "/sys", "/dev", "/.old-root", "/in", "/out"];
        if reserved.iter().any(|r| sm.target == *r || sm.target.starts_with(&format!("{r}/"))) {
            return Err(sandbox_err(format!(
                "session mount target conflicts with reserved path: {:?}",
                sm.target
            )));
        }
        // For files (e.g. Unix sockets), create an empty file as the mount point.
        // For directories, create the directory.
        if sm.source.is_dir() {
            fs::create_dir_all(&mount_point)
                .map_err(|e| sandbox_err(format!("create session mount dir {}: {e}", sm.target)))?;
        } else {
            fs::write(&mount_point, "")
                .map_err(|e| sandbox_err(format!("create session mount file {}: {e}", sm.target)))?;
        }
        // Verify the created mount point hasn't escaped via symlinks.
        let canonical = fs::canonicalize(&mount_point)
            .map_err(|e| sandbox_err(format!("canonicalize session mount {}: {e}", sm.target)))?;
        if !canonical.starts_with(new_root) {
            return Err(sandbox_err(format!(
                "session mount target resolves outside sandbox root: {:?} -> {:?}",
                sm.target,
                canonical
            )));
        }
        if sm.writable {
            bind_mount_rw(&sm.source, &mount_point)?;
        } else {
            bind_mount_ro(&sm.source, &mount_point)?;
        }
    }

    // 13. pivot_root: switch filesystem root.
    let old_root_path = format!("{new_root}/{OLD_ROOT_REL}");

    pivot_root(new_root, old_root_path.as_str())
        .map_err(|e| sandbox_err(format!("pivot_root: {e}")))?;

    chdir("/").map_err(|e| sandbox_err(format!("chdir /: {e}")))?;

    // 14. Unmount and remove old root.
    let old_root_in_new = format!("/{OLD_ROOT_REL}");
    umount2(old_root_in_new.as_str(), MntFlags::MNT_DETACH)
        .map_err(|e| sandbox_err(format!("umount old root: {e}")))?;
    // rmdir may fail if busy — that's fine, MNT_DETACH handles the cleanup.
    let _ = fs::remove_dir(&old_root_in_new);

    // 15. Remount root filesystem as read-only.
    // /out, /tmp, and /root are separate mounts (bind and tmpfs respectively)
    // so they remain writable. This prevents writing executables to /.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .map_err(|e| sandbox_err(format!("remount / read-only: {e}")))?;

    // 16. Writable HOME directory. Many tools (gcc, python, git, npm, etc.)
    // write dotfiles to $HOME. Mount a small tmpfs so programs don't fail.
    mount(
        Some("tmpfs"),
        "/root",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("size=16m,mode=0700"),
    )
    .map_err(|e| sandbox_err(format!("mount tmpfs on /root: {e}")))?;

    Ok(())
}

/// Bind mount a path read-only with NODEV + NOSUID + NOEXEC.
///
/// NOEXEC prevents execution from user-controlled directories. The sandbox
/// mounts system dirs (/usr, /bin, etc.) separately via `bind_mount_ro_nopriv`
/// which does NOT include NOEXEC since tools need to execute binaries from there.
fn bind_mount_ro(source: &Path, target: &str) -> Result<()> {
    // First bind, then remount RO (Linux requires two steps for RO bind mounts).
    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| sandbox_err(format!("bind mount {}: {e}", source.display())))?;

    mount(
        None::<&str>,
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY
            | MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| sandbox_err(format!("remount RO {}: {e}", source.display())))?;

    Ok(())
}

/// Bind mount a path read-write with NODEV + NOSUID + NOEXEC.
///
/// NOEXEC prevents a sandboxed process from writing a payload to the output
/// directory and executing it. On kernels without Landlock (< 5.13), this is
/// the only barrier preventing execution from /out.
fn bind_mount_rw(source: &Path, target: &str) -> Result<()> {
    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| sandbox_err(format!("bind mount RW {}: {e}", source.display())))?;

    mount(
        None::<&str>,
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT
            | MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| sandbox_err(format!("remount RW nodev/nosuid/noexec {}: {e}", source.display())))?;

    Ok(())
}

/// Bind mount read-only with NODEV + NOSUID for system directories.
/// Note: MS_NOEXEC is NOT applied because sandboxed tools need to execute
/// binaries from these paths (/usr/bin, /bin, etc.).
fn bind_mount_ro_nopriv(source: &str, target: &str) -> Result<()> {
    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| sandbox_err(format!("bind mount {source}: {e}")))?;

    mount(
        None::<&str>,
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
        None::<&str>,
    )
    .map_err(|e| sandbox_err(format!("remount RO nopriv {source}: {e}")))?;

    Ok(())
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
    fs::write(
        format!("{etc}/passwd"),
        "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
    )
    .map_err(|e| sandbox_err(format!("write /etc/passwd: {e}")))?;

    // group: root group.
    fs::write(
        format!("{etc}/group"),
        "root:x:0:\nnogroup:x:65534:\n",
    )
    .map_err(|e| sandbox_err(format!("write /etc/group: {e}")))?;

    // nsswitch.conf: use files only (no LDAP/NIS lookups).
    fs::write(
        format!("{etc}/nsswitch.conf"),
        "passwd: files\ngroup: files\nhosts: files dns\n",
    )
    .map_err(|e| sandbox_err(format!("write /etc/nsswitch.conf: {e}")))?;

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
        NetworkMode::Off => {
            "# no nameservers configured\n".to_string()
        }
    };
    fs::write(format!("{etc}/resolv.conf"), resolv)
        .map_err(|e| sandbox_err(format!("write /etc/resolv.conf: {e}")))?;

    Ok(())
}

/// Mount /proc and mask sensitive entries.
fn setup_proc(new_root: &str) -> Result<()> {
    let proc_target = format!("{new_root}/proc");

    mount(
        Some("proc"),
        &proc_target as &str,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| sandbox_err(format!("mount /proc: {e}")))?;

    // Mask sensitive /proc entries by bind-mounting /dev/null over them.
    let dev_null = format!("{new_root}/dev/null");
    // Ensure /dev/null exists first (we create it in setup_minimal_dev,
    // but proc setup runs before dev setup in sequence — create a temp one).
    if !Path::new(&dev_null).exists() {
        // Create a minimal /dev/null for masking. The real one is set up later.
        fs::write(&dev_null, "")
            .map_err(|e| sandbox_err(format!("create temp /dev/null: {e}")))?;
        mount(
            Some("/dev/null"),
            &dev_null as &str,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| sandbox_err(format!("bind /dev/null for masking: {e}")))?;
    }

    for entry in PROC_MASK_ENTRIES {
        let path = format!("{proc_target}/{entry}");
        if Path::new(&path).exists() {
            mount(
                Some(dev_null.as_str()),
                &path as &str,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|e| sandbox_err(format!("mask /proc/{entry}: {e}")))?;
        }
    }

    // Mask /proc/self entries. Build prefixed paths from PROC_SELF_MASK_ENTRIES.
    // Note: /proc/self/exe is a symlink and cannot be bind-mounted over;
    // it's already protected by the PID namespace.
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
            mount(
                Some("tmpfs"),
                &self_path as &str,
                Some("tmpfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some("size=0,mode=0555"),
            )
            .map_err(|e| sandbox_err(format!("mask /proc/self/{entry}: {e}")))?;
        } else {
            mount(
                Some(dev_null.as_str()),
                &self_path as &str,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|e| sandbox_err(format!("mask /proc/self/{entry}: {e}")))?;
        }
    }

    // Also mask /proc/1/* — the child is PID 1 inside its PID namespace,
    // so /proc/1/environ, /proc/1/maps etc. bypass the /proc/self/* masking.
    for entry in PROC_SELF_MASK_ENTRIES {
        let path = format!("{proc_target}/1/{entry}");
        let p = Path::new(&path);
        if !p.exists() {
            continue;
        }
        if p.is_dir() {
            mount(
                Some("tmpfs"),
                &path as &str,
                Some("tmpfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some("size=0,mode=0555"),
            )
            .map_err(|e| sandbox_err(format!("mask /proc/1/{entry}: {e}")))?;
        } else {
            mount(
                Some(dev_null.as_str()),
                &path as &str,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|e| sandbox_err(format!("mask /proc/1/{entry}: {e}")))?;
        }
    }

    // Mount RO tmpfs over /proc directories that leak host info or allow writes.
    // /proc/net leaks host network configuration (interfaces, routes, connections)
    // even inside a network namespace. /proc/tty reveals terminal info.
    for dir in PROC_DIR_MASK {
        let path = format!("{proc_target}/{dir}");
        if Path::new(&path).exists() {
            mount(
                Some("tmpfs"),
                &path as &str,
                Some("tmpfs"),
                MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
                Some("size=0,mode=0555"),
            )
            .map_err(|e| sandbox_err(format!("mount RO tmpfs on /proc/{dir}: {e}")))?;
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
            fs::write(&target, "")
                .map_err(|e| sandbox_err(format!("create /dev/{d}: {e}")))?;
        }
        mount(
            Some(source.as_str()),
            target.as_str(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| sandbox_err(format!("bind mount /dev/{d}: {e}")))?;

        // Remount with NOSUID+NOEXEC but NOT read-only. /dev/null and /dev/zero
        // must be writable — programs constantly write to /dev/null (shell redirections,
        // logging sinks, etc.) and writing to /dev/zero is a valid no-op.
        mount(
            None::<&str>,
            target.as_str(),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|e| sandbox_err(format!("remount /dev/{d}: {e}")))?;
    }

    // Interactive mode: bind-mount only the specific PTY slave file.
    // The PTY master is allocated on the host's devpts before clone() — the slave
    // path (e.g. /dev/pts/3) must be accessible inside the sandbox. We mount only
    // that single file, not the entire /dev/pts directory, so the sandbox cannot
    // see other users' PTY slaves or allocate new PTYs via /dev/ptmx.
    if let Some(slave_path) = pty_slave_path {
        let slave_name = slave_path
            .file_name()
            .ok_or_else(|| sandbox_err("PTY slave path has no filename".into()))?;

        // Create /dev/pts/ directory and the specific slave mount point.
        let pts_dir = format!("{dev}/pts");
        fs::create_dir_all(&pts_dir)
            .map_err(|e| sandbox_err(format!("create /dev/pts: {e}")))?;
        let slave_target = format!("{pts_dir}/{}", slave_name.to_string_lossy());
        fs::write(&slave_target, "")
            .map_err(|e| sandbox_err(format!("create PTY slave mount point: {e}")))?;

        // Bind mount the specific slave device file.
        let slave_source = slave_path.to_string_lossy();
        mount(
            Some(slave_source.as_ref()),
            slave_target.as_str(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| sandbox_err(format!("bind mount PTY slave: {e}")))?;

        // Harden: NOSUID+NOEXEC on the slave mount (defense in depth — the
        // slave is a char device, not an executable, but belt-and-suspenders).
        mount(
            None::<&str>,
            slave_target.as_str(),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|e| sandbox_err(format!("remount PTY slave: {e}")))?;
    }

    Ok(())
}

/// Shorthand constructor for `OaieError::SandboxError`.
fn sandbox_err(msg: String) -> OaieError {
    OaieError::SandboxError(msg)
}
