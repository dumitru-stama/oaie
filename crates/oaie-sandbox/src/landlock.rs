//! Landlock LSM defense-in-depth for sandbox child processes.
//!
//! Applied after `pivot_root()` in the sandbox child, before `execve()`.
//! Restricts filesystem access to only the paths the sandboxed process needs.
//! Falls back gracefully on kernels without Landlock support (< 5.13).
//!
//! Uses raw syscalls directly — no external crate dependency. This module
//! only runs inside the `clone()`-d child, so it must not allocate or panic.

use oaie_core::error::{OaieError, Result};

// ── Landlock syscall numbers (x86_64, same on aarch64) ──

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

// ── Landlock ABI constants (v1–v3 compatible) ──

/// Rule type: path beneath a directory.
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

// Filesystem access rights (Landlock ABI v1).
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

/// All filesystem access rights (ABI v1). Used as the `handled_access_fs`
/// in the ruleset — Landlock denies anything handled but not explicitly allowed.
const ALL_FS_ACCESS_V1: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;

// ABI v2 (kernel 5.19+): cross-directory rename/link.
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;

// ABI v3 (kernel 6.2+): truncate.
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

// ABI v5 (kernel 6.10+): ioctl on device files.
const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

/// Probe the highest supported Landlock ABI version.
/// Returns 0 if Landlock is not available.
fn landlock_abi_version() -> u32 {
    // Pass NULL attr, size 0, flag 1 (LANDLOCK_CREATE_RULESET_ATTR_SIZE_VER1)
    // to query the ABI version without creating a ruleset.
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<u8>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_ATTR_SIZE_VER1
        )
    };
    if ret >= 0 { ret as u32 } else { 0 }
}

/// Build the handled_access_fs bitmask for the detected ABI version.
fn all_fs_access_for_abi(abi: u32) -> u64 {
    let mut access = ALL_FS_ACCESS_V1;
    if abi >= 2 {
        access |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    access
}

/// Read-only access (read file + read dir).
const RO_ACCESS: u64 = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

/// Read-only + execute access (for /usr, /bin, etc.).
const RO_EXEC_ACCESS: u64 = RO_ACCESS | LANDLOCK_ACCESS_FS_EXECUTE;

/// Read-write access (everything except execute, ABI v1 base).
const RW_ACCESS_V1: u64 = ALL_FS_ACCESS_V1 & !LANDLOCK_ACCESS_FS_EXECUTE;

/// Build RW access for the detected ABI version (includes REFER/TRUNCATE/IOCTL_DEV).
fn rw_access_for_abi(abi: u32) -> u64 {
    let mut access = RW_ACCESS_V1;
    if abi >= 2 {
        access |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        access |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    access
}

// ── Kernel structs (must match kernel ABI) ──

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Apply Landlock filesystem restrictions inside the sandbox child.
///
/// Must be called after `pivot_root()` (paths are post-pivot) and after
/// `PR_SET_NO_NEW_PRIVS` (required by `landlock_restrict_self`).
///
/// Returns `Ok(true)` if Landlock was applied, `Ok(false)` if the kernel
/// doesn't support Landlock (ENOSYS/EOPNOTSUPP), or `Err` on unexpected failure.
///
/// `extra_ro_count` and `extra_rw_count` are the number of extra mounts
/// at `/mnt/ro0`..`/mnt/ro{n-1}` and `/mnt/rw0`..`/mnt/rw{n-1}`.
pub fn apply_landlock(extra_ro_count: usize, extra_rw_count: usize) -> Result<bool> {
    // Negotiate ABI version for best-available filesystem restrictions.
    let abi = landlock_abi_version();
    if abi == 0 {
        return Ok(false); // Landlock not available.
    }
    let all_access = all_fs_access_for_abi(abi);
    let rw_access = rw_access_for_abi(abi);

    // 1. Create a ruleset handling all filesystem access.
    let attr = RulesetAttr {
        handled_access_fs: all_access,
    };
    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32, // flags
        )
    };

    if ruleset_fd < 0 {
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::ENOSYS || errno == libc::EOPNOTSUPP {
            return Ok(false);
        }
        return Err(OaieError::SandboxError(format!(
            "landlock_create_ruleset failed (errno {errno})"
        )));
    }
    let ruleset_fd = ruleset_fd as i32;

    // 2. Add path rules for the post-pivot-root filesystem layout.
    // Use a closure to ensure ruleset_fd is closed on all exit paths
    // (add_path_rule errors would otherwise leak the fd via `?`).
    let add_rules = || -> Result<()> {
        // Input directory: read-only.
        add_path_rule(ruleset_fd, c"/in", RO_ACCESS)?;

        // Output directory: read-write.
        add_path_rule(ruleset_fd, c"/out", rw_access)?;

        // Temp: read-write but no execute.
        add_path_rule(ruleset_fd, c"/tmp", rw_access)?;

        // Home directory: read-write but no execute.
        add_path_rule(ruleset_fd, c"/root", rw_access)?;

        // System paths: read-only + execute.
        for path in &[c"/usr", c"/lib", c"/lib64", c"/bin", c"/sbin"] {
            add_path_rule(ruleset_fd, path, RO_EXEC_ACCESS)?;
        }

        // /proc: read-only (already masked by mount namespace).
        add_path_rule(ruleset_fd, c"/proc", RO_ACCESS)?;

        // /dev: read-write (programs write to /dev/null).
        add_path_rule(ruleset_fd, c"/dev", rw_access)?;

        // /etc: read-only (minimal etc from mounts.rs).
        add_path_rule(ruleset_fd, c"/etc", RO_ACCESS)?;

        // Extra mounts from policy.
        for i in 0..extra_ro_count {
            let path = format!("/mnt/ro{i}\0");
            add_path_rule_bytes(ruleset_fd, path.as_bytes(), RO_ACCESS)?;
        }
        for i in 0..extra_rw_count {
            let path = format!("/mnt/rw{i}\0");
            add_path_rule_bytes(ruleset_fd, path.as_bytes(), rw_access)?;
        }
        Ok(())
    };

    if let Err(e) = add_rules() {
        unsafe { libc::close(ruleset_fd); }
        return Err(e);
    }

    // 3. Enforce the ruleset.
    let ret = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
    unsafe { libc::close(ruleset_fd); }

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(OaieError::SandboxError(format!(
            "landlock_restrict_self failed (errno {errno})"
        )));
    }

    Ok(true)
}

/// Add a path rule to a Landlock ruleset. Silently skips if the path doesn't exist.
/// Returns an error if `landlock_add_rule` fails for a path that was successfully
/// opened — this indicates an unexpected kernel issue and the sandbox should not
/// proceed with a degraded Landlock ruleset (deny-by-default means the path would
/// become inaccessible).
fn add_path_rule(ruleset_fd: i32, path: &std::ffi::CStr, access: u64) -> Result<()> {
    let fd = unsafe {
        libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC)
    };
    if fd < 0 {
        return Ok(()); // Path doesn't exist post-pivot — skip silently.
    }

    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };

    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const PathBeneathAttr,
            0u32,
        )
    };
    unsafe { libc::close(fd); }

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(OaieError::SandboxError(format!(
            "landlock: add_rule failed for {:?} (errno {errno})",
            path
        )));
    }
    Ok(())
}

/// Add a path rule from a NUL-terminated byte slice (for dynamic paths like `/mnt/ro0`).
///
/// # Safety contract
/// `path_with_nul` must be a valid NUL-terminated byte string. The caller
/// ensures this via `format!("/mnt/ro{i}\0")`.
fn add_path_rule_bytes(ruleset_fd: i32, path_with_nul: &[u8], access: u64) -> Result<()> {
    if path_with_nul.last() != Some(&0) {
        return Err(OaieError::SandboxError(
            "landlock: path_with_nul not NUL-terminated".into(),
        ));
    }
    let fd = unsafe {
        libc::open(path_with_nul.as_ptr() as *const libc::c_char, libc::O_PATH | libc::O_CLOEXEC)
    };
    if fd < 0 {
        return Ok(());
    }

    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };

    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const PathBeneathAttr,
            0u32,
        )
    };
    unsafe { libc::close(fd); }

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        let path_display = &path_with_nul[..path_with_nul.len().saturating_sub(1)];
        return Err(OaieError::SandboxError(format!(
            "landlock: add_rule failed for {} (errno {errno})",
            String::from_utf8_lossy(path_display)
        )));
    }
    Ok(())
}

/// Probe whether Landlock is available on this kernel.
///
/// Returns `true` if `landlock_create_ruleset` succeeds with a minimal ruleset,
/// `false` if ENOSYS or EOPNOTSUPP. Used by `oaie doctor`.
pub fn probe_landlock() -> bool {
    let attr = RulesetAttr {
        handled_access_fs: ALL_FS_ACCESS_V1,
    };
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if ret >= 0 {
        unsafe { libc::close(ret as i32); }
        true
    } else {
        false
    }
}
