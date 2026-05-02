//! Tests extracted from oaie-sandbox: seccomp BPF filter construction.

use oaie_sandbox::seccomp::{build_filter, errno_tier_syscalls, kill_tier_syscalls, BLOCKED_IOCTL_CMD_COUNT, BLOCKED_PRCTL_OPS_COUNT, BLOCKED_SOCKET_AF_COUNT};

/// Overhead instructions beyond the 4 header + kill + errno tier syscalls.
/// Header = LD arch, JEQ arch, LD nr, JGE x32-gate
/// x32 ABI shares AUDIT_ARCH_X86_64 with native x86_64).
///
/// 5 (clone JEQ + socket JEQ + prctl JEQ + ioctl JEQ + default ALLOW)
/// + 5 (clone arg check: load + AND + JEQ + KILL + ALLOW)
/// + 2 + Ns (socket arg check: load + Ns AF JEQs + ALLOW)
/// + 2 + Np (prctl arg check: load + Np op JEQs + ALLOW)
/// + 2 + Ni (ioctl arg check: load + Ni cmd JEQs + ALLOW)
/// + 2 (clone3 JEQ + inline RET ENOSYS — glibc falls back to inspectable clone())
/// + 2 (kill_ret + errno_ret)
///
/// Total: 21 + Ns + BLOCKED_PRCTL_OPS_COUNT + BLOCKED_IOCTL_CMD_COUNT.
/// SYS_socketpair gets its own dispatch JEQ because it reaches
/// __sock_create the same way socket does, so it must hit the same
/// args[0] AF check. Ns is BLOCKED_SOCKET_AF_COUNT (+1 when in_host_netns
/// adds AF_NETLINK).
const FILTER_OVERHEAD: usize = 21 + BLOCKED_SOCKET_AF_COUNT + BLOCKED_PRCTL_OPS_COUNT + BLOCKED_IOCTL_CMD_COUNT;

#[test]
fn filter_builds_without_panic() {
    let filter = build_filter(false, false).unwrap();
    let expected = 4 + kill_tier_syscalls().len() + errno_tier_syscalls(false).len() + FILTER_OVERHEAD;
    assert_eq!(filter.len(), expected);
}

#[test]
fn filter_instruction_count() {
    let filter = build_filter(false, false).unwrap();
    // Sanity: at least 20 instructions (we have ~55+ syscalls + overhead).
    assert!(filter.len() > 20, "expected > 20 instructions, got {}", filter.len());
    // And not unreasonably large (must fit in u8 jump offsets, max 257).
    assert!(filter.len() < 200, "filter too large: {} instructions", filter.len());
}

#[test]
fn filter_allow_memfd_has_fewer_errno_syscalls() {
    let without = errno_tier_syscalls(false);
    let with = errno_tier_syscalls(true);
    // allow_memfd=true excludes memfd_create and execveat (2 fewer syscalls).
    assert_eq!(without.len(), with.len() + 2);
}

#[test]
fn filter_allow_memfd_builds() {
    let filter = build_filter(true, false).unwrap();
    let expected = 4 + kill_tier_syscalls().len() + errno_tier_syscalls(true).len() + FILTER_OVERHEAD;
    assert_eq!(filter.len(), expected);
}

#[test]
fn filter_in_host_netns_blocks_netlink() {
    // NetworkMode::On skips CLONE_NEWNET, so the "netlink is harmless
    // inside a netns" assumption breaks. The filter must add AF_NETLINK
    // to the socket-AF block list in that mode.
    let off = build_filter(false, false).unwrap();
    let on = build_filter(false, true).unwrap();
    assert_eq!(on.len(), off.len() + 1, "in_host_netns should add one AF JEQ");
}

#[test]
fn blocked_socket_af_count_matches() {
    // Ensure BLOCKED_SOCKET_AF_COUNT stays in sync with the actual blocked families.
    // Currently: AF_PACKET, AF_CAN, AF_TIPC, AF_BLUETOOTH, AF_ALG,
    //            AF_NFC, AF_VSOCK, AF_KCM, AF_QIPCRTR, AF_XDP.
    // AF_NETLINK is NOT in this base list — it's appended at build time
    // when in_host_netns=true (NetworkMode::On). Inside a netns it's
    // harmless and blocking it breaks getifaddrs().
    assert_eq!(BLOCKED_SOCKET_AF_COUNT, 10);
}

#[test]
fn blocked_ioctl_cmd_count_matches() {
    // Ensure BLOCKED_IOCTL_CMD_COUNT stays in sync with the actual blocked commands.
    // Currently: TIOCSTI, TIOCLINUX.
    assert_eq!(BLOCKED_IOCTL_CMD_COUNT, 2);
}

#[test]
fn errno_tier_includes_fspick() {
    let syscalls = errno_tier_syscalls(false);
    // SYS_fspick = 433 on x86_64, 431 on aarch64.
    #[cfg(target_arch = "x86_64")]
    let fspick_nr: i64 = 433;
    #[cfg(target_arch = "aarch64")]
    let fspick_nr: i64 = 431;
    assert!(syscalls.contains(&fspick_nr), "fspick should be in ERRNO tier");
}

#[test]
fn errno_tier_includes_syslog() {
    let syscalls = errno_tier_syscalls(false);
    // SYS_syslog = 103 on x86_64, 116 on aarch64.
    #[cfg(target_arch = "x86_64")]
    let syslog_nr: i64 = 103;
    #[cfg(target_arch = "aarch64")]
    let syslog_nr: i64 = 116;
    assert!(syscalls.contains(&syslog_nr), "syslog should be in ERRNO tier");
}

#[test]
fn errno_tier_includes_mount_info_syscalls() {
    let syscalls = errno_tier_syscalls(false);
    // statmount (457) and listmount (458) — kernel 6.8+, bypass /proc masking.
    assert!(syscalls.contains(&457), "statmount should be in ERRNO tier");
    assert!(syscalls.contains(&458), "listmount should be in ERRNO tier");
}
