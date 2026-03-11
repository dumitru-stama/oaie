//! `oaie firecracker` subcommand — manage Firecracker microVM assets and test VM boot.

use clap::Subcommand;

use oaie_core::error::{OaieError, Result};

/// Firecracker microVM management commands.
#[derive(Subcommand)]
pub enum FirecrackerCmd {
    /// Initialize Firecracker assets (kernel, rootfs, guest agent)
    Init {
        /// Path to the kernel image (vmlinux)
        #[arg(long)]
        kernel: String,
        /// Path to the root filesystem image (ext4)
        #[arg(long)]
        rootfs: String,
        /// Path to the guest agent binary (oaie-guest)
        #[arg(long)]
        guest: String,
        /// Overwrite existing assets
        #[arg(long)]
        force: bool,
    },

    /// Check Firecracker prerequisites
    Check,

    /// Boot a test VM, run echo, and verify roundtrip
    BootTest,
}

impl FirecrackerCmd {
    pub fn execute(self) -> Result<()> {
        #[cfg(not(feature = "firecracker"))]
        {
            let _ = self;
            Err(OaieError::Io(std::io::Error::other(
                "oaie was built without the 'firecracker' feature",
            )))
        }

        #[cfg(feature = "firecracker")]
        match self {
            FirecrackerCmd::Init {
                kernel,
                rootfs,
                guest,
                force,
            } => execute_init(&kernel, &rootfs, &guest, force),
            FirecrackerCmd::Check => execute_check(),
            FirecrackerCmd::BootTest => execute_boot_test(),
        }
    }
}

#[cfg(feature = "firecracker")]
fn execute_init(kernel: &str, rootfs: &str, guest: &str, force: bool) -> Result<()> {
    use oaie_firecracker::rootfs::FirecrackerAssets;
    use std::path::Path;

    use crate::output;

    let assets = FirecrackerAssets::init(
        Path::new(kernel),
        Path::new(rootfs),
        Path::new(guest),
        force,
    )?;

    output::info("Firecracker assets initialized:");
    output::field("kernel", &assets.kernel.display().to_string());
    output::field("rootfs", &assets.rootfs.display().to_string());
    output::field("guest", &assets.guest_agent.display().to_string());
    Ok(())
}

#[cfg(feature = "firecracker")]
fn execute_check() -> Result<()> {
    use oaie_firecracker::detect;

    use crate::output;

    let caps = detect::detect();

    output::header("Firecracker Prerequisites");
    println!();

    let status = |ok: bool| if ok { "OK" } else { "MISSING" };

    output::field(
        "Binary",
        &match &caps.firecracker_path {
            Some(p) => format!(
                "{} (v{})",
                p.display(),
                caps.firecracker_version.as_deref().unwrap_or("unknown")
            ),
            None => "not found".into(),
        },
    );
    output::field("/dev/kvm", status(caps.kvm_available));
    output::field(
        "Kernel",
        &caps
            .kernel_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "not found".into()),
    );
    output::field(
        "Rootfs",
        &caps
            .rootfs_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "not found".into()),
    );
    output::field(
        "Guest agent",
        &caps
            .guest_agent_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "not found".into()),
    );

    println!();
    if caps.available {
        output::info("All prerequisites met — Firecracker backend ready");
    } else {
        output::warn("Missing prerequisites:");
        for issue in &caps.issues {
            eprintln!("  - {issue}");
        }
    }

    Ok(())
}

#[cfg(feature = "firecracker")]
fn execute_boot_test() -> Result<()> {
    use oaie_firecracker::detect;
    use oaie_firecracker::rootfs::FirecrackerAssets;
    use oaie_firecracker::vm::{FirecrackerVm, VmConfig};
    use std::collections::HashMap;

    use crate::output;

    output::info("Running Firecracker boot test...");

    // Check prerequisites.
    let caps = detect::detect();
    if !caps.available {
        return Err(OaieError::Io(std::io::Error::other(format!(
            "prerequisites not met: {}",
            caps.issues.join(", ")
        ))));
    }

    let assets = FirecrackerAssets::load()?;

    let config = VmConfig {
        firecracker_path: caps.firecracker_path.unwrap(),
        kernel_path: assets.kernel,
        rootfs_path: assets.rootfs,
        vcpu_count: 1,
        mem_size_mib: 128,
        input_image: None,
        output_image: None,
    };

    let mut vm = FirecrackerVm::boot(&config)?;
    output::info("VM booted successfully");

    let stdout_tmp = tempfile::NamedTempFile::new().map_err(OaieError::Io)?;
    let stderr_tmp = tempfile::NamedTempFile::new().map_err(OaieError::Io)?;

    let (exit_code, duration) = vm.run_job(
        vec!["echo".into(), "oaie-firecracker-boot-test".into()],
        HashMap::new(),
        Some(std::time::Duration::from_secs(10)),
        false,
        stdout_tmp.path(),
        stderr_tmp.path(),
        true,
    )?;

    vm.shutdown()?;

    let stdout_content = std::fs::read_to_string(stdout_tmp.path()).unwrap_or_default();

    if exit_code == 0 && stdout_content.trim() == "oaie-firecracker-boot-test" {
        output::info(&format!(
            "Boot test passed! echo roundtrip in {:.1}ms (VM lifecycle)",
            duration.as_secs_f64() * 1000.0,
        ));
        Ok(())
    } else {
        Err(OaieError::Io(std::io::Error::other(format!(
            "boot test failed: exit_code={exit_code}, stdout={stdout_content:?}"
        ))))
    }
}
