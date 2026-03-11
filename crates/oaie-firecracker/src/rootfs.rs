//! Firecracker asset management — kernel, rootfs, and guest agent.
//!
//! Assets are stored in `~/.oaie/firecracker/`:
//! - `vmlinux` — uncompressed Linux kernel image
//! - `rootfs.ext4` — minimal Alpine Linux root filesystem
//! - `oaie-guest` — static musl binary of the guest agent

use std::fs;
use std::path::{Path, PathBuf};

use oaie_core::error::{OaieError, Result};

use crate::detect::assets_dir;

/// Paths to required Firecracker assets.
#[derive(Clone, Debug)]
pub struct FirecrackerAssets {
    /// Path to the kernel image.
    pub kernel: PathBuf,
    /// Path to the root filesystem image.
    pub rootfs: PathBuf,
    /// Path to the guest agent binary.
    pub guest_agent: PathBuf,
}

impl FirecrackerAssets {
    /// Load asset paths from the standard assets directory.
    ///
    /// Returns an error if any required asset is missing.
    pub fn load() -> Result<Self> {
        let dir = assets_dir();

        let kernel = dir.join("vmlinux");
        let rootfs = dir.join("rootfs.ext4");
        let guest_agent = dir.join("oaie-guest");

        let mut missing = Vec::new();
        if !kernel.exists() {
            missing.push(format!("kernel: {}", kernel.display()));
        }
        if !rootfs.exists() {
            missing.push(format!("rootfs: {}", rootfs.display()));
        }
        if !guest_agent.exists() {
            missing.push(format!("guest agent: {}", guest_agent.display()));
        }

        if !missing.is_empty() {
            return Err(OaieError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "missing Firecracker assets in {}:\n  {}",
                    dir.display(),
                    missing.join("\n  ")
                ),
            )));
        }

        Ok(Self {
            kernel,
            rootfs,
            guest_agent,
        })
    }

    /// Initialize the assets directory by copying from local build artifacts.
    ///
    /// For v0.2, this copies from local paths rather than downloading.
    /// `kernel_src`, `rootfs_src`, and `guest_src` are the source paths.
    pub fn init(
        kernel_src: &Path,
        rootfs_src: &Path,
        guest_src: &Path,
        force: bool,
    ) -> Result<Self> {
        let dir = assets_dir();
        fs::create_dir_all(&dir)?;

        let kernel = dir.join("vmlinux");
        let rootfs = dir.join("rootfs.ext4");
        let guest_agent = dir.join("oaie-guest");

        copy_asset(kernel_src, &kernel, "kernel", force)?;
        copy_asset(rootfs_src, &rootfs, "rootfs", force)?;
        copy_asset(guest_src, &guest_agent, "guest agent", force)?;

        // Make guest agent executable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o755);
            fs::set_permissions(&guest_agent, perms)?;
        }

        Ok(Self {
            kernel,
            rootfs,
            guest_agent,
        })
    }

    /// Check that all assets exist and are non-empty.
    pub fn check(&self) -> Result<()> {
        check_asset(&self.kernel, "kernel")?;
        check_asset(&self.rootfs, "rootfs")?;
        check_asset(&self.guest_agent, "guest agent")?;
        Ok(())
    }
}

/// Copy a single asset file, respecting the `force` flag.
fn copy_asset(src: &Path, dst: &Path, name: &str, force: bool) -> Result<()> {
    if !src.exists() {
        return Err(OaieError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{name} source not found: {}", src.display()),
        )));
    }

    if dst.exists() && !force {
        eprintln!(
            "OAIE: {name} already exists at {}, skipping (use --force to overwrite)",
            dst.display()
        );
        return Ok(());
    }

    eprintln!(
        "OAIE: copying {name}: {} -> {}",
        src.display(),
        dst.display()
    );
    fs::copy(src, dst)?;
    Ok(())
}

/// Check that an asset exists and is non-empty.
fn check_asset(path: &Path, name: &str) -> Result<()> {
    if !path.exists() {
        return Err(OaieError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{name} not found at {}", path.display()),
        )));
    }

    let meta = fs::metadata(path)?;
    if meta.len() == 0 {
        return Err(OaieError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{name} at {} is empty", path.display()),
        )));
    }

    Ok(())
}
