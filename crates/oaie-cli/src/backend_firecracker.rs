//! Firecracker microVM execution backend.
//!
//! Runs the command inside a Firecracker microVM with hardware-enforced
//! (KVM) isolation. The tool runs in a separate kernel/rootfs, communicating
//! with the host via AF_VSOCK.
//!
//! Behind the `firecracker` feature flag to keep tokio/hyper out of the
//! core oaie binary.

#[cfg(feature = "firecracker")]
use std::collections::HashMap;
#[cfg(feature = "firecracker")]
use std::path::Path;
#[cfg(feature = "firecracker")]
use std::time::Duration;

#[cfg(feature = "firecracker")]
use oaie_core::error::{OaieError, Result};
#[cfg(feature = "firecracker")]
use oaie_core::job::JobSpec;
#[cfg(feature = "firecracker")]
use oaie_core::manifest::ResourceInfo;
#[cfg(feature = "firecracker")]
use oaie_core::run_dir::RunDir;
#[cfg(feature = "firecracker")]
use oaie_core::run_id::RunId;

/// Result of a Firecracker VM execution.
#[cfg(feature = "firecracker")]
pub struct FirecrackerExecResult {
    /// Process exit code from the tool.
    pub exit_code: i32,
    /// Wall-clock duration of the tool execution.
    pub duration: Duration,
    /// Firecracker version string.
    pub firecracker_version: Option<String>,
    /// Kernel image name.
    pub kernel_name: Option<String>,
    /// Rootfs image name.
    pub rootfs_name: Option<String>,
    /// Resource usage (memory, not available from VM yet).
    pub resources: Option<ResourceInfo>,
}

/// Execute a command inside a Firecracker microVM.
///
/// This function:
/// 1. Detects Firecracker prerequisites
/// 2. Creates ext4 input image (if input dir specified)
/// 3. Creates ext4 output image
/// 4. Boots the VM with images attached
/// 5. Sends RunJob, streams stdout/stderr to run_dir files
/// 6. Receives JobDone
/// 7. Extracts outputs from output image
/// 8. Shuts down the VM
///
/// Returns a `FirecrackerExecResult` with exit code, duration, and metadata.
#[cfg(feature = "firecracker")]
pub fn execute_firecracker(
    job: &JobSpec,
    run_dir: &RunDir,
    out_dir: &Path,
    run_id: &RunId,
    effective_timeout: Option<Duration>,
    quiet: bool,
) -> Result<FirecrackerExecResult> {
    use oaie_firecracker::detect;
    use oaie_firecracker::image;
    use oaie_firecracker::rootfs::FirecrackerAssets;
    use oaie_firecracker::vm::{FirecrackerVm, VmConfig};

    if job.command.is_empty() {
        return Err(OaieError::InvalidJobSpec("empty command".into()));
    }

    // 1. Detect prerequisites.
    let caps = detect::detect();
    if !caps.available {
        return Err(OaieError::Other(format!(
            "Firecracker prerequisites not met: {}",
            caps.issues.join(", ")
        )));
    }

    let assets = FirecrackerAssets::load()?;

    // 2. Create ext4 input image if input directory is specified.
    let work_dir = tempfile::Builder::new()
        .prefix("oaie-fc-io-")
        .tempdir()
        .map_err(OaieError::Io)?;
    let work_path = work_dir.path();

    let input_image = if let Some(ref input_dir) = job.inputs {
        let img_path = work_path.join("input.ext4");
        image::create_input_image(input_dir.as_ref(), &img_path)?;
        Some(img_path)
    } else {
        None
    };

    // 3. Create ext4 output image (32 MiB default).
    let output_image_path = work_path.join("output.ext4");
    image::create_output_image(&output_image_path, 32)?;

    // 4. Boot the VM.
    let config = VmConfig {
        firecracker_path: caps.firecracker_path.clone().unwrap(),
        kernel_path: assets.kernel.clone(),
        rootfs_path: assets.rootfs.clone(),
        vcpu_count: 1,
        mem_size_mib: 128,
        input_image,
        output_image: Some(output_image_path.clone()),
    };

    let mut vm = FirecrackerVm::boot(&config)?;

    // 5. Build environment variables.
    let mut env = HashMap::new();
    env.insert("OAIE_RUN_ID".to_string(), run_id.full());
    env.insert("OAIE_OUT".to_string(), "/out".to_string());

    // 6. Run the job.
    let (exit_code, duration) = vm.run_job(
        job.command.clone(),
        env,
        effective_timeout,
        false, // trace — TODO Step 24
        &run_dir.stdout_path(),
        &run_dir.stderr_path(),
        quiet,
    )?;

    // 7. Shut down the VM.
    vm.shutdown()?;

    // 8. Extract outputs from the output image.
    // SECURITY: validate filenames from the guest to prevent path traversal.
    // A malicious tool could create files named "../../../etc/cron.d/evil".
    let files = image::list_image_files(&output_image_path).unwrap_or_default();
    for (name, _size) in &files {
        // Reject any filename with path traversal components.
        // Note: extract_file() also validates with an allowlist, but we
        // check here too for defense-in-depth before touching out_dir.
        if name.contains("..") || name.contains('/') || name.contains('\\')
            || name.starts_with('.')
            || name.contains('\0')
        {
            oaie_core::log_warn!(
                "skipping output file with suspicious name from guest VM: {name:?}"
            );
            continue;
        }
        let dest = out_dir.join(name);
        if let Err(e) = image::extract_file(&output_image_path, name, &dest) {
            oaie_core::log_warn!("failed to extract output file {name}: {e}");
        }
    }

    Ok(FirecrackerExecResult {
        exit_code,
        duration,
        firecracker_version: caps.firecracker_version.clone(),
        kernel_name: Some(
            assets
                .kernel
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "vmlinux".into()),
        ),
        rootfs_name: Some(
            assets
                .rootfs
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "rootfs.ext4".into()),
        ),
        resources: None,
    })
}
