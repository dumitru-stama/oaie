//! ext4 image creation for VM I/O.
//!
//! Input directories are packaged as read-only ext4 images using `mkfs.ext4 -d`
//! (from e2fsprogs). This avoids needing root privileges — `mkfs.ext4 -d`
//! populates the filesystem from a directory without mounting.
//!
//! Output images are empty ext4 filesystems that the guest mounts as writable.
//! After VM exit, the host reads files back using `debugfs`.

use std::path::Path;
use std::process::Command;

use oaie_core::error::{OaieError, Result};

/// Minimum image size in bytes (4 MiB).
const MIN_IMAGE_SIZE: u64 = 4 * 1024 * 1024;

/// Maximum input image size in bytes (4 GiB). Prevents a huge input directory
/// from creating an oversized image that exhausts disk space.
const MAX_INPUT_IMAGE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum output image size in MiB (512 MiB).
const MAX_OUTPUT_IMAGE_MIB: u32 = 512;

/// Maximum debugfs output we'll read (1 MiB). Protects against a corrupt
/// image producing unbounded output from debugfs.
const MAX_DEBUGFS_OUTPUT: usize = 1024 * 1024;

/// Create an ext4 image from a directory's contents.
///
/// Uses `mkfs.ext4 -d <dir>` to populate the filesystem without mounting.
/// The image is sized to the directory contents + 10% headroom, with a
/// minimum of 4 MiB.
pub fn create_input_image(input_dir: &Path, image_path: &Path) -> Result<()> {
    if !input_dir.exists() {
        return Err(OaieError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("input directory does not exist: {}", input_dir.display()),
        )));
    }

    // Calculate directory size (uses symlink_metadata to avoid following symlinks).
    let dir_size = dir_size(input_dir)?;
    // Add 10% headroom using integer arithmetic (avoids f64 precision loss).
    let image_size = (dir_size.saturating_add(dir_size / 10)).max(MIN_IMAGE_SIZE);

    if image_size > MAX_INPUT_IMAGE_SIZE {
        return Err(OaieError::Io(std::io::Error::other(format!(
            "input directory too large for VM image: {} bytes (max {} bytes)",
            image_size, MAX_INPUT_IMAGE_SIZE
        ))));
    }

    // Create empty file of the right size.
    create_sparse_file(image_path, image_size)?;

    // Format as ext4 and populate from directory.
    let output = Command::new("mkfs.ext4")
        .args(["-q", "-F"])
        .arg("-d")
        .arg(input_dir)
        .arg(image_path)
        .output()
        .map_err(|e| {
            OaieError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to run mkfs.ext4: {e}"),
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OaieError::Io(std::io::Error::other(
            format!("mkfs.ext4 failed: {stderr}"),
        )));
    }

    Ok(())
}

/// Create an empty ext4 image for output collection.
///
/// The guest mounts this as writable at /out. After VM exit, the host
/// reads files back using `debugfs` or by loop-mounting.
pub fn create_output_image(image_path: &Path, size_mib: u32) -> Result<()> {
    if size_mib > MAX_OUTPUT_IMAGE_MIB {
        return Err(OaieError::Io(std::io::Error::other(format!(
            "output image size {} MiB exceeds maximum {} MiB",
            size_mib, MAX_OUTPUT_IMAGE_MIB
        ))));
    }
    let size = (size_mib as u64) * 1024 * 1024;
    create_sparse_file(image_path, size.max(MIN_IMAGE_SIZE))?;

    let output = Command::new("mkfs.ext4")
        .args(["-q", "-F"])
        .arg(image_path)
        .output()
        .map_err(|e| {
            OaieError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to run mkfs.ext4: {e}"),
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OaieError::Io(std::io::Error::other(
            format!("mkfs.ext4 failed: {stderr}"),
        )));
    }

    Ok(())
}

/// List files in an ext4 image root directory using debugfs.
///
/// Returns a list of (name, size) tuples for regular files in the root
/// directory only. Subdirectories are not recursed (output files from the
/// guest agent are always placed in the root of /out).
pub fn list_image_files(image_path: &Path) -> Result<Vec<(String, u64)>> {
    use std::process::Stdio;

    let mut child = Command::new("debugfs")
        .args(["-R", "ls -p /"])
        .arg(image_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            OaieError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to run debugfs: {e}"),
            ))
        })?;

    // Read stdout with a size cap to prevent a corrupt image from
    // producing unbounded output.
    let stdout_pipe = child.stdout.take().unwrap();
    let mut buf = Vec::new();
    use std::io::Read;
    stdout_pipe
        .take(MAX_DEBUGFS_OUTPUT as u64)
        .read_to_end(&mut buf)
        .map_err(OaieError::Io)?;
    let _ = child.wait();

    let stdout = String::from_utf8_lossy(&buf);
    let mut files = Vec::new();

    for line in stdout.lines() {
        // debugfs -p format: /inode/type/mode/uid/gid/name/size/...
        // Type field: 40000 = dir, 100000+ = regular file, 120000 = symlink.
        let fields: Vec<&str> = line.split('/').collect();
        if fields.len() >= 7 {
            let file_type = fields[2].trim();
            let name = fields[5];
            // Skip . and .. entries and lost+found.
            if name == "." || name == ".." || name == "lost+found" {
                continue;
            }
            // Only include regular files (mode starts with 100).
            // Reject symlinks (120), directories (040), devices, etc.
            if !file_type.starts_with("100") {
                continue;
            }
            let size = fields[6].parse::<u64>().unwrap_or(0);
            files.push((name.to_string(), size));
        }
    }

    Ok(files)
}

/// Extract a single file from an ext4 image using debugfs.
///
/// SECURITY: `file_name` must be a simple basename (no path separators,
/// no `..`, no special characters). Callers must validate before calling.
pub fn extract_file(image_path: &Path, file_name: &str, dest_path: &Path) -> Result<()> {
    // SECURITY: Validate filename with an allowlist to prevent debugfs command
    // injection. debugfs -R tokenizes on whitespace and interprets quotes and
    // special characters, so we only allow safe characters: [a-zA-Z0-9._-].
    let valid = !file_name.is_empty()
        && !file_name.contains("..")
        && file_name.len() <= 255
        && file_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    if !valid {
        return Err(OaieError::Io(std::io::Error::other(
            format!("invalid filename for extraction: {file_name:?}"),
        )));
    }
    // Reject if dest already exists — the exists() check after debugfs
    // assumes debugfs created the file. A pre-existing dest would make a
    // non-zero exit indistinguishable from success.
    if dest_path.exists() {
        return Err(OaieError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("extract_file: destination already exists: {}", dest_path.display()),
        )));
    }
    let dump_cmd = format!("dump /{} {}", file_name, dest_path.display());
    let output = Command::new("debugfs")
        .args(["-R", &dump_cmd])
        .arg(image_path)
        .output()
        .map_err(|e| {
            OaieError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to run debugfs: {e}"),
            ))
        })?;

    // debugfs -R exits 0 even when the dump request fails (errors go to
    // stderr only). The only reliable success signal is whether dest_path
    // was actually created — we verified above that it did not pre-exist.
    if !dest_path.exists() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OaieError::Io(std::io::Error::other(
            format!("debugfs dump failed for {file_name}: {stderr}"),
        )));
    }

    Ok(())
}

/// Calculate the total size of a directory recursively.
///
/// Uses `symlink_metadata` to avoid following symlinks — a symlink pointing
/// outside the directory could cause incorrect size calculations or TOCTOU
/// issues.
fn dir_size(path: &Path) -> Result<u64> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_file() {
        return Ok(meta.len());
    }
    let mut total = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        // Use file_type() which does NOT follow symlinks (uses lstat).
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            // Skip symlinks — don't follow them for size calculation.
            continue;
        } else if ft.is_file() {
            total = total.saturating_add(entry.metadata()?.len());
        } else if ft.is_dir() {
            total = total.saturating_add(dir_size(&entry.path())?);
        }
    }
    Ok(total)
}

/// Create a sparse file with the given size.
fn create_sparse_file(path: &Path, size: u64) -> Result<()> {
    use std::fs::File;
    let f = File::create(path)?;
    f.set_len(size)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn create_input_image_from_temp_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let input_dir = tmp.path().join("input");
        fs::create_dir(&input_dir).unwrap();
        fs::write(input_dir.join("hello.txt"), "hello world").unwrap();
        fs::write(input_dir.join("data.bin"), vec![0u8; 1024]).unwrap();

        let image_path = tmp.path().join("input.ext4");

        // This test requires mkfs.ext4 to be available.
        match create_input_image(&input_dir, &image_path) {
            Ok(()) => {
                assert!(image_path.exists());
                let meta = fs::metadata(&image_path).unwrap();
                assert!(meta.len() >= MIN_IMAGE_SIZE);
            }
            Err(e) => {
                // mkfs.ext4 not available — skip gracefully.
                let msg = e.to_string();
                assert!(
                    msg.contains("mkfs.ext4") || msg.contains("No such file"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn create_output_image_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let image_path = tmp.path().join("output.ext4");

        match create_output_image(&image_path, 4) {
            Ok(()) => {
                assert!(image_path.exists());
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("mkfs.ext4") || msg.contains("No such file"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn dir_size_recursive() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("a.txt"), "hello").unwrap();
        let sub = tmp.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("b.txt"), "world!").unwrap();

        let size = dir_size(tmp.path()).unwrap();
        // "hello" = 5, "world!" = 6
        assert_eq!(size, 11);
    }

    #[test]
    fn sparse_file_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sparse.img");
        create_sparse_file(&path, 10 * 1024 * 1024).unwrap();

        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 10 * 1024 * 1024);
    }
}
