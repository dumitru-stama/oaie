//! Recursive directory traversal without external dependencies.
//!
//! Replaces the `walkdir` crate with a minimal implementation using
//! `std::fs::read_dir()`. Only the features used by OAIE are supported:
//! recursive descent, no symlink following, optional sorted output.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Maximum recursion depth to prevent stack overflow from deeply nested
/// directory trees (e.g. crafted by a malicious sandboxed process).
const MAX_DEPTH: usize = 256;

/// A single entry from a recursive directory walk.
pub struct WalkEntry {
    path: PathBuf,
    metadata: fs::Metadata,
}

impl WalkEntry {
    /// Full path of the entry.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Metadata of the entry (from `symlink_metadata`, does not follow symlinks).
    pub fn metadata(&self) -> &fs::Metadata {
        &self.metadata
    }

    /// Returns true if the entry is a regular file (not a symlink, directory, etc.).
    pub fn is_file(&self) -> bool {
        self.metadata.file_type().is_file()
    }
}

/// Recursively walk a directory tree, skipping symlinks.
///
/// - Entries are sorted by file name within each directory for deterministic output.
/// - Symlinks are never followed.
/// - The root directory itself is not included in the results.
/// - I/O errors on individual entries are collected into the result vec.
pub fn walk_dir_sorted(root: &Path) -> Vec<Result<WalkEntry, io::Error>> {
    let mut results = Vec::new();
    walk_recursive(root, &mut results, true, 0);
    results
}

/// Recursively walk a directory tree, skipping symlinks.
///
/// Same as [`walk_dir_sorted`] but without sorting — faster when order
/// doesn't matter (e.g. counting blobs in `oaie doctor`).
pub fn walk_dir(root: &Path) -> Vec<Result<WalkEntry, io::Error>> {
    let mut results = Vec::new();
    walk_recursive(root, &mut results, false, 0);
    results
}

fn walk_recursive(
    dir: &Path,
    results: &mut Vec<Result<WalkEntry, io::Error>>,
    sorted: bool,
    depth: usize,
) {
    if depth >= MAX_DEPTH {
        results.push(Err(io::Error::other(
            format!("maximum directory depth ({MAX_DEPTH}) exceeded at {}", dir.display()),
        )));
        return;
    }
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            results.push(Err(e));
            return;
        }
    };

    // Collect entries so we can optionally sort them.
    let mut entries: Vec<fs::DirEntry> = Vec::new();
    for entry in read_dir {
        match entry {
            Ok(e) => entries.push(e),
            Err(e) => results.push(Err(e)),
        }
    }

    if sorted {
        entries.sort_by_key(|e| e.file_name());
    }

    for entry in entries {
        // Use symlink_metadata to avoid following symlinks.
        let metadata = match entry.path().symlink_metadata() {
            Ok(m) => m,
            Err(e) => {
                results.push(Err(e));
                continue;
            }
        };

        let file_type = metadata.file_type();

        // Skip symlinks entirely (security: prevent symlink traversal attacks).
        if file_type.is_symlink() {
            continue;
        }

        let path = entry.path();

        if file_type.is_dir() {
            // Recurse into subdirectories before adding their entries.
            walk_recursive(&path, results, sorted, depth + 1);
        } else {
            results.push(Ok(WalkEntry { path, metadata }));
        }
    }
}
