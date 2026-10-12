//! Capability-rooted, read-only file access for explicitly authorized source files.
//!
//! All I/O occurs relative to an already-open `cap_std::fs::Dir` handle.
//! Reject symlink/junction indirection by default, including links *inside*
//! the root; the capability implementation also prevents escape under races.
use crate::scope::ScopeError;
#[cfg(unix)]
use cap_fs_ext::OpenOptionsSyncExt;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

/// A read-only capability to one directory explicitly granted by the caller.
#[derive(Debug)]
pub struct FileRoot {
    dir: Dir,
    root: PathBuf,
}

impl FileRoot {
    /// Open a host-authorized directory with no-follow descent at each component.
    ///
    /// Absolute paths descend from the filesystem volume root. Relative paths
    /// descend from an *opened current-directory handle*, never from a pathname
    /// reconstructed using `current_dir()`. That distinction prevents an
    /// attacker replacing the CWD's former pathname between lookup and open.
    ///
    /// Untrusted collectors must not choose this root; the host grants access.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ScopeError> {
        let requested = root.as_ref();
        if requested.as_os_str().is_empty() {
            return Err(ScopeError::InvalidInput);
        }
        let is_absolute = requested.is_absolute();
        let mut anchor = PathBuf::new();
        let mut names: Vec<OsString> = Vec::new();
        for component in requested.components() {
            match component {
                Component::Prefix(prefix) => {
                    if !is_absolute {
                        return Err(ScopeError::InvalidInput);
                    }
                    #[cfg(windows)]
                    {
                        use std::path::Prefix;
                        if !matches!(prefix.kind(), Prefix::Disk(_)) {
                            return Err(ScopeError::InvalidInput);
                        }
                    }
                    anchor.push(prefix.as_os_str());
                }
                Component::RootDir => {
                    if !is_absolute {
                        return Err(ScopeError::InvalidInput);
                    }
                    anchor.push(component.as_os_str());
                }
                Component::Normal(part) => {
                    if part.to_string_lossy().contains(['*', '?', '\0', ':']) {
                        return Err(ScopeError::InvalidInput);
                    }
                    names.push(part.to_os_string());
                }
                Component::CurDir => {}
                Component::ParentDir => return Err(ScopeError::OutOfScope),
            }
        }
        // Opening "." is the only ambient operation on a relative request.
        // From then on, all operations are confined to that specific handle.
        let (dir, root_path) = if is_absolute {
            if !anchor.is_absolute() {
                return Err(ScopeError::InvalidInput);
            }
            let dir =
                Dir::open_ambient_dir(&anchor, ambient_authority()).map_err(|_| ScopeError::Io)?;
            (dir, anchor)
        } else {
            let dir =
                Dir::open_ambient_dir(".", ambient_authority()).map_err(|_| ScopeError::Io)?;
            // A relative display path is intentionally NOT a reconstructed
            // absolute path, and must never be used as an authority token.
            (dir, PathBuf::from("."))
        };
        Self::descend(dir, root_path, names)
    }

    // The root is always built using opened directory handles, including the
    // relative-root case. Kept separate to exercise directory replacement
    // deterministically without a timing-dependent concurrency test.
    fn descend(
        mut dir: Dir,
        mut root_path: PathBuf,
        names: Vec<OsString>,
    ) -> Result<Self, ScopeError> {
        for component in names {
            dir = dir
                .open_dir_nofollow(&component)
                .map_err(|_| ScopeError::OutOfScope)?;
            root_path.push(component);
        }
        Ok(Self {
            dir,
            root: root_path,
        })
    }

    /// Display-only location of the root (relative if originally relative).\n    ///\n    /// This path is not an access token and must not be reopened for I/O.
    pub fn root_path(&self) -> &Path {
        &self.root
    }

    /// Authorize one existing relative file; no wildcards, traversal, or
    /// symlinks (including Windows junctions/reparse redirects) are permitted.
    pub fn authorize<'a>(
        &'a self,
        relative: impl AsRef<Path>,
        max_bytes: usize,
    ) -> Result<AuthorizedFile<'a>, ScopeError> {
        let path = relative.as_ref();
        if max_bytes == 0 || max_bytes > 64 * 1024 * 1024 {
            return Err(ScopeError::InvalidInput);
        }
        validate_relative(path)?;
        self.inspect(path)?;
        Ok(AuthorizedFile {
            root: self,
            relative: path.to_path_buf(),
            max_bytes,
        })
    }

    fn inspect(&self, path: &Path) -> Result<(), ScopeError> {
        validate_relative(path)?;
        let mut prefix = PathBuf::new();
        for component in path.components() {
            if let Component::Normal(part) = component {
                prefix.push(part);
                let kind = self
                    .dir
                    .symlink_metadata(&prefix)
                    .map_err(|_| ScopeError::Io)?
                    .file_type();
                if kind.is_symlink() {
                    return Err(ScopeError::OutOfScope);
                }
            }
        }
        // cap-std canonicalization is relative to this Dir, even when the
        // operating system encounters symlinks or Windows reparse points.
        // Reject redirection inside root as well as escape attempts.
        let resolved = self
            .dir
            .canonicalize(path)
            .map_err(|_| ScopeError::OutOfScope)?;
        if resolved != path {
            return Err(ScopeError::OutOfScope);
        }
        if !self.dir.is_file(path) {
            return Err(ScopeError::InvalidInput);
        }
        Ok(())
    }
}

/// A checked read capability for one file; does not expose an ambient path API.
#[derive(Debug)]
pub struct AuthorizedFile<'a> {
    root: &'a FileRoot,
    relative: PathBuf,
    max_bytes: usize,
}

impl AuthorizedFile<'_> {
    /// Return the approved relative filename for diagnostics only.
    pub fn relative(&self) -> &Path {
        &self.relative
    }

    // Keep the bare file handle private. Returning an unrestricted File
    // would allow callers to bypass the max_bytes budget after authorization.
    fn open_handle(&self) -> Result<cap_std::fs::File, ScopeError> {
        self.root.inspect(&self.relative)?;
        let mut dir = self.root.dir.open_dir(".").map_err(|_| ScopeError::Io)?;
        if let Some(parent) = self.relative.parent() {
            for component in parent.components() {
                let Component::Normal(name) = component else {
                    return Err(ScopeError::OutOfScope);
                };
                dir = dir
                    .open_dir_nofollow(name)
                    .map_err(|_| ScopeError::OutOfScope)?;
            }
        }
        let basename = self.relative.file_name().ok_or(ScopeError::InvalidInput)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        // On Unix, opening a FIFO for reading can hang BEFORE a post-open
        // type check. Nonblocking open ensures it cannot stall the collector.
        #[cfg(unix)]
        options.nonblock(true);
        let file = dir
            .open_with(basename, &options)
            .map_err(|_| ScopeError::OutOfScope)?;
        // Validate the OPENED HANDLE, not the mutable directory entry.
        // This also rejects FIFOs, Unix sockets and devices after a swap.
        let meta = file.metadata().map_err(|_| ScopeError::Io)?;
        if !meta.is_file() {
            return Err(ScopeError::InvalidInput);
        }
        if meta.len() > self.max_bytes as u64 {
            return Err(ScopeError::ResourceLimit);
        }
        Ok(file)
    }

    /// Open a read-only capability with an enforced maximum read budget.
    ///
    /// The returned reader does not expose the inner file handle.
    /// `read_bounded` additionally detects content that exceeds the budget.
    pub fn open_read(&self) -> Result<AuthorizedReader, ScopeError> {
        Ok(AuthorizedReader {
            file: self.open_handle()?,
            remaining: self.max_bytes as u64,
        })
    }

    /// SHA-256 of an exact authorized source file with a caller-specific byte
    /// budget that may be tighter than the host's file grant.
    ///
    /// Hashes in fixed-size buffers and reads one byte beyond the smaller
    /// ceiling to detect overflow, even if the file grows during inspection.
    /// Does not expose an unrestricted file handle or allocate file-sized data.
    pub fn sha256_bounded(&self, max_bytes: usize) -> Result<(String, usize), ScopeError> {
        let mut file = self.open_handle()?;
        let ceiling = self.max_bytes.min(max_bytes) as u64;
        let mut digest = Sha256::new();
        let mut observed = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let remaining = ceiling.saturating_sub(observed).saturating_add(1);
            let chunk = buffer
                .len()
                .min(usize::try_from(remaining).unwrap_or(buffer.len()));
            let n = file
                .read(&mut buffer[..chunk])
                .map_err(|_| ScopeError::Io)?;
            if n == 0 {
                break;
            }
            observed = observed
                .checked_add(n as u64)
                .ok_or(ScopeError::ResourceLimit)?;
            if observed > ceiling {
                return Err(ScopeError::ResourceLimit);
            }
            digest.update(&buffer[..n]);
        }
        let count = usize::try_from(observed).map_err(|_| ScopeError::ResourceLimit)?;
        Ok((format!("{:x}", digest.finalize()), count))
    }

    /// Read at most the approved bytes, returning ResourceLimit for overflow.
    pub fn read_bounded(&self) -> Result<Vec<u8>, ScopeError> {
        let file = self.open_handle()?;
        let cap = u64::try_from(self.max_bytes).map_err(|_| ScopeError::InvalidInput)?;
        let mut data = Vec::new();
        file.take(cap.saturating_add(1))
            .read_to_end(&mut data)
            .map_err(|_| ScopeError::Io)?;
        if data.len() > self.max_bytes {
            return Err(ScopeError::ResourceLimit);
        }
        Ok(data)
    }
}

/// Opaque bounded file reader that never exposes its underlying file handle.
#[derive(Debug)]
pub struct AuthorizedReader {
    file: cap_std::fs::File,
    remaining: u64,
}

impl Read for AuthorizedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let maximum = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let len = buf.len().min(maximum);
        let count = self.file.read(&mut buf[..len])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}

/// Validate a strict relative path with one or more named components.
pub fn validate_relative(path: &Path) -> Result<(), ScopeError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(ScopeError::InvalidInput);
    }
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(ScopeError::OutOfScope);
        };
        let text = part.to_string_lossy();
        if text.is_empty()
            || text.contains(['*', '?', '\0', ':'])
            || text.len() > 255
            || (!cfg!(windows) && text.contains('\\'))
        {
            return Err(ScopeError::InvalidInput);
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod relative_root_tests {
    #![allow(clippy::unwrap_used)]
    use super::{FileRoot, OsString};
    use cap_std::{ambient_authority, fs::Dir};
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn opened_cwd_handle_survives_rename_and_path_replacement() {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let fixture = std::env::temp_dir().join(format!(
            "cryptomap-cwd-anchor-{}-{unique}",
            std::process::id()
        ));
        let active = fixture.join("active");
        let moved = fixture.join("moved");
        fs::create_dir_all(active.join("inside")).unwrap();
        fs::write(active.join("inside").join("proof.txt"), b"authorized").unwrap();

        let cwd_handle = Dir::open_ambient_dir(&active, ambient_authority()).unwrap();
        fs::rename(&active, &moved).unwrap();
        fs::create_dir_all(active.join("inside")).unwrap();
        fs::write(active.join("inside").join("proof.txt"), b"substituted").unwrap();

        // The security property does not depend on winning a scheduling race:
        // the directory name is replaced AFTER acquiring its handle but BEFORE
        // descending into "inside". Path-based descent would read "substituted".
        let root =
            FileRoot::descend(cwd_handle, ".".into(), vec![OsString::from("inside")]).unwrap();
        assert_eq!(
            root.authorize("proof.txt", 64)
                .unwrap()
                .read_bounded()
                .unwrap(),
            b"authorized"
        );
        fs::remove_dir_all(&fixture).unwrap();
    }
}
