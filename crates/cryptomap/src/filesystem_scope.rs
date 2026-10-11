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
    /// Open the caller's directory without following a symlink at ANY path
    /// component, including the root itself.
    ///
    /// Only the filesystem volume root ("/" or "C:\\") is opened with ambient
    /// authority. Every descendant component is opened relative to the previous
    /// directory handle using an atomic no-follow operation. This closes the
    /// check-then-open race in an ambient full-path directory open.
    ///
    /// Untrusted collectors must not choose this root; authorization belongs
    /// to the hosting process, not to a collector descriptor.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ScopeError> {
        let requested = root.as_ref();
        if requested.as_os_str().is_empty() {
            return Err(ScopeError::InvalidInput);
        }
        let absolute = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| ScopeError::Io)?
                .join(requested)
        };
        let mut anchor = PathBuf::new();
        let mut names: Vec<OsString> = Vec::new();
        for component in absolute.components() {
            match component {
                Component::Prefix(prefix) => {
                    let _ = &prefix;
                    // On Windows, UNC, device and verbatim prefixes can evade
                    // ordinary path component assumptions. Accept drive roots
                    // only; explicit network roots need a separate contract.
                    #[cfg(windows)]
                    {
                        use std::path::Prefix;
                        if !matches!(prefix.kind(), Prefix::Disk(_)) {
                            return Err(ScopeError::InvalidInput);
                        }
                    }
                    anchor.push(prefix.as_os_str());
                }
                Component::RootDir => anchor.push(component.as_os_str()),
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
        if !anchor.is_absolute() {
            return Err(ScopeError::InvalidInput);
        }
        // Ambient authority is used ONLY for a platform filesystem anchor,
        // never for the untrusted or racy requested full directory path.
        let mut dir =
            Dir::open_ambient_dir(&anchor, ambient_authority()).map_err(|_| ScopeError::Io)?;
        let mut root_path = anchor;
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

    /// Resolved display-only location of the root (not an access token).
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
