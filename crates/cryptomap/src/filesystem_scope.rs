//! Capability-rooted, read-only file access for explicitly authorized source files.
//!
//! All I/O occurs relative to an already-open `cap_std::fs::Dir` handle.
//! Reject symlink/junction indirection by default, including links *inside*
//! the root; the capability implementation also prevents escape under races.
use crate::scope::ScopeError;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{ambient_authority, fs::{Dir, OpenOptions}};
use std::{
    io::Read,
    path::{Component, Path, PathBuf},
};

/// A read-only capability to one directory explicitly granted by the caller.
#[derive(Debug)]
pub struct FileRoot {
    dir: Dir,
    root: PathBuf,
}

impl FileRoot {
    /// Open exactly the caller-authorized directory using ambient authority once.
    ///
    /// The caller is the authority: never derive roots from untrusted collector
    /// options, repository contents, or an imported inventory.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ScopeError> {
        let root = root.as_ref();
        let meta = std::fs::symlink_metadata(root).map_err(|_| ScopeError::Io)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(ScopeError::InvalidInput);
        }
        let dir = Dir::open_ambient_dir(root, ambient_authority())
            .map_err(|_| ScopeError::Io)?;
        let root = std::fs::canonicalize(root).map_err(|_| ScopeError::Io)?;
        Ok(Self { dir, root })
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
                let kind = self.dir.symlink_metadata(&prefix)
                    .map_err(|_| ScopeError::Io)?.file_type();
                if kind.is_symlink() {
                    return Err(ScopeError::OutOfScope);
                }
            }
        }
        // cap-std canonicalization is relative to this Dir, even when the
        // operating system encounters symlinks or Windows reparse points.
        // Reject redirection inside root as well as escape attempts.
        let resolved = self.dir.canonicalize(path).map_err(|_| ScopeError::OutOfScope)?;
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

    /// Open an anchored file handle after a fresh path/symlink check.
    ///
    /// cap-std uses platform capability-based resolution to prevent
    /// filesystem escape if another process races a path component.
    pub fn open_read(&self) -> Result<cap_std::fs::File, ScopeError> {
        self.root.inspect(&self.relative)?;
        // Open each parent without following symlinks. The final component is
        // also opened O_NOFOLLOW / Windows reparse-safe by cap-fs-ext.
        // This protects the *exact authorized file* even if an attacker swaps
        // a directory entry between our validation and actual OS open.
        let mut dir = self.root.dir.open_dir(".").map_err(|_| ScopeError::Io)?;
        if let Some(parent) = self.relative.parent() {
            for component in parent.components() {
                let Component::Normal(name) = component else {
                    return Err(ScopeError::OutOfScope);
                };
                dir = dir.open_dir_nofollow(name).map_err(|_| ScopeError::OutOfScope)?;
            }
        }
        let basename = self.relative.file_name().ok_or(ScopeError::InvalidInput)?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        dir.open_with(basename, &options).map_err(|_| ScopeError::OutOfScope)
    }

    /// Read at most the approved bytes, returning ResourceLimit for overflow.
    pub fn read_bounded(&self) -> Result<Vec<u8>, ScopeError> {
        let file = self.open_read()?;
        let cap = u64::try_from(self.max_bytes)
            .map_err(|_| ScopeError::InvalidInput)?;
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
            || text.as_bytes().len() > 255
            || (!cfg!(windows) && text.contains('\\'))
        {
            return Err(ScopeError::InvalidInput);
        }
    }
    Ok(())
}
