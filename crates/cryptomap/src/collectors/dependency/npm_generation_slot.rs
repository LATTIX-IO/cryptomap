//! Capability-rooted, create-only publication of immutable recovery candidates.
//!
//! The caller supplies an already-open dedicated directory capability and two
//! simple names. Published slots are created atomically with hard links, never
//! overwritten. The host owns directory exclusivity and durable directory sync.
use super::{
    npm_generation::NpmVerifiedGeneration, npm_generation_frame::write_framed_npm_generation,
    npm_manifest::NpmReconciliationError,
};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use std::io::Write;

fn valid_slot_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 96
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// Remove a temporary candidate on both error and successful publication.
///
/// Cleanup is best-effort: a crash or failed unlink can leave an orphan staging
/// file. It cannot modify an already published hard-linked slot.
struct StagingCleanup<'a> {
    dir: &'a Dir,
    name: &'a str,
}
impl Drop for StagingCleanup<'_> {
    fn drop(&mut self) {
        let _ = self.dir.remove_file(self.name);
    }
}

/// Publish a completely serialized and file-synced generation as a new slot.
///
/// This is a create-only operation; if the slot already exists (including a
/// symlink), publication fails and leaves the existing entry unchanged.
/// The caller must provide an exclusive directory capability and two unique,
/// simple ASCII basenames (no separators, traversal, dot components or NUL).
/// A hard link exposes the fully written file in one namespace operation,
/// avoiding partial-content publication and cross-platform replace semantics.
///
/// An untrusted co-writer inside the same directory could race by replacing
/// staging entries before the hard-link operation; **do not grant writes to
/// untrusted actors in this directory**. A synced data file plus a link does
/// not guarantee the directory entry survives power failure: the host is
/// responsible for filesystem durability barriers and for advancing the
/// separate rollback-resistant trusted anchor. Never treat this as an A/C/I
/// guarantee on untrusted storage or a reusable slot-overwrite transaction.
///
/// This function does not open paths outside the supplied capability, execute
/// package commands, connect to networks, or infer actual algorithm use.
pub fn publish_immutable_npm_generation_slot(
    dir: &Dir,
    generation: &NpmVerifiedGeneration,
    staging_name: &str,
    slot_name: &str,
    max_payload_bytes: usize,
) -> Result<usize, NpmReconciliationError> {
    use NpmReconciliationError::{ResourceLimit, UnboundEvidence};
    if !valid_slot_name(staging_name) || !valid_slot_name(slot_name) || staging_name == slot_name {
        return Err(UnboundEvidence);
    }
    // Fail oversized serialization before creating even a staging entry.
    let mut frame = Vec::new();
    let total = write_framed_npm_generation(generation, &mut frame, max_payload_bytes)?;
    if total != frame.len() {
        return Err(ResourceLimit);
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true).follow(FollowSymlinks::No);
    let mut file = dir
        .open_with(staging_name, &opts)
        .map_err(|_| UnboundEvidence)?;
    let cleanup = StagingCleanup {
        dir,
        name: staging_name,
    };
    file.write_all(&frame).map_err(|_| UnboundEvidence)?;
    file.sync_all().map_err(|_| UnboundEvidence)?;
    drop(file);
    // Hard-link creation is create-only; unlike ordinary rename on Unix it
    // cannot clobber an existing slot or symlink entry.
    dir.hard_link(staging_name, dir, slot_name)
        .map_err(|_| UnboundEvidence)?;
    drop(cleanup);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_basenames_only_without_ambiguous_or_special_characters() {
        for name in [
            "", ".", "..", "../a", "a/b", "a\\b", "a.b", "a:b", " bad", "bad ", "a\n", "a\0",
        ] {
            assert!(!valid_slot_name(name), "{name:?}");
        }
        assert!(!valid_slot_name(&"a".repeat(97)));
        for name in ["A", "slot_17", "stage-1", "2026_10_12"] {
            assert!(valid_slot_name(name), "{name:?}");
        }
    }
}
