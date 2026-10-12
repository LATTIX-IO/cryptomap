//! Bounded, strict JSON interchange for verified npm snapshot generations.
//!
//! Import always reauthorizes live source bytes, verifies persisted evidence,
//! and publishes through the store CAS. A file on disk is never a trust root.
use super::{
    npm_generation::{NpmGenerationStore, NpmVerifiedGeneration},
    npm_manifest::NpmReconciliationError,
};
use crate::{
    InventoryLimits, InventorySnapshot, SnapshotId, raw::RawLimits, scope::CollectionScope,
    strict_json::StrictJson,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    sync::Arc,
};

const FORMAT_VERSION: u32 = 1;

#[derive(Serialize)]
struct ExportBundle<'a> {
    version: u32,
    checkpoint: &'a super::npm_checkpoint::NpmProjectionCheckpoint,
    snapshot: &'a InventorySnapshot,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportBundle {
    version: u32,
    checkpoint: super::npm_checkpoint::NpmProjectionCheckpoint,
    snapshot: InventorySnapshot,
}

/// A streaming JSON sink that fails before writing beyond the caller's cap.
struct BoundedJson {
    bytes: Vec<u8>,
    max_bytes: usize,
}

impl Write for BoundedJson {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > self.max_bytes.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("generation JSON byte cap exceeded"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serialize an already verified in-memory npm generation to bounded JSON.
///
/// The file format deliberately excludes the process-local publication
/// sequence. This encodes a candidate recovery bundle, **not** a signed
/// authorization token or an assertion of current source freshness.
///
/// The writer enforces the byte ceiling during serialization; there is no
/// unbounded intermediate \`serde_json::to_vec\` allocation. Snapshot contents
/// may include sensitive dependency paths and identifiers; hosts must protect
/// stored bytes with appropriate access control.
pub fn encode_npm_generation(
    generation: &NpmVerifiedGeneration,
    max_bytes: usize,
) -> Result<Vec<u8>, NpmReconciliationError> {
    use NpmReconciliationError::ResourceLimit;
    if max_bytes == 0 {
        return Err(ResourceLimit);
    }
    let mut output = BoundedJson {
        bytes: Vec::new(),
        max_bytes,
    };
    serde_json::to_writer(
        &mut output,
        &ExportBundle {
            version: FORMAT_VERSION,
            checkpoint: generation.checkpoint(),
            snapshot: generation.snapshot(),
        },
    )
    .map_err(|_| ResourceLimit)?;
    Ok(output.bytes)
}

/// Revalidate a bounded recovery bundle before atomically publishing it.
///
/// Strict JSON decoding rejects duplicate keys at any nesting level and the
/// versioned envelope forbids unknown fields. A recovered checkpoint and
/// inventory are never trusted solely because their saved checksums match:
/// \`NpmGenerationStore::publish\` reopens both explicitly granted source files,
/// verifies their hashes, complete collector provenance and canonical graph,
/// and then applies the caller's expected-sequence compare-and-swap.
///
/// The caller supplies a store pre-bound to its tenant/source pair and is
/// responsible for crash-consistent external file writes and anti-rollback
/// guarantees across process restarts. This operation does not open any
/// arbitrary bundle path, execute scripts, contact networks or auto-recollect.
pub fn restore_npm_generation(
    store: &NpmGenerationStore,
    bytes: &[u8],
    scope: &CollectionScope,
    expected_sequence: Option<u64>,
    max_bytes: usize,
    raw_limits: RawLimits,
    inventory_limits: InventoryLimits,
) -> Result<Arc<NpmVerifiedGeneration>, NpmReconciliationError> {
    let bundle = decode_recovery_bundle(bytes, max_bytes)?;
    store.publish(
        bundle.checkpoint,
        bundle.snapshot,
        scope,
        expected_sequence,
        raw_limits,
        inventory_limits,
    )
}

/// A host-trusted recovery pin obtained independently of the candidate bundle.
///
/// The caller must protect the anchor against replacement and rollback (for
/// example, using trusted persistent storage). A matching SHA-256 pin rejects
/// alternate valid inventory generations, but it is not authentication if
/// attackers can rewrite the anchor. Do not derive this value from the
/// untrusted recovery bytes being verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmTrustedRecoveryAnchor {
    snapshot_id: SnapshotId,
    checkpoint_fingerprint: String,
}

impl NpmTrustedRecoveryAnchor {
    /// Bind a trusted snapshot identity to its exact checkpoint fingerprint.
    ///
    /// The fingerprint must be a lowercase 64-hex-digit SHA-256 value.
    /// Construction validates syntax, not provenance or trust.
    pub fn new(
        snapshot_id: SnapshotId,
        checkpoint_fingerprint: impl Into<String>,
    ) -> Result<Self, NpmReconciliationError> {
        let fingerprint = checkpoint_fingerprint.into();
        let Some(hex) = fingerprint.strip_prefix("sha256:") else {
            return Err(NpmReconciliationError::UnboundEvidence);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(NpmReconciliationError::UnboundEvidence);
        }
        Ok(Self {
            snapshot_id,
            checkpoint_fingerprint: fingerprint,
        })
    }

    /// The expected canonical snapshot identity.
    pub fn snapshot_id(&self) -> &SnapshotId {
        &self.snapshot_id
    }

    /// The expected source-bound checkpoint fingerprint.
    pub fn checkpoint_fingerprint(&self) -> &str {
        &self.checkpoint_fingerprint
    }
}

fn decode_recovery_bundle(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<ImportBundle, NpmReconciliationError> {
    use NpmReconciliationError::{ResourceLimit, UnboundEvidence};
    if max_bytes == 0 || bytes.len() > max_bytes {
        return Err(ResourceLimit);
    }
    let strict: StrictJson = serde_json::from_slice(bytes).map_err(|_| UnboundEvidence)?;
    let bundle: ImportBundle = serde_json::from_value(strict.0).map_err(|_| UnboundEvidence)?;
    if bundle.version != FORMAT_VERSION {
        return Err(UnboundEvidence);
    }
    Ok(bundle)
}

/// Recover only the exact canonical generation pinned by an independent host.
///
/// This strengthens recovery against stale-but-otherwise-valid bundle replay:
/// the candidate's immutable snapshot ID and checkpoint fingerprint must both
/// match the trusted anchor, *before* any source reauthorization or publication.
/// The store then performs its ordinary exact-grant, canonical graph/evidence,
/// source-freshness and generation compare-and-swap validation. A mismatch never
/// changes the current generation.
///
/// The trusted anchor must be supplied by a host-owned rollback-resistant
/// authority. This function cannot establish the authenticity or monotonicity
/// of an anchor loaded from the same untrusted bundle or storage location.
pub fn restore_npm_generation_pinned(
    store: &NpmGenerationStore,
    bytes: &[u8],
    trusted: &NpmTrustedRecoveryAnchor,
    scope: &CollectionScope,
    expected_sequence: Option<u64>,
    max_bytes: usize,
    raw_limits: RawLimits,
    inventory_limits: InventoryLimits,
) -> Result<Arc<NpmVerifiedGeneration>, NpmReconciliationError> {
    let bundle = decode_recovery_bundle(bytes, max_bytes)?;
    if &bundle.snapshot.id != trusted.snapshot_id()
        || &bundle.checkpoint.snapshot_id != trusted.snapshot_id()
        || bundle.checkpoint.fingerprint != trusted.checkpoint_fingerprint()
    {
        return Err(NpmReconciliationError::UnboundEvidence);
    }
    store.publish(
        bundle.checkpoint,
        bundle.snapshot,
        scope,
        expected_sequence,
        raw_limits,
        inventory_limits,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bounded_json_writer_fails_before_limit() {
        let mut sink = BoundedJson {
            bytes: Vec::new(),
            max_bytes: 3,
        };
        assert_eq!(sink.write(b"ab").unwrap(), 2);
        assert!(sink.write(b"cd").is_err());
        assert_eq!(sink.bytes, b"ab");
        assert_eq!(sink.write(b"c").unwrap(), 1);
        assert!(sink.write(b"d").is_err());
        assert_eq!(sink.bytes, b"abc");
    }
}
