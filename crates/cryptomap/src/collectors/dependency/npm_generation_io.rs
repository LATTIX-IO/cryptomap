//! Explicit host-supplied bounded stream adapters for npm recovery candidates.
//!
//! The host selects the reader and writer. This module never opens paths,
//! discovers files, executes package scripts, or commits persistent storage.
use super::{
    npm_generation::{NpmGenerationStore, NpmVerifiedGeneration},
    npm_generation_codec::{
        NpmRecoveryLimits, NpmTrustedRecoveryAnchor, encode_npm_generation,
        restore_npm_generation_pinned,
    },
    npm_manifest::NpmReconciliationError,
};
use crate::scope::CollectionScope;
use std::{
    io::{Read, Write},
    sync::Arc,
};

/// Read an untrusted recovery bundle from a host-selected stream with a strict
/// pre-decode byte ceiling.
///
/// At most `max_bytes + 1` bytes are read. The extra byte distinguishes an
/// exact-limit candidate from an oversized one without trusting a size hint.
/// Zero or unrepresentable limits, oversized inputs and truncated/failed I/O
/// are rejected; malformed but bounded bytes are rejected by the downstream
/// strict recovery decoder. No filesystem path or network authority is gained.
///
/// A hostile reader that blocks forever requires a host-enforced timeout:
/// the synchronous standard `Read` trait has no cancellation or deadline.
pub fn read_bounded_npm_generation<R: Read>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Vec<u8>, NpmReconciliationError> {
    use NpmReconciliationError::{ResourceLimit, UnboundEvidence};
    if max_bytes == 0 {
        return Err(ResourceLimit);
    }
    let count = max_bytes.checked_add(1).ok_or(ResourceLimit)?;
    let count = u64::try_from(count).map_err(|_| ResourceLimit)?;
    let mut result = Vec::new();
    reader
        .take(count)
        .read_to_end(&mut result)
        .map_err(|_| UnboundEvidence)?;
    if result.len() > max_bytes {
        return Err(ResourceLimit);
    }
    Ok(result)
}

/// Write a generation candidate to a host-selected sink, respecting the same
/// bounded JSON encoding as `encode_npm_generation`.
///
/// Serialization completes within the ceiling *before the first sink write*.
/// Once writing begins, an I/O failure can leave partial bytes in that sink.
/// The host must stage, sync, and atomically commit or discard writes as needed;
/// a successful write is not durable, atomic or authenticated by this method.
/// No file path is accepted or opened here.
pub fn write_bounded_npm_generation<W: Write>(
    generation: &NpmVerifiedGeneration,
    writer: &mut W,
    max_bytes: usize,
) -> Result<usize, NpmReconciliationError> {
    let bytes = encode_npm_generation(generation, max_bytes)?;
    writer
        .write_all(&bytes)
        .map_err(|_| NpmReconciliationError::UnboundEvidence)?;
    Ok(bytes.len())
}

/// Load and publish a bounded recovery candidate from a host-selected reader
/// only if its independently supplied trusted generation anchor, authorized
/// source bytes, complete persisted evidence and canonical graph all verify.
///
/// Publication preserves the store's compare-and-swap semantics. Over-limit,
/// malformed and failed stream reads never modify the generation store. This
/// API does not make a trusted anchor rollback-resistant or authorize a path.
pub fn restore_npm_generation_pinned_from_reader<R: Read>(
    store: &NpmGenerationStore,
    reader: &mut R,
    trusted: &NpmTrustedRecoveryAnchor,
    scope: &CollectionScope,
    expected_sequence: Option<u64>,
    limits: NpmRecoveryLimits,
) -> Result<Arc<NpmVerifiedGeneration>, NpmReconciliationError> {
    let bytes = read_bounded_npm_generation(reader, limits.max_bytes)?;
    restore_npm_generation_pinned(store, &bytes, trusted, scope, expected_sequence, limits)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    #[test]
    fn bounded_stream_reader_accepts_exact_limit_and_rejects_overflow_without_overreading() {
        let mut exact = Cursor::new(b"abcd");
        assert_eq!(read_bounded_npm_generation(&mut exact, 4).unwrap(), b"abcd");
        assert_eq!(exact.position(), 4);

        let mut too_large = Cursor::new(b"abcdef");
        assert_eq!(
            read_bounded_npm_generation(&mut too_large, 4),
            Err(NpmReconciliationError::ResourceLimit)
        );
        assert_eq!(too_large.position(), 5);
        assert_eq!(
            read_bounded_npm_generation(&mut Cursor::new(b"a"), 0),
            Err(NpmReconciliationError::ResourceLimit)
        );
        assert_eq!(
            read_bounded_npm_generation(&mut Cursor::new(b""), 0),
            Err(NpmReconciliationError::ResourceLimit)
        );
        assert_eq!(
            read_bounded_npm_generation(&mut Cursor::new(b"a"), usize::MAX),
            Err(NpmReconciliationError::ResourceLimit)
        );
    }

    struct ErrorAfterFirstRead(bool);

    impl Read for ErrorAfterFirstRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                Err(io::Error::other("simulated failed storage read"))
            } else {
                self.0 = true;
                buf[0] = b'{';
                Ok(1)
            }
        }
    }

    #[test]
    fn bounded_stream_reader_rejects_io_errors_and_does_not_return_partial_bytes() {
        assert_eq!(
            read_bounded_npm_generation(&mut ErrorAfterFirstRead(false), 256),
            Err(NpmReconciliationError::UnboundEvidence)
        );
    }
}
