//! Bounded length- and digest-framed npm recovery candidates.
//!
//! Framing detects truncation, trailing bytes and transport corruption.
//! SHA-256 is unkeyed: it is not authentication, authorization or anti-rollback.
use super::{
    npm_generation::{NpmGenerationStore, NpmVerifiedGeneration},
    npm_generation_codec::{
        NpmRecoveryLimits, NpmTrustedRecoveryAnchor, encode_npm_generation,
        restore_npm_generation_pinned,
    },
    npm_manifest::NpmReconciliationError,
};
use crate::scope::CollectionScope;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    sync::Arc,
};

const MAGIC: &[u8; 8] = b"CMNPGEN1";
const HEADER_LEN: usize = 8 + 8 + 32;

/// Write one complete candidate with magic, big-endian length, SHA-256 and body.
///
/// Complete bounded serialization occurs before writing. A sink failure may
/// still leave partial bytes; the host owns durable staging/atomic commit.
pub fn write_framed_npm_generation<W: Write>(
    generation: &NpmVerifiedGeneration,
    writer: &mut W,
    max_payload_bytes: usize,
) -> Result<usize, NpmReconciliationError> {
    let body = encode_npm_generation(generation, max_payload_bytes)?;
    let len = u64::try_from(body.len()).map_err(|_| NpmReconciliationError::ResourceLimit)?;
    let total = HEADER_LEN
        .checked_add(body.len())
        .ok_or(NpmReconciliationError::ResourceLimit)?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&Sha256::digest(&body));
    frame.extend_from_slice(&body);
    writer
        .write_all(&frame)
        .map_err(|_| NpmReconciliationError::UnboundEvidence)?;
    Ok(total)
}

/// Read exactly one framed candidate, rejecting truncated, oversized, tampered,
/// unknown-version and trailing-byte streams before downstream JSON decoding.
///
/// This reads a single byte after the declared payload to detect trailing
/// content. A blocking reader needs a host-supplied deadline/cancellation.
pub fn read_framed_npm_generation<R: Read>(
    reader: &mut R,
    max_payload_bytes: usize,
) -> Result<Vec<u8>, NpmReconciliationError> {
    use NpmReconciliationError::{ResourceLimit, UnboundEvidence};
    if max_payload_bytes == 0 {
        return Err(ResourceLimit);
    }
    let mut header = [0u8; HEADER_LEN];
    reader
        .read_exact(&mut header)
        .map_err(|_| UnboundEvidence)?;
    if &header[..MAGIC.len()] != MAGIC {
        return Err(UnboundEvidence);
    }
    let len = u64::from_be_bytes(header[8..16].try_into().map_err(|_| UnboundEvidence)?);
    if len == 0 || len > u64::try_from(max_payload_bytes).map_err(|_| ResourceLimit)? {
        return Err(ResourceLimit);
    }
    let size = usize::try_from(len).map_err(|_| ResourceLimit)?;
    let mut body = vec![0u8; size];
    reader.read_exact(&mut body).map_err(|_| UnboundEvidence)?;
    let hash = Sha256::digest(&body);
    if hash.as_slice() != &header[16..HEADER_LEN] {
        return Err(UnboundEvidence);
    }
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing).map_err(|_| UnboundEvidence)? != 0 {
        return Err(UnboundEvidence);
    }
    Ok(body)
}

/// Import a complete integrity-framed candidate through existing host-pinned
/// live-source/evidence verification and atomic generation publication.
pub fn restore_framed_npm_generation_pinned<R: Read>(
    store: &NpmGenerationStore,
    reader: &mut R,
    anchor: &NpmTrustedRecoveryAnchor,
    scope: &CollectionScope,
    expected_sequence: Option<u64>,
    limits: NpmRecoveryLimits,
) -> Result<Arc<NpmVerifiedGeneration>, NpmReconciliationError> {
    let body = read_framed_npm_generation(reader, limits.max_bytes)?;
    restore_npm_generation_pinned(store, &body, anchor, scope, expected_sequence, limits)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        out.extend_from_slice(&Sha256::digest(payload));
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn framing_detects_truncation_tampering_unknown_magic_and_trailing_bytes() {
        let input = frame(b"{}");
        assert_eq!(
            read_framed_npm_generation(&mut Cursor::new(&input), 2).unwrap(),
            b"{}"
        );
        assert_eq!(
            read_framed_npm_generation(&mut Cursor::new(&input), 1),
            Err(NpmReconciliationError::ResourceLimit)
        );
        assert_eq!(
            read_framed_npm_generation(&mut Cursor::new(&input), 0),
            Err(NpmReconciliationError::ResourceLimit)
        );
        for i in 0..input.len() {
            assert!(read_framed_npm_generation(&mut Cursor::new(&input[..i]), 10).is_err());
        }
        let mut modified = input.clone();
        *modified.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            read_framed_npm_generation(&mut Cursor::new(modified), 10),
            Err(NpmReconciliationError::UnboundEvidence)
        );
        let mut modified = input.clone();
        modified[0] = b'X';
        assert_eq!(
            read_framed_npm_generation(&mut Cursor::new(modified), 10),
            Err(NpmReconciliationError::UnboundEvidence)
        );
        let mut modified = input.clone();
        modified.push(b' ');
        assert_eq!(
            read_framed_npm_generation(&mut Cursor::new(modified), 10),
            Err(NpmReconciliationError::UnboundEvidence)
        );
        let mut modified = input.clone();
        modified[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            read_framed_npm_generation(&mut Cursor::new(modified), 10),
            Err(NpmReconciliationError::ResourceLimit)
        );
        let mut modified = input.clone();
        modified[8..16].copy_from_slice(&0_u64.to_be_bytes());
        assert_eq!(
            read_framed_npm_generation(&mut Cursor::new(modified), 10),
            Err(NpmReconciliationError::ResourceLimit)
        );
    }

    struct BrokenReader;
    impl Read for BrokenReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected failure"))
        }
    }

    #[test]
    fn failed_stream_reads_fail_closed() {
        assert_eq!(
            read_framed_npm_generation(&mut BrokenReader, 100),
            Err(NpmReconciliationError::UnboundEvidence)
        );
    }
}
