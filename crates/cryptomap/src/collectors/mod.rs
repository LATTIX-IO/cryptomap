//! Opt-in, scoped collectors. No automatic discovery or implicit I/O.
pub mod dependency;

/// Optional parser-backed explicitly authorized source evidence collectors.
#[cfg(any(feature = "rust-source", feature = "json-tls-config"))]
pub mod source;

/// Passive exact-grant public X.509 certificate file evidence.
#[cfg(feature = "certificate-files")]
pub mod certificate;
