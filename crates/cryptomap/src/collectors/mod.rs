//! Opt-in, scoped collectors. No automatic discovery or implicit I/O.
pub mod dependency;

/// Optional parser-backed explicitly authorized source evidence collectors.
#[cfg(any(feature = "rust-source", feature = "json-tls-config"))]
pub mod source;

/// Passive exact-grant public X.509 certificate file evidence.
#[cfg(feature = "certificate-files")]
pub mod certificate;

/// B5.3 portable bounded certificate-store evidence collector (provider injected).
#[cfg(feature = "certificate-store-grants")]
pub mod certificate_store;

/// B6 opt-in exact-grant TLS probe planning; B6.1 does not perform I/O.
#[cfg(feature = "tls-probe")]
pub mod tls;
