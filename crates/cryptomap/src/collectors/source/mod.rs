//! Explicit file-scoped source syntax evidence, never runtime execution proof.
#[cfg(feature = "rust-source")]
pub mod rust;

/// Opt-in bounded JSON TLS configuration file evidence.
#[cfg(feature = "json-tls-config")]
pub mod config_json;
