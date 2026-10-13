//! Opt-in, scoped collectors. No automatic discovery or implicit I/O.
pub mod dependency;

/// Optional parser-backed explicitly authorized source evidence collectors.
#[cfg(feature = "rust-source")]
pub mod source;
