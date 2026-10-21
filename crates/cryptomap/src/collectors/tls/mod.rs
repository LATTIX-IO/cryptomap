//! B6 bounded, explicit-grant TLS observation components.
//!
//! B6.1 provides only a transport authorization plan. It does not open sockets
//! or perform cryptographic handshakes, certificate validation or discovery.

/// An inert, exact-grant and finite TLS probe plan.
pub mod probe;
