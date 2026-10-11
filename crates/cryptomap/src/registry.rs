//! Versioned, deterministic exact identifier resolution for cryptography.
//!
//! Registry resolution never implies use, cryptographic strength or compliance.
//! Unknown values are explicitly retained for later evidence reconciliation.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Increment when the built-in mapping semantics or contents change.
pub const REGISTRY_VERSION: &str = "1.0.0";
/// Upper bound for caller-supplied identifiers and namespace strings.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// Source-specific identifier namespace. Identical spelling across different
/// namespaces is never treated as an alias without explicit registration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Namespace {
    /// IANA TLS cipher suite numeric code or official name.
    TlsCipherSuite,
    /// IANA TLS supported group numeric code or official name.
    TlsGroup,
    /// X.509 algorithm object identifier, using dotted decimal form.
    X509Oid,
    /// Names used by OpenSSL EVP APIs.
    OpenSsl,
    /// SSH protocol algorithm names per the SSH registries.
    Ssh,
    /// Vendor-specific extension requiring explicit ownership.
    Extension(String),
}

/// Cryptographic operation or protocol profile namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// TLS cipher suite profile, not a single underlying primitive.
    CipherSuite,
    /// TLS key exchange named group.
    Group,
    /// Public-key or key encoding identifier.
    Key,
    /// Signature scheme including padding/hash when specified.
    Signature,
    /// Symmetric encryption including mode/size where specified.
    Encryption,
    /// Digest/hash function.
    Hash,
    /// Key derivation mechanism.
    Kdf,
    /// Protocol-level identifier.
    Protocol,
}

/// Registry errors are typed and omit untrusted identifiers from diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// Identifier, namespace or canonical descriptor violates input bounds.
    InvalidInput,
    /// Registration attempts to shadow or redefine an exact existing key.
    Collision,
    /// Canonical identifier is malformed or missing.
    InvalidCanonical,
    /// Registry serialization could not be encoded.
    EncodingFailure,
}

/// Exact normalized resolution, with immutable raw provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resolution {
    /// Exact documented mapping in the registry.
    Known {
        /// Exact canonical profile identifier, never just family alone.
        canonical: String,
        /// Crypto family (not evidence of actual deployment/use).
        family: String,
        /// Stable mapping provenance key.
        rule: String,
        /// Registry semantic version.
        registry_version: String,
        /// Original, unmodified input.
        raw: String,
    },
    /// No mapping is defined in this namespace and kind.
    Unknown {
        /// Original identifier preserved without guessing.
        raw: String,
        /// Registry version used for lookup.
        registry_version: String,
    },
}

/// Source-attested entry for a precise, exact alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mapping {
    /// Namespace of the incoming alias.
    pub namespace: Namespace,
    /// Operation or protocol domain.
    pub kind: Kind,
    /// Exact case-sensitive input spelling.
    pub alias: String,
    /// Canonical identifier with explicit cryptographic profile.
    pub canonical: String,
    /// Family classification (never compliance or security evaluation).
    pub family: String,
    /// Stable rule name.
    pub rule: String,
    /// Standards document or authoritative registry reference.
    pub source: String,
}

/// Immutable-in-use registry with explicit validated extension insertion.
#[derive(Debug, Clone)]
pub struct Registry {
    entries: BTreeMap<(Namespace, Kind, String), Mapping>,
}

fn valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

impl Default for Registry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Registry {
    /// Start from an empty registry for fixtures and controlled extensions.
    pub fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Add one exact alias, refusing collisions instead of replacing mappings.
    pub fn register(&mut self, entry: Mapping) -> Result<(), RegistryError> {
        if !valid(&entry.alias)
            || !valid(&entry.canonical)
            || !valid(&entry.family)
            || !valid(&entry.rule)
            || !valid(&entry.source)
            || matches!(&entry.namespace, Namespace::Extension(owner) if !valid(owner))
        {
            return Err(RegistryError::InvalidInput);
        }
        let key = (
            entry.namespace.clone(),
            entry.kind.clone(),
            entry.alias.clone(),
        );
        if self.entries.contains_key(&key) {
            return Err(RegistryError::Collision);
        }
        self.entries.insert(key, entry);
        Ok(())
    }

    /// Lookup exact input spelling only, without normalization by similarity.
    pub fn resolve(
        &self,
        namespace: &Namespace,
        kind: &Kind,
        raw: &str,
    ) -> Result<Resolution, RegistryError> {
        if !valid(raw) || matches!(namespace, Namespace::Extension(owner) if !valid(owner)) {
            return Err(RegistryError::InvalidInput);
        }
        let version = REGISTRY_VERSION.to_owned();
        match self
            .entries
            .get(&(namespace.clone(), kind.clone(), raw.to_owned()))
        {
            Some(m) => Ok(Resolution::Known {
                canonical: m.canonical.clone(),
                family: m.family.clone(),
                rule: m.rule.clone(),
                registry_version: version,
                raw: raw.to_owned(),
            }),
            None => Ok(Resolution::Unknown {
                raw: raw.to_owned(),
                registry_version: version,
            }),
        }
    }

    /// Stable SHA-256 digest over semantic version and sorted mapping records.
    ///
    /// The input JSON uses a tuple array rather than iteration order from a HashMap.
    pub fn digest(&self) -> Result<String, RegistryError> {
        let data =
            serde_json::to_vec(&(REGISTRY_VERSION, self.entries.values().collect::<Vec<_>>()))
                .map_err(|_| RegistryError::EncodingFailure)?;
        let digest = Sha256::digest(data);
        Ok(format!("{digest:x}"))
    }

    /// Exact built-in mappings from IANA and relevant RFCs.
    pub fn builtin() -> Self {
        let mut out = Self::empty();
        let mut add = |namespace,
                       kind,
                       alias: &str,
                       canonical: &str,
                       family: &str,
                       rule: &str,
                       source: &str| {
            assert!(
                out.register(Mapping {
                    namespace,
                    kind,
                    alias: alias.into(),
                    canonical: canonical.into(),
                    family: family.into(),
                    rule: rule.into(),
                    source: source.into(),
                })
                .is_ok(),
                "static built-in mapping contains no collisions"
            );
        };
        for alias in ["0x1301", "TLS_AES_128_GCM_SHA256"] {
            add(
                Namespace::TlsCipherSuite,
                Kind::CipherSuite,
                alias,
                "TLS_AES_128_GCM_SHA256",
                "TLS 1.3",
                "iana:tls-ciphers:1301",
                "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml",
            );
        }
        for alias in ["0x1302", "TLS_AES_256_GCM_SHA384"] {
            add(
                Namespace::TlsCipherSuite,
                Kind::CipherSuite,
                alias,
                "TLS_AES_256_GCM_SHA384",
                "TLS 1.3",
                "iana:tls-ciphers:1302",
                "https://www.rfc-editor.org/rfc/rfc8446",
            );
        }
        for alias in ["0x001D", "x25519"] {
            add(
                Namespace::TlsGroup,
                Kind::Group,
                alias,
                "x25519",
                "ECDH",
                "iana:tls-group:29",
                "https://www.rfc-editor.org/rfc/rfc8446",
            );
        }
        for alias in ["0x0017", "secp256r1"] {
            add(
                Namespace::TlsGroup,
                Kind::Group,
                alias,
                "secp256r1",
                "ECDH",
                "iana:tls-group:23",
                "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml",
            );
        }
        add(
            Namespace::X509Oid,
            Kind::Signature,
            "1.2.840.113549.1.1.11",
            "sha256WithRSAEncryption",
            "RSA PKCS#1 v1.5",
            "rfc4055:sha256-rsa",
            "https://www.rfc-editor.org/rfc/rfc4055",
        );
        add(
            Namespace::X509Oid,
            Kind::Signature,
            "1.2.840.113549.1.1.10",
            "RSASSA-PSS:parameters-required",
            "RSA-PSS",
            "rfc4055:rsassa-pss",
            "https://www.rfc-editor.org/rfc/rfc4055",
        );
        add(
            Namespace::X509Oid,
            Kind::Key,
            "1.2.840.10045.2.1",
            "id-ecPublicKey:curve-unspecified",
            "EC",
            "rfc5480:ec-public-key",
            "https://www.rfc-editor.org/rfc/rfc5480",
        );
        add(
            Namespace::OpenSsl,
            Kind::Hash,
            "SHA256",
            "SHA-256",
            "SHA-2",
            "openssl:evp-sha256",
            "https://docs.openssl.org/3.0/man3/EVP_sha256/",
        );
        add(
            Namespace::Ssh,
            Kind::Key,
            "ssh-ed25519",
            "ssh-ed25519",
            "Ed25519",
            "rfc8709:ssh-ed25519",
            "https://www.rfc-editor.org/rfc/rfc8709",
        );
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn exact_namespace_and_profile_distinctions() {
        let registry = Registry::builtin();
        let known = registry
            .resolve(&Namespace::TlsCipherSuite, &Kind::CipherSuite, "0x1301")
            .unwrap();
        assert!(
            matches!(known, Resolution::Known { canonical, .. } if canonical == "TLS_AES_128_GCM_SHA256")
        );
        let different = registry
            .resolve(&Namespace::TlsCipherSuite, &Kind::CipherSuite, "0x1302")
            .unwrap();
        assert!(
            matches!(different, Resolution::Known { canonical, .. } if canonical == "TLS_AES_256_GCM_SHA384")
        );
        assert!(matches!(
            registry
                .resolve(&Namespace::OpenSsl, &Kind::CipherSuite, "0x1301")
                .unwrap(),
            Resolution::Unknown { .. }
        ));
        assert!(matches!(
            registry
                .resolve(
                    &Namespace::TlsCipherSuite,
                    &Kind::CipherSuite,
                    "tls_aes_128_gcm_sha256"
                )
                .unwrap(),
            Resolution::Unknown { .. }
        ));
        assert!(
            matches!(registry.resolve(&Namespace::X509Oid, &Kind::Signature, "1.2.3.4").unwrap(), Resolution::Unknown { raw, .. } if raw == "1.2.3.4")
        );
    }
    #[test]
    fn insertion_order_does_not_change_digest() {
        let sample = Registry::builtin();
        let mut forward = Registry::empty();
        let mut reverse = Registry::empty();
        let entries: Vec<_> = sample.entries.values().cloned().collect();
        for entry in &entries {
            forward.register(entry.clone()).unwrap();
        }
        for entry in entries.into_iter().rev() {
            reverse.register(entry).unwrap();
        }
        assert_eq!(sample.digest(), forward.digest());
        assert_eq!(forward.digest(), reverse.digest());
    }
    #[test]
    fn collision_oversize_and_unknown_fail_closed() {
        let mut registry = Registry::builtin();
        let original = registry.entries.values().next().unwrap().clone();
        assert_eq!(registry.register(original), Err(RegistryError::Collision));
        assert_eq!(
            registry.resolve(&Namespace::Ssh, &Kind::Key, &"x".repeat(257)),
            Err(RegistryError::InvalidInput)
        );
        assert!(matches!(
            registry
                .resolve(&Namespace::Ssh, &Kind::Key, "unknown@vendor")
                .unwrap(),
            Resolution::Unknown { .. }
        ));
    }
}
