//! B5.5 opt-in pseudonymous X.509 identity hints; never a trust decision.
//!
//! Only exact canonical DER Distinguished Name equality is asserted. Alternate
//! string encodings, Unicode normalization, RFC4514 spellings and case-folding
//! are deliberately NOT conflated. B5.6 may use these as candidate hints only.
use crate::collectors::certificate::MAX_CERT_DER_BYTES;
use crate::{
    certificate_name::canonical_name,
    coverage::CollectionScopeId,
    raw::{RawFactKind, RawObservation},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};
use zeroize::Zeroizing;

/// Uninformative, non-secret error classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// A missing, invalid, or under-length secret or namespace.
    InvalidAuthority,
    /// The supplied certificate was malformed or exceeded its DER budget.
    InvalidCertificate,
    /// The authority belongs to a different authorized collection scope.
    ScopeMismatch,
}

/// Opaque, tenant-and-key-version-scoped candidate correlation hints.
///
/// These values are pseudonymous, not anonymous: anyone holding a key can
/// compute candidate identifiers. They do not establish certificate issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateIdentityHints {
    /// Same role-neutral DN on either issuer or subject hashes identically.
    pub subject_dn: Option<String>,
    /// Same role-neutral DN on either issuer or subject hashes identically.
    pub issuer_dn: Option<String>,
    /// Serial is keyed and bound to the issuer DN, never globally matched.
    pub issuer_serial: Option<String>,
}
impl CertificateIdentityHints {
    /// Namespaced attributes explicitly chosen for an authorized inventory.
    pub fn attributes(&self) -> std::collections::BTreeMap<String, String> {
        let mut values = std::collections::BTreeMap::new();
        for (key, value) in [
            ("x509:identity:v1:subject-dn", &self.subject_dn),
            ("x509:identity:v1:issuer-dn", &self.issuer_dn),
            ("x509:identity:v1:issuer-serial", &self.issuer_serial),
        ] {
            if let Some(value) = value {
                values.insert(key.to_owned(), value.clone());
            }
        }
        values
    }
}

/// Host-owned keyed capability. Not Clone, Serialize, or publicly Debug.
///
/// The key is never emitted as an observation, request option, or log field.
/// Drop overwrites the owned key buffer. The host must also control its own
/// source buffer and any copies outside this capability.
pub struct CertificateIdentityAuthority {
    scope: CollectionScopeId,
    tenant: String,
    version: String,
    key: Zeroizing<[u8; 32]>,
}
impl std::fmt::Debug for CertificateIdentityAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertificateIdentityAuthority([REDACTED])")
    }
}
impl Drop for CertificateIdentityAuthority {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}
impl CertificateIdentityAuthority {
    /// Create an authority for an exact scope with a 256-bit host-generated key.
    ///
    /// Keys must come from a CSPRNG outside Cryptomap and must be independently
    /// allocated across tenants and versions. No generic user passwords.
    pub fn new(
        scope: CollectionScopeId,
        tenant: &str,
        version: &str,
        key: [u8; 32],
    ) -> Result<Self, IdentityError> {
        let key = Zeroizing::new(key);
        fn valid(s: &str) -> bool {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        }
        if !valid(tenant) || !valid(version) || key.iter().all(|b| *b == 0) {
            return Err(IdentityError::InvalidAuthority);
        }
        Ok(Self {
            scope,
            tenant: tenant.to_owned(),
            version: version.to_owned(),
            key,
        })
    }

    /// Scope identity prevents a host from silently reusing a capability in
    /// another collection scope. A host remains responsible for tenant binding.
    pub fn check_scope(&self, scope: &CollectionScopeId) -> Result<(), IdentityError> {
        if &self.scope != scope {
            return Err(IdentityError::ScopeMismatch);
        }
        Ok(())
    }

    fn mac(&self, domain: &[u8], fields: &[&[u8]]) -> String {
        // Length-prefixed fields eliminate tuple concatenation ambiguity.
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .unwrap_or_else(|_| unreachable!("fixed SHA-256 HMAC key"));
        for part in [
            b"cryptomap:x509-identity:v1".as_slice(),
            self.tenant.as_bytes(),
            self.version.as_bytes(),
            self.scope.as_str().as_bytes(),
            domain,
        ]
        .into_iter()
        .chain(fields.iter().copied())
        {
            mac.update(&(part.len() as u64).to_be_bytes());
            mac.update(part);
        }
        let digest = mac.finalize().into_bytes();
        let mut value = String::from("hmac-sha256:v1:");
        for byte in digest {
            use std::fmt::Write;
            let _ = write!(&mut value, "{byte:02x}");
        }
        value
    }

    fn record_receipt(&self, record: &RawObservation) -> Result<String, IdentityError> {
        if !matches!(record.fact, RawFactKind::Certificate { .. }) {
            return Err(IdentityError::InvalidCertificate);
        }
        // Use the existing, deterministic serde wire representation for all
        // context and attributes. The receipt itself is removed from the
        // cloned record so it cannot be recursively self-referential.
        let mut unsigned = record.clone();
        unsigned.attributes.remove("x509:identity:v1:receipt");
        let bytes = Zeroizing::new(
            serde_json::to_vec(&unsigned).map_err(|_| IdentityError::InvalidCertificate)?,
        );
        Ok(self.mac(b"record-receipt", &[bytes.as_slice()]))
    }

    /// Attach a keyed integrity receipt to exactly one collector-produced
    /// record, binding scope, tenant, key version, source, run, fingerprint,
    /// observation properties and all pseudonyms. Not exposed to plugins.
    pub(crate) fn seal_record(&self, record: &mut RawObservation) -> Result<(), IdentityError> {
        if !matches!(record.fact, RawFactKind::Certificate { .. })
            || record.attributes.contains_key("x509:identity:v1:receipt")
        {
            return Err(IdentityError::InvalidCertificate);
        }
        if !record.attributes.keys().any(|key| {
            matches!(
                key.as_str(),
                "x509:identity:v1:subject-dn" | "x509:identity:v1:issuer-dn"
            )
        }) {
            return Ok(());
        }
        record.attributes.insert(
            "x509:identity:v1:namespace".into(),
            self.mac(b"namespace", &[]),
        );
        let receipt = self.record_receipt(record)?;
        record
            .attributes
            .insert("x509:identity:v1:receipt".into(), receipt);
        Ok(())
    }

    /// Authenticate a collected record before promoting any pseudonym to
    /// canonical inventory. A syntactically plausible imported HMAC is never
    /// sufficient: normalizers require this *same* host-owned authority.
    pub(crate) fn verify_record(&self, record: &RawObservation) -> bool {
        let Some(namespace) = record.attributes.get("x509:identity:v1:namespace") else {
            return false;
        };
        let Some(receipt) = record.attributes.get("x509:identity:v1:receipt") else {
            return false;
        };
        if namespace != &self.mac(b"namespace", &[]) {
            return false;
        }
        self.record_receipt(record)
            .is_ok_and(|signed| signed == *receipt)
    }

    /// Project bounded canonical public DER to opaque issuer/subject hints.
    ///
    /// Only supported, unambiguous ASCII DirectoryString representations
    /// (PrintableString and UTF8String) are normalized. Other DN encodings,
    /// Unicode requiring LDAP StringPrep or unsupported attributes remain
    /// explicitly Unknown, preventing fabricated issuer matches. This does
    /// not establish X.509 issuance or certificate trust.
    pub fn project_der(&self, der: &[u8]) -> Result<CertificateIdentityHints, IdentityError> {
        if der.is_empty() || der.len() > MAX_CERT_DER_BYTES {
            return Err(IdentityError::InvalidCertificate);
        }
        let certificate =
            Certificate::from_der(der).map_err(|_| IdentityError::InvalidCertificate)?;
        let same = certificate
            .to_der()
            .map_err(|_| IdentityError::InvalidCertificate)?;
        if same != der {
            return Err(IdentityError::InvalidCertificate);
        }
        let tbs = &certificate.tbs_certificate;
        let subject = Zeroizing::new(
            tbs.subject
                .to_der()
                .map_err(|_| IdentityError::InvalidCertificate)?,
        );
        let issuer = Zeroizing::new(
            tbs.issuer
                .to_der()
                .map_err(|_| IdentityError::InvalidCertificate)?,
        );
        let subject_name = canonical_name(&subject).map(Zeroizing::new);
        let issuer_name = canonical_name(&issuer).map(Zeroizing::new);
        let subject_dn = subject_name
            .as_ref()
            .map(|name| self.mac(b"dn", &[name.as_slice()]));
        let issuer_dn = issuer_name
            .as_ref()
            .map(|name| self.mac(b"dn", &[name.as_slice()]));
        let issuer_serial = issuer_name.as_ref().map(|name| {
            self.mac(
                b"issuer-serial",
                &[name.as_slice(), tbs.serial_number.as_bytes()],
            )
        });
        Ok(CertificateIdentityHints {
            subject_dn,
            issuer_dn,
            issuer_serial,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use x509_cert::der::{DecodePem, Encode};
    const RSA: &[u8] = include_bytes!("../examples/fixtures/certificate/rsa.pem");
    fn authority(tenant: &str, version: &str, key: u8) -> CertificateIdentityAuthority {
        CertificateIdentityAuthority::new(
            CollectionScopeId::new("identity-test").unwrap(),
            tenant,
            version,
            [key; 32],
        )
        .unwrap()
    }
    #[test]
    fn stable_keyed_hints_and_default_secret_privacy() {
        let cert = Certificate::from_pem(RSA).unwrap().to_der().unwrap();
        let a = authority("tenant-a", "key-1", 7);
        let h = a.project_der(&cert).unwrap();
        assert_eq!(h, a.project_der(&cert).unwrap());
        assert_ne!(
            h,
            authority("tenant-b", "key-1", 7)
                .project_der(&cert)
                .unwrap()
        );
        assert_ne!(
            h,
            authority("tenant-a", "key-2", 7)
                .project_der(&cert)
                .unwrap()
        );
        assert_ne!(
            h,
            authority("tenant-a", "key-1", 8)
                .project_der(&cert)
                .unwrap()
        );
        assert!(!format!("{a:?}").contains("tenant-a"));
        assert!(
            !serde_json::to_string(&h.attributes())
                .unwrap()
                .contains("PRIVATE")
        );
        assert!(
            h.attributes()
                .values()
                .all(|x| x.starts_with("hmac-sha256:v1:") && x.len() == 79)
        );
    }
    #[test]
    fn reject_zero_key_and_scope_mismatch() {
        let scope = CollectionScopeId::new("identity-test").unwrap();
        assert!(matches!(
            CertificateIdentityAuthority::new(scope, "t", "v", [0; 32]),
            Err(IdentityError::InvalidAuthority)
        ));
        let a = authority("tenant", "v", 5);
        assert_eq!(
            a.check_scope(&CollectionScopeId::new("other").unwrap()),
            Err(IdentityError::ScopeMismatch)
        );
        assert_eq!(a.project_der(&[0]), Err(IdentityError::InvalidCertificate));
    }
    #[test]
    fn same_subject_and_issuer_correlate_without_certificate_trust() {
        let issuer = Certificate::from_pem(RSA).unwrap();
        let mut child = issuer.clone();
        // An in-memory TBS edit is deliberately *not* re-signed. Matching
        // candidate identities never implies signature/path validation.
        child.tbs_certificate.issuer = issuer.tbs_certificate.subject.clone();
        let key = authority("tenant-a", "v1", 19);
        let issuer_hint = key.project_der(&issuer.to_der().unwrap()).unwrap();
        let child_hint = key.project_der(&child.to_der().unwrap()).unwrap();
        assert_eq!(issuer_hint.subject_dn, child_hint.issuer_dn);
    }

    #[test]
    fn equal_keys_must_not_correlate_across_scopes() {
        let cert = Certificate::from_pem(RSA).unwrap().to_der().unwrap();
        let a = authority("tenant-a", "v1", 19).project_der(&cert).unwrap();
        let other = CertificateIdentityAuthority::new(
            CollectionScopeId::new("other-scope").unwrap(),
            "tenant-a",
            "v1",
            [19; 32],
        )
        .unwrap()
        .project_der(&cert)
        .unwrap();
        assert_ne!(a, other);
    }
}
