//! Versioned, type-aware canonical asset identity derivation.
use crate::{AssetId, AssetKind, InventoryError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Explicit collection/administrative scope for otherwise ambiguous identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityContext {
    /// Logical scope of the collection, including tenant/environment separation.
    pub scope: String,
    /// Optional stable endpoint, workload or source use-site for ambiguous instances.
    #[serde(default)]
    pub use_site: Option<String>,
    /// Concrete key provider instance, required for key and key-store identities.
    #[serde(default)]
    pub provider_instance: Option<String>,
}
impl IdentityContext {
    /// Pin an exact provider instance for identity derivation of keys and stores.
    pub fn with_provider_instance(mut self, instance: impl Into<String>) -> Result<Self, InventoryError> {
        let instance = instance.into();
        validate_component(&instance)?;
        self.provider_instance = Some(instance);
        Ok(self)
    }

    /// Specify a stable use-site identity when a profile alone is ambiguous.
    pub fn with_use_site(mut self, site: impl Into<String>) -> Result<Self, InventoryError> {
        let site = site.into();
        validate_component(&site)?;
        self.use_site = Some(site);
        Ok(self)
    }

    /// Construct a validated identity scope.
    pub fn new(scope: impl Into<String>) -> Result<Self, InventoryError> {
        let scope = scope.into();
        validate_component(&scope)?;
        Ok(Self {
            scope,
            use_site: None,
            provider_instance: None,
        })
    }
}
/// Identity result, retaining the canonical key components for inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetIdentity {
    /// Stable version of this canonicalization contract.
    pub version: u32,
    /// Canonical asset kind discriminator.
    pub kind: String,
    /// Scope-bound canonical identity components.
    pub components: Vec<String>,
}
impl AssetIdentity {
    /// Hash the canonical tuple with an identity-domain separator.
    pub fn asset_id(&self) -> Result<AssetId, InventoryError> {
        for item in &self.components {
            validate_component(item)?;
        }
        let encoded = serde_json::to_vec(&("cryptomap:asset:v1", self))
            .map_err(|e| InventoryError::Encoding(e.to_string()))?;
        let digest = Sha256::digest(encoded);
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        AssetId::new(format!("asset:v1:{hex}"))
    }
}
fn validate_component(s: &str) -> Result<(), InventoryError> {
    if s.is_empty() || s.len() > 2048 || s.trim() != s || s.chars().any(char::is_control) {
        return Err(InventoryError::InsufficientIdentity);
    }
    Ok(())
}
fn fold(s: &str) -> Result<String, InventoryError> {
    validate_component(s)?;
    Ok(s.to_ascii_lowercase())
}
fn host(value: &str) -> Result<String, InventoryError> {
    validate_component(value)?;
    let unbracketed = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(value);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let name = value.trim_end_matches('.');
    if name.is_empty() || name.contains('/') || name.contains(':') || name.contains(' ') {
        return Err(InventoryError::InsufficientIdentity);
    }
    fold(name)
}
/// Derive type-specific identity for an asset without collector insertion-order dependence.
///
/// Mutable descriptive fields must not enter the identity. If the source cannot
/// identify an asset, return InsufficientIdentity rather than merging unknowns.
pub fn derive(kind: &AssetKind, ctx: &IdentityContext) -> Result<AssetIdentity, InventoryError> {
    let scope = ctx.scope.clone();
    let (name, mut parts) = match kind {
        AssetKind::AlgorithmUse {
            family,
            profile,
            use_site,
        } => (
            "algorithm-use",
            vec![
                scope,
                fold(use_site)?,
                fold(family)?,
                profile
                    .as_deref()
                    .map(fold)
                    .transpose()?
                    .unwrap_or_else(|| "unspecified".into()),
            ],
        ),
        AssetKind::Key {
            provider,
            fingerprint,
            ..
        } => {
            let prov = provider
                .as_deref()
                .ok_or(InventoryError::InsufficientIdentity)?;
            let id = fingerprint
                .as_deref()
                .ok_or(InventoryError::InsufficientIdentity)?;
            ("key", vec![scope,
                ctx.provider_instance.clone().ok_or(InventoryError::InsufficientIdentity)?,
                fold(prov)?, fold(id)?])
        }
        AssetKind::Certificate {
            fingerprint_sha256, ..
        } => ("certificate", vec![fold(fingerprint_sha256)?]),
        AssetKind::Protocol {
            family,
            version,
            state,
        } => {
            let ver = version
                .as_deref()
                .ok_or(InventoryError::InsufficientIdentity)?;
            (
                "protocol",
                vec![
                    scope,
                    ctx.use_site
                        .clone()
                        .ok_or(InventoryError::InsufficientIdentity)?,
                    fold(family)?,
                    fold(ver)?,
                    format!("{state:?}"),
                ],
            )
        }
        AssetKind::Endpoint {
            transport,
            host: h,
            port,
            scope: endpoint_scope,
        } => (
            "endpoint",
            vec![
                scope,
                fold(endpoint_scope)?,
                fold(transport)?,
                host(h)?,
                port.to_string(),
            ],
        ),
        AssetKind::Library {
            ecosystem,
            name,
            version,
        } => (
            "library",
            vec![scope, fold(ecosystem)?, fold(name)?, version.clone()],
        ),
        AssetKind::Runtime { name, version } => {
            let version = version
                .as_deref()
                .ok_or(InventoryError::InsufficientIdentity)?;
            ("runtime", vec![scope, fold(name)?, version.to_string()])
        }
        AssetKind::KeyStore { provider, name } => {
            ("keystore", vec![scope, fold(provider)?, name.clone()])
        }
        AssetKind::SourceUse { source, location } => {
            ("source-use", vec![scope, source.clone(), location.clone()])
        }
        AssetKind::TrustAnchor { fingerprint } => ("trust-anchor", vec![fold(fingerprint)?]),
        AssetKind::Extension { namespace, kind } => (
            "extension",
            vec![
                scope,
                ctx.use_site
                    .clone()
                    .ok_or(InventoryError::InsufficientIdentity)?,
                fold(namespace)?,
                fold(kind)?,
            ],
        ),
        AssetKind::Provider { name, instance } => {
            ("provider", vec![scope, fold(name)?, instance.clone()])
        }
        AssetKind::CryptoImplementation { product, version } => (
            "implementation",
            vec![scope, fold(product)?, version.clone()],
        ),
        AssetKind::Authority {
            certificate_fingerprint,
        } => ("authority", vec![fold(certificate_fingerprint)?]),
        AssetKind::DetailedAlgorithm { metadata: m } => (
            "algorithm-use",
            vec![
                scope,
                fold(&m.use_site)?,
                fold(&m.family)?,
                match &m.profile {
                    crate::metadata::Observed::Known(p) => fold(p)?,
                    _ => "unspecified".into(),
                },
            ],
        ),
        AssetKind::DetailedKey { metadata: m } => {
            let provider = match &m.provider {
                crate::metadata::Observed::Known(v) => v,
                _ => return Err(InventoryError::InsufficientIdentity),
            };
            let key = match &m.fingerprint_or_reference {
                crate::metadata::Observed::Known(v) => v,
                _ => return Err(InventoryError::InsufficientIdentity),
            };
            ("key", vec![scope, fold(provider)?, fold(key)?])
        }
        AssetKind::DetailedCertificate { metadata: m } => {
            ("certificate", vec![fold(&m.fingerprint_sha256)?])
        }
        AssetKind::DetailedProtocol { metadata: m } => {
            let site = ctx
                .use_site
                .clone()
                .ok_or(InventoryError::InsufficientIdentity)?;
            (
                "protocol",
                vec![
                    scope,
                    site,
                    fold(&m.family)?,
                    match &m.version {
                        crate::metadata::Observed::Known(v) => fold(v)?,
                        _ => "unspecified".into(),
                    },
                    format!("{:?}", m.state),
                ],
            )
        }
        AssetKind::DetailedDependency { metadata: m } => (
            "library",
            vec![
                scope,
                fold(&m.ecosystem)?,
                fold(&m.name)?,
                m.version.clone(),
            ],
        ),
        AssetKind::DetailedImplementation { metadata: m } => (
            "implementation",
            vec![
                scope,
                fold(&m.product)?,
                match &m.version {
                    crate::metadata::Observed::Known(v) => v.clone(),
                    _ => return Err(InventoryError::InsufficientIdentity),
                },
            ],
        ),
    };
    for p in &parts {
        validate_component(p)?;
    }
    Ok(AssetIdentity {
        version: 1,
        kind: name.into(),
        components: std::mem::take(&mut parts),
    })
}
impl AssetId {
    /// Derive a stable ID from type-specific canonical identity components.
    pub fn from_kind(kind: &AssetKind, context: &IdentityContext) -> Result<Self, InventoryError> {
        derive(kind, context)?.asset_id()
    }
}
