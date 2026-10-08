//! Input and provenance validation for bounded, nonsecret inventory records.
use crate::{Asset, AssetKind, Evidence, InventoryError, InventoryLimits, Observation};
use sha2::{Digest, Sha256};

/// Validate an input string as safe bounded inventory metadata.
///
/// The check is intentionally not a generic secret detector; upstream collectors
/// must not submit credentials or key material in the first place.
pub fn safe_text(value: &str, max_bytes: usize) -> Result<(), InventoryError> {
    if value.len() > max_bytes
        || value
            .chars()
            .any(|c| c == '\0' || c.is_control() && c != '\n')
    {
        return Err(InventoryError::InvalidMetadata);
    }
    let uppercase = value.to_ascii_uppercase();
    for marker in [
        "-----BEGIN PRIVATE KEY",
        "-----BEGIN RSA PRIVATE KEY",
        "-----BEGIN EC PRIVATE KEY",
        "-----BEGIN OPENSSH PRIVATE KEY",
        "-----BEGIN ENCRYPTED PRIVATE KEY",
        "AWS_SECRET_ACCESS_KEY=",
        "-----BEGIN PGP PRIVATE KEY BLOCK",
    ] {
        if uppercase.contains(marker) {
            return Err(InventoryError::ProhibitedMaterial);
        }
    }
    Ok(())
}
fn part(s: &str, a: usize, b: usize) -> Result<i64, InventoryError> {
    let text = s.get(a..b).ok_or(InventoryError::InvalidTimestamp)?;
    if !text.bytes().all(|x| x.is_ascii_digit()) {
        return Err(InventoryError::InvalidTimestamp);
    }
    text.parse().map_err(|_| InventoryError::InvalidTimestamp)
}
fn leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}
/// Parse RFC3339 timestamps into UTC whole seconds, ignoring fractional subseconds.
///
/// Requires a timezone and rejects invalid dates/times and unsupported year widths.
pub fn utc_seconds(s: &str) -> Result<i64, InventoryError> {
    if s.len() < 20 || s.len() > 40 || !s.is_ascii() {
        return Err(InventoryError::InvalidTimestamp);
    }
    for (i, c) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
        if s.as_bytes().get(i) != Some(&c) {
            return Err(InventoryError::InvalidTimestamp);
        }
    }
    let y = part(s, 0, 4)?;
    let m = part(s, 5, 7)?;
    let d = part(s, 8, 10)?;
    let hh = part(s, 11, 13)?;
    let mm = part(s, 14, 16)?;
    let ss = part(s, 17, 19)?;
    if !(1..=12).contains(&m) || hh > 23 || mm > 59 || ss > 59 {
        return Err(InventoryError::InvalidTimestamp);
    }
    let month_days = [
        31,
        if leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if d < 1 || d > month_days[(m - 1) as usize] {
        return Err(InventoryError::InvalidTimestamp);
    }
    let tz_at = if s.ends_with('Z') {
        s.len() - 1
    } else {
        s.get(19..)
            .ok_or(InventoryError::InvalidTimestamp)?
            .rfind(['+', '-'])
            .map(|i| i + 19)
            .ok_or(InventoryError::InvalidTimestamp)?
    };
    if tz_at == 19 {
    } else {
        let fraction = s.get(19..tz_at).ok_or(InventoryError::InvalidTimestamp)?;
        if !fraction.starts_with('.')
            || fraction.len() < 2
            || !fraction[1..].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(InventoryError::InvalidTimestamp);
        }
    }
    let offset = if s.ends_with('Z') {
        0
    } else {
        if s.len() != tz_at + 6 || s.as_bytes().get(tz_at + 3) != Some(&b':') {
            return Err(InventoryError::InvalidTimestamp);
        }
        let h = part(s, tz_at + 1, tz_at + 3)?;
        let min = part(s, tz_at + 4, tz_at + 6)?;
        if h > 23 || min > 59 {
            return Err(InventoryError::InvalidTimestamp);
        }
        let sign = if s.as_bytes()[tz_at] == b'+' {
            1
        } else if s.as_bytes()[tz_at] == b'-' {
            -1
        } else {
            return Err(InventoryError::InvalidTimestamp);
        };
        sign * (h * 3600 + min * 60)
    };
    // Gregorian days since Unix epoch, based on 400-year eras.
    let yy = y - i64::from(m <= 2);
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Ok(days * 86400 + hh * 3600 + mm * 60 + ss - offset)
}
/// A bounded validated observation property key.
pub fn property_key(value: &str) -> Result<(), InventoryError> {
    safe_text(value, 256)?;
    let (namespace, field) = value
        .split_once(':')
        .ok_or(InventoryError::InvalidMetadata)?;
    if namespace.is_empty()
        || field.is_empty()
        || !namespace
            .bytes()
            .all(|x| x.is_ascii_alphanumeric() || x == b'-' || x == b'_')
    {
        return Err(InventoryError::InvalidMetadata);
    }
    Ok(())
}
impl Evidence {
    /// Validate provenance, timestamp and bounded source identifier.
    pub fn validate(&self, limits: &InventoryLimits) -> Result<(), InventoryError> {
        if self.collector_version.is_empty() {
            return Err(InventoryError::InvalidMetadata);
        }
        safe_text(&self.collector_version, 128)?;
        safe_text(&self.source, limits.field_bytes)?;
        utc_seconds(&self.observed_at)?;
        if matches!(self.kind, crate::EvidenceKind::Inferred) {
            let rule=self.inference_rule.as_deref().ok_or(InventoryError::InvalidMetadata)?;
            if rule.is_empty() { return Err(InventoryError::InvalidMetadata); }
            safe_text(rule,128)?;
        }
        if let Some(digest) = &self.source_sha256 {
            if digest.len() != 64 || !digest.bytes().all(|x| x.is_ascii_hexdigit()) {
                return Err(InventoryError::InvalidMetadata);
            }
        }
        Ok(())
    }
}
impl Observation {
    /// Validate the shape of an evidence-backed claim.
    pub fn validate(&self, limits: &InventoryLimits) -> Result<(), InventoryError> {
        property_key(&self.property)?;
        safe_text(&self.value, limits.field_bytes)
    }
}
impl Asset {
    /// Validate asset metadata and extension bounds.
    pub fn validate(&self, limits: &InventoryLimits) -> Result<(), InventoryError> {
        if self.extensions.len() > limits.extension_entries {
            return Err(InventoryError::LimitExceeded("extensions"));
        }
        for (k, v) in &self.extensions {
            property_key(k)?;
            safe_text(v, limits.field_bytes)?;
        }
        let kind =
            serde_json::to_vec(&self.kind).map_err(|e| InventoryError::Encoding(e.to_string()))?;
        if kind.len() > limits.record_bytes {
            return Err(InventoryError::LimitExceeded("asset bytes"));
        }
        let preview = String::from_utf8_lossy(&kind);
        safe_text(&preview, limits.record_bytes)?;
        match &self.kind {
            AssetKind::Certificate {
                fingerprint_sha256, ..
            }
            | AssetKind::TrustAnchor {
                fingerprint: fingerprint_sha256,
            } => {
                if fingerprint_sha256.len() != 64
                    || !fingerprint_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(InventoryError::InvalidMetadata);
                }
            }
            _ => {}
        }
        Ok(())
    }
}
/// SHA-256 hex digest of a nonsecret metadata object.
pub(crate) fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
