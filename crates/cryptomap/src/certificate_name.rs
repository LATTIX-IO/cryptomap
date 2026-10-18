//! Bounded conservative X.509 DN comparison-key construction.
//!
//! Supports ASCII PrintableString and ASCII UTF8String on known case-ignore
//! DirectoryString attributes. Non-ASCII, IA5, BMP, Teletex, Universal,
//! unknown attribute syntaxes or structurally ambiguous names return Unknown.
//! This is a deliberately supported SUBSET of RFC 5280 7.1 / RFC 4518,
//! not an implementation of full Unicode LDAP StringPrep.
use x509_cert::der::{Decode, asn1::ObjectIdentifier};

const MAX_RDN: usize = 64;
const MAX_ATTRIBUTE_PER_RDN: usize = 16;
const MAX_ATTR_BYTES: usize = 1024;
const MAX_DN_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    wire: &'a [u8],
}
fn tlv<'a>(stream: &mut &'a [u8]) -> Option<Tlv<'a>> {
    let original = *stream;
    let (&tag, tail) = original.split_first()?;
    if tag & 0x1f == 0x1f { return None; }
    let (&first, rest) = tail.split_first()?;
    let (length, after_length) = if first & 0x80 == 0 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 3 || rest.len() < n || rest[0] == 0 { return None; }
        let mut len = 0usize;
        for &byte in &rest[..n] { len = len.checked_mul(256)?.checked_add(byte as usize)?; }
        if len < 128 { return None; }
        (len, &rest[n..])
    };
    if length > after_length.len() { return None; }
    let (value, remainder) = after_length.split_at(length);
    let wire_length = original.len() - remainder.len();
    *stream = remainder;
    Some(Tlv { tag, value, wire: &original[..wire_length] })
}
fn len_prefix(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    let length = u32::try_from(bytes.len()).ok()?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Some(())
}
fn directory_oid(oid: &str) -> bool {
    matches!(
        oid,
        "2.5.4.3" | "2.5.4.4" | "2.5.4.5" | "2.5.4.6" | "2.5.4.7"
          | "2.5.4.8" | "2.5.4.10" | "2.5.4.11" | "2.5.4.12"
          | "2.5.4.42" | "2.5.4.43" | "2.5.4.44" | "2.5.4.65"
    )
}
fn canonical_ascii_value(value: Tlv<'_>) -> Option<Vec<u8>> {
    if !matches!(value.tag, 0x13 | 0x0c) || value.value.is_empty()
        || value.value.len() > MAX_ATTR_BYTES || !value.value.is_ascii()
    {
        return None;
    }
    // Restrict PrintableString to its ASN.1 permitted code points.
    if value.tag == 0x13 && !value.value.iter().all(|&byte| {
        byte.is_ascii_alphanumeric() || matches!(byte,
            b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.'
            | b'/' | b':' | b'=' | b'?')
    }) {
        return None;
    }
    // Do not silently equate controls, tabs or non-ASCII Unicode; normalizing
    // them correctly would require full LDAP StringPrep and attribute syntax.
    if value.value.iter().any(|&b| b < 0x20 || b == 0x7f) { return None; }
    let mut normalized = Vec::with_capacity(value.value.len());
    let mut space = false;
    for &byte in value.value {
        if byte == b' ' {
            space = !normalized.is_empty();
        } else {
            if space { normalized.push(b' '); }
            normalized.push(byte.to_ascii_lowercase());
            space = false;
        }
    }
    if normalized.is_empty() { return None; }
    Some(normalized)
}

/// Build a bounded, role-neutral, unambiguous supported comparison key.
/// None means identity Unknown, never an empty or inferred identity.
///
/// Preserves the RDN sequence and each RDN's SET boundary, sorting
/// normalized attribute pairs only *within* an RDN. No plaintext leaves
/// the caller and the returned temporary must never be logged/exported.
pub(crate) fn canonical_name(der: &[u8]) -> Option<Vec<u8>> {
    if der.is_empty() || der.len() > MAX_DN_BYTES { return None; }
    let mut input = der;
    let sequence = tlv(&mut input)?;
    if sequence.tag != 0x30 || !input.is_empty() { return None; }
    let mut rdns = sequence.value;
    let mut key = Vec::new();
    key.extend_from_slice(b"cryptomap:dn-ascii-comparison:v1");
    let mut count = 0;
    while !rdns.is_empty() {
        count += 1;
        if count > MAX_RDN { return None; }
        let rdn = tlv(&mut rdns)?;
        if rdn.tag != 0x31 || rdn.value.is_empty() { return None; }
        let mut attrs = rdn.value;
        let mut normalized = Vec::new();
        while !attrs.is_empty() {
            if normalized.len() >= MAX_ATTRIBUTE_PER_RDN { return None; }
            let pair = tlv(&mut attrs)?;
            if pair.tag != 0x30 { return None; }
            let mut inner = pair.value;
            let oid = tlv(&mut inner)?;
            if oid.tag != 0x06 { return None; }
            let oid = ObjectIdentifier::from_der(oid.wire).ok()?.to_string();
            if !directory_oid(&oid) { return None; }
            let value = tlv(&mut inner)?;
            if !inner.is_empty() { return None; }
            let normalized_value = canonical_ascii_value(value)?;
            let mut item = Vec::new();
            len_prefix(&mut item, oid.as_bytes())?;
            len_prefix(&mut item, &normalized_value)?;
            normalized.push(item);
        }
        normalized.sort_unstable();
        if normalized.windows(2).any(|items| items[0] == items[1]) {
            // A DER-distinct but semantically duplicated value is ambiguous.
            return None;
        }
        let mut group = Vec::new();
        for item in normalized { len_prefix(&mut group, &item)?; }
        len_prefix(&mut key, &group)?;
    }
    if count == 0 { return None; }
    Some(key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    // CN=AbC, DER PrintableString versus UTF8String.
    const PRINTABLE: &[u8] = &[0x30,0x0e,0x31,0x0c,0x30,0x0a,0x06,0x03,0x55,0x04,0x03,0x13,0x03,b'A',b'b',b'C'];
    const UTF8: &[u8] = &[0x30,0x0e,0x31,0x0c,0x30,0x0a,0x06,0x03,0x55,0x04,0x03,0x0c,0x03,b'a',b'B',b'c'];
    #[test]
    fn cross_tag_ascii_casefold_and_structure() {
        assert_eq!(canonical_name(PRINTABLE), canonical_name(UTF8));
        assert!(canonical_name(PRINTABLE).is_some());
        let mut changed = PRINTABLE.to_vec();
        *changed.last_mut().unwrap() = b'd';
        assert_ne!(canonical_name(PRINTABLE),canonical_name(&changed));
    }
    #[test]
    fn reject_unsupported_unicode_and_malformed_der() {
        let mut unicode = UTF8.to_vec();
        unicode[13] = 0xc3; unicode[14] = 0xa9;
        assert_eq!(canonical_name(&unicode),None);
        assert_eq!(canonical_name(&[0x30,0x00]),None);
        assert_eq!(canonical_name(&[0x30,0x80]),None);
        assert_eq!(canonical_name(&[0x30,0x01,0xff]),None);
        assert_eq!(canonical_name(&vec![0;MAX_DN_BYTES+1]),None);
    }
    #[test]
    fn rdn_sequence_boundaries_do_not_collapse() {
        let a=canonical_name(PRINTABLE).unwrap();
        let mut two=vec![0x30,0x1c];
        two.extend_from_slice(&PRINTABLE[2..]);
        two.extend_from_slice(&PRINTABLE[2..]);
        let b=canonical_name(&two).unwrap();
        assert_ne!(a,b);
    }
}
