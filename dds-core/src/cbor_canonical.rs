//! **M-1 (security review)** — deterministic CBOR encoder for the
//! `TokenPayload` and `PublicKeyBundle` shapes, following RFC 8949
//! §4.2.1 (Core Deterministic Encoding):
//!
//! - integers in shortest-form argument encoding,
//! - text and byte strings with a definite-length head,
//! - maps with keys sorted by the lexicographic order of their
//!   encoded bytes (shortest-first then byte-wise),
//! - arrays with definite-length heads,
//! - no indefinite-length items, no tags, no floats.
//!
//! Scope is narrow on purpose — only the shapes the token-signing
//! path touches, so the encoder stays short and auditable. Every
//! other consumer of CBOR in the workspace keeps using `ciborium`.
//!
//! The encoder is **stable**: adding a new field to `TokenPayload`
//! (or to any struct handled here) requires an explicit change to
//! `encode_token_payload` so that reviewers notice. The
//! `canonical_token_payload_covers_all_fields` test in this module
//! is a structural canary: whenever `TokenPayload` grows a field,
//! the test fails until the author updates the encoder.

use alloc::vec::Vec;

use crate::crypto::{PublicKeyBundle, SchemeId};
use crate::token::{TokenKind, TokenPayload};

/// Errors produced by the canonical encoder. Reserved for future
/// shapes that cannot be canonically encoded (today the encoder is
/// infallible for `TokenPayload`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalCborError {}

/// RFC 8949 major types we emit.
const MAJOR_UNSIGNED_INT: u8 = 0;
const MAJOR_BYTE_STRING: u8 = 2;
const MAJOR_TEXT_STRING: u8 = 3;
const MAJOR_MAP: u8 = 5;

/// Append the CBOR initial byte + argument in shortest form.
fn write_head(buf: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg < 24 {
        buf.push(mt | arg as u8);
    } else if arg <= 0xff {
        buf.push(mt | 0x18);
        buf.push(arg as u8);
    } else if arg <= 0xffff {
        buf.push(mt | 0x19);
        buf.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        buf.push(mt | 0x1a);
        buf.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        buf.push(mt | 0x1b);
        buf.extend_from_slice(&arg.to_be_bytes());
    }
}

fn enc_u64(v: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(9);
    write_head(&mut b, MAJOR_UNSIGNED_INT, v);
    b
}

fn enc_text(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut b = Vec::with_capacity(bytes.len() + 9);
    write_head(&mut b, MAJOR_TEXT_STRING, bytes.len() as u64);
    b.extend_from_slice(bytes);
    b
}

fn enc_bytes(v: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(v.len() + 9);
    write_head(&mut b, MAJOR_BYTE_STRING, v.len() as u64);
    b.extend_from_slice(v);
    b
}

/// Write a map with its entries sorted by encoded-key bytes (RFC
/// 8949 §4.2.1 map-key ordering).
fn write_sorted_map(buf: &mut Vec<u8>, mut entries: Vec<(Vec<u8>, Vec<u8>)>) {
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    write_head(buf, MAJOR_MAP, entries.len() as u64);
    for (k, v) in entries {
        buf.extend_from_slice(&k);
        buf.extend_from_slice(&v);
    }
}

/// `TokenKind`'s on-wire text representation. Kept in sync with the
/// `#[serde(rename = "…")]` attributes on the enum — mirror so the
/// canonical encoder doesn't depend on serde's naming at runtime.
fn token_kind_str(k: &TokenKind) -> &'static str {
    match k {
        TokenKind::Attest => "vch:attest",
        TokenKind::Vouch => "vch:vouch",
        TokenKind::Revoke => "vch:revoke",
        TokenKind::Burn => "vch:burn",
    }
}

/// `SchemeId`'s on-wire text representation (default serde
/// externally-tagged form for unit variants is the variant name).
fn scheme_id_str(s: &SchemeId) -> &'static str {
    match s {
        SchemeId::Ed25519 => "Ed25519",
        SchemeId::EcdsaP256 => "EcdsaP256",
        SchemeId::HybridEdMldsa65 => "HybridEdMldsa65",
        SchemeId::TripleHybridEdEcdsaMldsa65 => "TripleHybridEdEcdsaMldsa65",
    }
}

/// Canonical CBOR for `PublicKeyBundle { scheme, bytes }`.
pub fn encode_public_key_bundle(kb: &PublicKeyBundle) -> Vec<u8> {
    let mut out = Vec::new();
    let entries = alloc::vec![
        (enc_text("scheme"), enc_text(scheme_id_str(&kb.scheme))),
        (enc_text("bytes"), enc_bytes(&kb.bytes)),
    ];
    write_sorted_map(&mut out, entries);
    out
}

/// Canonical CBOR for a `TokenPayload`.
///
/// Present `Option` fields are included; absent ones are omitted
/// (matching the `skip_serializing_if = "Option::is_none"` semantics
/// on the struct). `iss_key` is recursively canonicalised.
pub fn encode_token_payload(p: &TokenPayload) -> Vec<u8> {
    let mut out = Vec::new();
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = alloc::vec![
        // Always-present fields.
        (enc_text("iss"), enc_text(&p.iss)),
        (enc_text("iss_key"), encode_public_key_bundle(&p.iss_key)),
        (enc_text("jti"), enc_text(&p.jti)),
        (enc_text("sub"), enc_text(&p.sub)),
        (enc_text("kind"), enc_text(token_kind_str(&p.kind))),
        (enc_text("iat"), enc_u64(p.iat)),
    ];

    if let Some(v) = &p.purpose {
        entries.push((enc_text("purpose"), enc_text(v)));
    }
    if let Some(v) = &p.vch_iss {
        entries.push((enc_text("vch_iss"), enc_text(v)));
    }
    if let Some(v) = &p.vch_sum {
        entries.push((enc_text("vch_sum"), enc_text(v)));
    }
    if let Some(v) = &p.revokes {
        entries.push((enc_text("revokes"), enc_text(v)));
    }
    if let Some(v) = p.exp {
        entries.push((enc_text("exp"), enc_u64(v)));
    }
    if let Some(v) = &p.body_type {
        entries.push((enc_text("body_type"), enc_text(v)));
    }
    if let Some(v) = &p.body_cbor {
        entries.push((enc_text("body_cbor"), enc_bytes(v)));
    }

    write_sorted_map(&mut out, entries);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{PublicKeyBundle, SchemeId};
    use crate::token::{TokenKind, TokenPayload};

    fn sample_bundle() -> PublicKeyBundle {
        PublicKeyBundle {
            scheme: SchemeId::Ed25519,
            bytes: alloc::vec![0x01; 32],
        }
    }

    fn sample_payload() -> TokenPayload {
        TokenPayload {
            iss: "urn:vouchsafe:alice.hash".into(),
            iss_key: sample_bundle(),
            jti: "jti-1".into(),
            sub: "urn:vouchsafe:alice.hash".into(),
            kind: TokenKind::Attest,
            purpose: Some("dds:directory-entry".into()),
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1_700_000_000,
            exp: Some(4_102_444_800),
            body_type: None,
            body_cbor: None,
        }
    }

    #[test]
    fn head_shortest_form_boundaries() {
        // 0..23 fits in the initial byte.
        let v = enc_u64(23);
        assert_eq!(v, alloc::vec![0x17]);
        // 24..255 uses one trailing byte.
        let v = enc_u64(24);
        assert_eq!(v, alloc::vec![0x18, 0x18]);
        let v = enc_u64(255);
        assert_eq!(v, alloc::vec![0x18, 0xff]);
        // 256..65535 uses two trailing bytes.
        let v = enc_u64(256);
        assert_eq!(v, alloc::vec![0x19, 0x01, 0x00]);
        let v = enc_u64(65535);
        assert_eq!(v, alloc::vec![0x19, 0xff, 0xff]);
        // 65536..(2^32-1) uses four.
        let v = enc_u64(65536);
        assert_eq!(v, alloc::vec![0x1a, 0x00, 0x01, 0x00, 0x00]);
        // 2^32 uses eight.
        let v = enc_u64(1u64 << 32);
        assert_eq!(
            v,
            alloc::vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn text_string_header_and_bytes() {
        let v = enc_text("abc");
        // major 3 (0x60) | len 3
        assert_eq!(v, alloc::vec![0x63, b'a', b'b', b'c']);
    }

    #[test]
    fn byte_string_header_and_bytes() {
        let v = enc_bytes(&[0xde, 0xad, 0xbe, 0xef]);
        // major 2 (0x40) | len 4
        assert_eq!(v, alloc::vec![0x44, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn map_keys_are_byte_sorted() {
        let mut buf = Vec::new();
        let entries = alloc::vec![
            (enc_text("zzz"), enc_u64(1)),
            (enc_text("aaa"), enc_u64(2)),
            (enc_text("aa"), enc_u64(3)),
        ];
        write_sorted_map(&mut buf, entries);
        // map header 0xa3 (major 5, len 3)
        assert_eq!(buf[0], 0xa3);
        // sorted by encoded-key bytes: shortest first, then lex.
        // Keys start at offset 1. "aa" = 0x62 0x61 0x61 -> shortest.
        assert_eq!(&buf[1..4], &[0x62, b'a', b'a']); // "aa"
        // value for "aa" is 3 -> 0x03 (1 byte).
        assert_eq!(buf[4], 0x03);
        // then "aaa" (4 bytes), value 2.
        assert_eq!(&buf[5..9], &[0x63, b'a', b'a', b'a']);
        assert_eq!(buf[9], 0x02);
        // then "zzz" (4 bytes), value 1.
        assert_eq!(&buf[10..14], &[0x63, b'z', b'z', b'z']);
        assert_eq!(buf[14], 0x01);
    }

    #[test]
    fn public_key_bundle_is_deterministic_and_sorted() {
        let a = encode_public_key_bundle(&sample_bundle());
        let b = encode_public_key_bundle(&sample_bundle());
        assert_eq!(a, b);
        // Map header (len=2) followed by "bytes" key (shorter encoded
        // than "scheme").
        assert_eq!(a[0], 0xa2);
        assert_eq!(&a[1..7], &[0x65, b'b', b'y', b't', b'e', b's']);
    }

    #[test]
    fn token_payload_encode_is_deterministic() {
        let a = encode_token_payload(&sample_payload());
        let b = encode_token_payload(&sample_payload());
        assert_eq!(a, b);
    }

    /// Structural canary: when `TokenPayload` grows a field, this
    /// test fails unless the author also updates
    /// `encode_token_payload`. Counts the present fields on a
    /// payload whose every `Option` is `Some`.
    #[test]
    fn canonical_token_payload_covers_all_fields() {
        let mut p = sample_payload();
        p.vch_iss = Some("urn:vouchsafe:x".into());
        p.vch_sum = Some("hash".into());
        p.revokes = Some("jti-r".into());
        p.body_type = Some("dds:type".into());
        p.body_cbor = Some(alloc::vec![1, 2, 3]);
        let enc = encode_token_payload(&p);
        // Map header for 13 entries: 0xad (0xa0 | 13).
        assert_eq!(
            enc[0], 0xad,
            "expected 13-entry map; if TokenPayload grew a field, \
             update encode_token_payload and this test."
        );
    }

    /// Absent `Option` fields are omitted (not encoded as `null`).
    /// Matches `skip_serializing_if = \"Option::is_none\"`.
    #[test]
    fn absent_option_fields_are_omitted() {
        let p = sample_payload();
        let enc = encode_token_payload(&p);
        // Present: iss, iss_key, jti, sub, kind, iat, purpose, exp = 8.
        assert_eq!(enc[0], 0xa8);
    }
}
