//! End-to-end FIDO2 verify probe — no node, no HTTP.
//!
//! Runs the same makeCredential → verify_attestation → getAssertion →
//! verify_assertion path the multinode test uses, but feeds the bytes
//! directly into `dds_domain::fido2`. If this passes locally, the
//! cryptographic plumbing is sound and any failure in the multinode
//! path lives in the gossip / re-broadcast / store layer.

use base64::Engine;
use ctap_hid_fido2::{
    Cfg, FidoKeyHidFactory,
    fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
    verifier,
};
use sha2::{Digest, Sha256};

const RP_ID: &str = "dds.local";

fn cbor_text(out: &mut Vec<u8>, s: &str) {
    let len = s.len();
    if len < 24 {
        out.push(0x60 | len as u8);
    } else if len < 256 {
        out.push(0x78);
        out.push(len as u8);
    } else {
        out.push(0x79);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(s.as_bytes());
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    let len = b.len();
    if len < 24 {
        out.push(0x40 | len as u8);
    } else if len < 256 {
        out.push(0x58);
        out.push(len as u8);
    } else {
        out.push(0x59);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(b);
}

fn cbor_int(out: &mut Vec<u8>, val: i64) {
    if val >= 0 {
        let v = val as u64;
        if v < 24 {
            out.push(v as u8);
        } else if v < 256 {
            out.push(0x18);
            out.push(v as u8);
        } else {
            out.push(0x19);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
    } else {
        let v = (-1 - val) as u64;
        if v < 24 {
            out.push(0x20 | v as u8);
        } else if v < 256 {
            out.push(0x38);
            out.push(v as u8);
        } else {
            out.push(0x39);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
    }
}

fn cbor_array_header(out: &mut Vec<u8>, len: usize) {
    if len < 24 {
        out.push(0x80 | len as u8);
    } else if len < 256 {
        out.push(0x98);
        out.push(len as u8);
    } else {
        out.push(0x99);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

fn rebuild(
    fmt: &str,
    auth_data: &[u8],
    alg: i32,
    sig: &[u8],
    x5c: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa3);
    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, fmt);
    cbor_text(&mut out, "attStmt");
    if fmt == "none" || sig.is_empty() {
        out.push(0xa0);
    } else if !x5c.is_empty() {
        out.push(0xa3);
        cbor_text(&mut out, "alg");
        cbor_int(&mut out, alg as i64);
        cbor_text(&mut out, "sig");
        cbor_bytes(&mut out, sig);
        cbor_text(&mut out, "x5c");
        cbor_array_header(&mut out, x5c.len());
        for c in x5c {
            cbor_bytes(&mut out, c);
        }
    } else {
        out.push(0xa2);
        cbor_text(&mut out, "alg");
        cbor_int(&mut out, alg as i64);
        cbor_text(&mut out, "sig");
        cbor_bytes(&mut out, sig);
    }
    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, auth_data);
    out
}

fn main() {
    let device = FidoKeyHidFactory::create(&Cfg::init()).expect("open device");
    println!("=== FIDO2 end-to-end verify probe ===\n");

    // ── Step 1: makeCredential ───────────────────────────────────
    println!(">>> TOUCH for makeCredential <<<");
    let chal = verifier::create_challenge();
    let make_args = MakeCredentialArgsBuilder::new(RP_ID, &chal).build();
    let att = device
        .make_credential_with_args(&make_args)
        .expect("makeCredential");
    println!(
        "got attestation: fmt={} alg={} sig.len={} x5c.len={} auth_data.len={} cred_id.len={}",
        att.fmt,
        att.attstmt_alg,
        att.attstmt_sig.len(),
        att.attstmt_x5c.len(),
        att.auth_data.len(),
        att.credential_descriptor.id.len()
    );

    // ── Step 2: verify locally using ctap-hid-fido2 ──────────────
    let verify = verifier::verify_attestation(RP_ID, &chal, &att);
    if !verify.is_success {
        eprintln!("local verify_attestation FAILED");
        std::process::exit(1);
    }
    let cred_id = verify.credential_id.clone();
    println!("local ctap-hid-fido2 verify: OK");

    // ── Step 3: rebuild attobj like multinode test does ──────────
    let attobj = rebuild(&att.fmt, &att.auth_data, att.attstmt_alg, &att.attstmt_sig, &att.attstmt_x5c);
    println!("rebuilt attobj len={}", attobj.len());

    // ── Step 4: parse via dds_domain::fido2 (the server's path) ──
    let parsed = match dds_domain::fido2::verify_attestation(&attobj, &chal) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("dds_domain verify_attestation FAILED: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "dds_domain parsed attestation: cred_id.len={} rp_id_hash[0..4]={:02x?}",
        parsed.credential_id.len(),
        &parsed.rp_id_hash[0..4]
    );

    // Extract COSE key the same way the server does at assertion time.
    let p = 37 + 16 + 2 + parsed.credential_id.len();
    let cose_bytes = &parsed.auth_data[p..];
    let pk = match dds_domain::fido2::cose_to_credential_public_key(cose_bytes) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("cose_to_credential_public_key FAILED: {e}");
            std::process::exit(1);
        }
    };
    println!("extracted credential public key OK");

    // ── Step 5: getAssertion + verify ────────────────────────────
    println!("\n>>> TOUCH for getAssertion <<<");
    let cdj = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://{}"}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"server-issued-challenge"),
        RP_ID
    );
    let cdh: [u8; 32] = Sha256::digest(cdj.as_bytes()).into();

    let args = GetAssertionArgsBuilder::new(RP_ID, &cdh)
        .credential_id(&cred_id)
        .build();
    let mut assertions = device.get_assertion_with_args(&args).expect("getAssertion");
    let a = assertions.remove(0);
    println!(
        "got assertion: auth_data.len={} sig.len={}",
        a.auth_data.len(),
        a.signature.len()
    );

    // ── Step 6: cross-check — verify via ctap-hid-fido2 too ──────
    let local_ok = verifier::verify_assertion(
        RP_ID,
        &verify.credential_public_key,
        &cdh,
        &a,
    );
    println!("ctap-hid-fido2 verify_assertion: {}", if local_ok { "PASS" } else { "FAIL" });

    // ── Step 7: verify assertion via dds_domain::fido2 ───────────
    let dds_result = dds_domain::fido2::verify_assertion(&a.auth_data, &cdh, &a.signature, &pk);
    match &dds_result {
        Ok(_) => println!("dds_domain    verify_assertion: PASS ✓"),
        Err(e) => println!("dds_domain    verify_assertion: FAIL — {e}"),
    }

    // ── Step 7b: low-level p256 cross-check ─────────────────────
    {
        use ::signature::Verifier;
        let cose_pk_v = match dds_domain::fido2::cose_to_credential_public_key(cose_bytes).unwrap() {
            dds_domain::fido2::CredentialPublicKey::P256(vk) => vk,
            _ => panic!("not P256"),
        };
        let mut signed = Vec::new();
        signed.extend_from_slice(&a.auth_data);
        signed.extend_from_slice(&cdh);
        match p256::ecdsa::Signature::from_der(&a.signature) {
            Ok(sig_raw) => {
                let r1: Result<(), _> = cose_pk_v.verify(&signed, &sig_raw);
                println!("manual p256 verify(from_der, as-is) = {r1:?}");
                if let Some(norm) = sig_raw.normalize_s() {
                    let r2: Result<(), _> = cose_pk_v.verify(&signed, &norm);
                    println!("manual p256 verify(from_der, normalize_s) = {r2:?}");
                } else {
                    println!("manual: signature already low-S (no normalization needed)");
                }
            }
            Err(e) => println!("manual p256 from_der failed: {e}"),
        }
    }

    // ── Diag dump — print the signed blob + signature length ────
    let mut signed = Vec::with_capacity(a.auth_data.len() + cdh.len());
    signed.extend_from_slice(&a.auth_data);
    signed.extend_from_slice(&cdh);
    println!("\n── diagnostic dump ──");
    println!("assertion.auth_data ({} bytes): {}", a.auth_data.len(), hex(&a.auth_data));
    println!("client_data_hash    ({} bytes): {}", cdh.len(), hex(&cdh));
    println!("signed blob         ({} bytes): {}", signed.len(), hex(&signed[..40.min(signed.len())]));
    println!("  (showing first 40 bytes only; full sig verification uses all {} bytes)", signed.len());
    println!("assertion.signature ({} bytes): {}", a.signature.len(), hex(&a.signature));
    // Compare: ctap-hid-fido2's public key PEM vs dds_domain extracted bytes
    println!("\nctap-hid-fido2 cred PK PEM:\n{}", verify.credential_public_key.pem);
    println!("cose_bytes ({} bytes): {}", cose_bytes.len(), hex(cose_bytes));

    if !local_ok && dds_result.is_err() {
        std::process::exit(1);
    }
    if local_ok && dds_result.is_err() {
        eprintln!("\n!! local ctap-hid-fido2 PASSES but dds_domain FAILS — bug in dds_domain::fido2::verify_assertion");
        std::process::exit(2);
    }
    println!("\nALL CHECKS PASSED");
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for c in b { let _ = write!(s, "{c:02x}"); }
    s
}
