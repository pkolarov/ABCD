# FIDO2 Attestation Allow-List & Upgrade Path

## Supported Attestation Formats

DDS currently accepts two WebAuthn attestation formats during user enrollment
(`POST /v1/enroll/user`):

| Format   | Description | x5c chain | AAGUID checked |
|----------|-------------|-----------|----------------|
| `none`   | No attestation statement. The authenticator provides only the credential public key. Suitable for platform authenticators and soft tokens. | No | No |
| `packed` | Self-attestation only (no x5c certificate chain). The authenticator signs `authData ‖ clientDataHash` with the credential private key. Signature is verified against the extracted COSE public key. | **Skipped** | No |

Unsupported formats (`tpm`, `android-key`, `android-safetynet`, `apple`,
`fido-u2f`) are rejected with a `Fido2Error::Format` error at enrollment time.

## Why Only `none` and `packed` Self-Attestation

1. **Platform coverage**: Windows Hello, macOS Touch ID/Face ID, and most
   roaming FIDO2 keys (YubiKey, Crayonic C-Key, Feitian) emit either `none`
   or `packed` self-attestation by default when the relying party does not
   request direct/enterprise attestation.

2. **No CA trust store required**: Full `packed` with x5c, `tpm`, and
   `android-key` all require maintaining a trusted root certificate store
   (FIDO MDS or vendor-specific). DDS intentionally avoids this dependency
   to keep the trust model self-contained — identity trust flows through
   the vouch chain, not through hardware vendor PKI.

3. **Privacy**: `none` attestation reveals no information about the
   authenticator make/model. This aligns with DDS's design principle
   of minimizing metadata leakage.

## x5c Certificate Chain — Why It Is Skipped

The `packed` attestation handler (`verify_packed` in `dds-domain/src/fido2.rs`)
currently ignores the `x5c` array even if present. Reasons:

- **Self-attestation is sufficient for enrollment**: DDS treats the FIDO2
  credential as a possession factor. The vouch chain provides the trust
  anchor, not the authenticator vendor's certificate.
- **x5c validation requires a FIDO Metadata Service (MDS) trust store**:
  Maintaining an up-to-date MDS blob adds operational complexity and a
  network dependency at enrollment time.
- **Mismatch risk**: If x5c validation were enforced but the MDS blob were
  stale, legitimate authenticators would be rejected — a worse failure mode
  than accepting self-attestation.

## AAGUID Considerations

The Authenticator Attestation GUID (AAGUID) is extracted from the
`authData` but **not validated** against an allow-list. This means:

- Any FIDO2-compliant authenticator can be used for enrollment.
- There is no restriction to specific hardware models.
- Enterprises wanting to restrict enrollment to approved authenticator
  models should implement an AAGUID allow-list (see upgrade path below).

## Upgrade Path

### Phase 1: AAGUID Allow-List (Recommended Near-Term)

Add a `fido2_allowed_aaguids` list to `DomainConfig`:

```toml
[domain]
fido2_allowed_aaguids = [
  "2fc0579f-8113-47ea-b116-bb5a8db9202a",  # YubiKey 5 NFC
  "ee882879-721c-4913-9775-3dfcce97072a",  # Crayonic C-Key
]
```

When non-empty, enrollment rejects any authenticator whose AAGUID is not in
the list. When empty (default), all authenticators are accepted.

Implementation: parse AAGUID from `authData` bytes 37..53 in
`verify_attestation`, return it in `ParsedAttestation`, check against the
config in `LocalService::enroll_user`.

### Phase 2: Full `packed` with x5c Verification

For environments requiring hardware-backed attestation proof:

1. Bundle or fetch the FIDO Alliance MDS blob (JWT-signed, ~2 MB).
2. On enrollment, if `attStmt` contains an `x5c` array:
   - Validate the certificate chain against MDS root certificates.
   - Verify the AAGUID in `authData` matches the leaf certificate's
     AAGUID extension (OID 1.3.6.1.4.1.45724.1.1.4).
   - Verify the attestation signature using the leaf certificate's
     public key (not the credential key).
3. Reject enrollment if chain validation fails.

This is a breaking change for authenticators that only support
self-attestation. Recommend gating behind a `fido2_require_x5c: bool`
config flag.

### Phase 3: TPM Attestation

For Windows devices with TPM 2.0:

1. Parse the `tpm` attestation format per WebAuthn §8.3.
2. Validate the AIK certificate chain against the TPM vendor CA
   (e.g., Microsoft TPM Root Certificate Authority).
3. Verify the `certInfo` (TPMS_ATTEST structure) signature.

TPM attestation provides the strongest hardware binding but requires
the most complex validation. Recommended only for high-assurance
deployments.

## Current Code References

- Attestation parsing & verification: `dds-domain/src/fido2.rs` → `verify_attestation()`
- Enrollment flow: `dds-node/src/service.rs` → `enroll_user()`
- Test builders: `build_none_attestation()`, `build_packed_self_attestation()` in `fido2.rs`
