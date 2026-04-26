//! Trust graph traversal and chain validation.
//!
//! Walks the Vouchsafe vouch chain from a principal back to a trusted root,
//! validating signatures and checking for revocations at each step.
//! Maximum chain depth is configurable (default: 5).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use subtle::ConstantTimeEq;

use crate::token::{Token, TokenKind};

/// Default maximum trust chain depth.
pub const DEFAULT_MAX_CHAIN_DEPTH: usize = 5;

/// The trust graph: stores tokens and revocations, and validates trust chains.
///
/// Two secondary indices keep query paths sublinear in the total token
/// count: `vouches_by_subject` maps the subject URN of each vouch to the
/// JTIs of vouches that vouch for it, and `attestations_by_iss` maps an
/// issuer URN to the JTIs of its attestation tokens. Without these,
/// `purposes_for` / `walk_chain` / `has_purpose` were O(V) per call and
/// blew the §10 ≤ 1 ms KPI at ~1K vouches in the soak. The indices are
/// maintained alongside `add_token`, `remove_token`, and `sweep_expired`.
#[derive(Debug, Clone)]
pub struct TrustGraph {
    /// All attestation tokens by JTI.
    attestations: BTreeMap<String, Token>,
    /// All vouch tokens by JTI.
    vouches: BTreeMap<String, Token>,
    /// Map of revoked JTI -> issuer URN of the revoker.
    revocations: BTreeMap<String, String>,
    /// Set of burned identity URNs.
    burned: BTreeSet<String>,
    /// Maximum chain depth for trust evaluation.
    max_chain_depth: usize,
    /// Secondary index: subject URN (the `vch_iss` of a vouch) → set of
    /// vouch JTIs that vouch for it. Used by `walk_chain`, `purposes_for`,
    /// and `has_purpose` to avoid scanning every vouch in the graph.
    vouches_by_subject: BTreeMap<String, BTreeSet<String>>,
    /// Secondary index: attestation issuer URN → set of attestation JTIs
    /// for that issuer. Used to look up the target attestation token for
    /// `vch_sum` verification without scanning every attestation.
    attestations_by_iss: BTreeMap<String, BTreeSet<String>>,
}

impl TrustGraph {
    /// Create a new empty trust graph with default max chain depth.
    pub fn new() -> Self {
        Self {
            attestations: BTreeMap::new(),
            vouches: BTreeMap::new(),
            revocations: BTreeMap::new(),
            burned: BTreeSet::new(),
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
            vouches_by_subject: BTreeMap::new(),
            attestations_by_iss: BTreeMap::new(),
        }
    }

    /// Set the maximum chain depth.
    pub fn set_max_chain_depth(&mut self, depth: usize) {
        self.max_chain_depth = depth;
    }

    /// Add a token to the trust graph. Validates structural shape,
    /// signature and issuer binding (but not expiry — expired tokens
    /// are handled during evaluation and sweep).
    ///
    /// **B-2 (security review):** the structural shape check matches
    /// the invariants enforced by `Token::create_with_version`, so a
    /// signed-but-malformed token (e.g. a `Vouch` without
    /// `vch_iss` / `vch_sum`, a `Revoke` without `revokes`, or a
    /// `Revoke` / `Burn` carrying `exp`) is rejected the same way it
    /// would be at construction time.
    pub fn add_token(&mut self, token: Token) -> Result<(), TrustError> {
        token
            .validate_shape()
            .map_err(|e| TrustError::TokenValidation(e.to_string()))?;
        token
            .verify_signature()
            .map_err(|e| TrustError::TokenValidation(e.to_string()))?;
        token
            .verify_issuer_binding()
            .map_err(|e| TrustError::TokenValidation(e.to_string()))?;

        let iss = &token.payload.iss;
        if self.burned.contains(iss) {
            return Err(TrustError::IdentityBurned(iss.clone()));
        }

        match token.payload.kind {
            TokenKind::Attest => {
                let jti = token.payload.jti.clone();
                let iss = token.payload.iss.clone();
                // H-4: refuse duplicate JTIs outright. The previous behaviour
                // silently overwrote the prior token under the same JTI,
                // letting a second enrollment with the same label substitute
                // its own attestation in issuer-keyed lookups.
                if self.attestations.contains_key(&jti) || self.vouches.contains_key(&jti) {
                    return Err(TrustError::DuplicateJti(jti));
                }
                self.attestations.insert(jti.clone(), token);
                self.attestations_by_iss.entry(iss).or_default().insert(jti);
            }
            TokenKind::Vouch => {
                let jti = token.payload.jti.clone();
                if self.vouches.contains_key(&jti) || self.attestations.contains_key(&jti) {
                    return Err(TrustError::DuplicateJti(jti));
                }
                // Vouch::create enforces vch_iss is Some, so this clone
                // is safe — but we tolerate None defensively.
                if let Some(subject) = token.payload.vch_iss.clone() {
                    self.vouches_by_subject
                        .entry(subject)
                        .or_default()
                        .insert(jti.clone());
                }
                self.vouches.insert(jti, token);
            }
            TokenKind::Revoke => {
                if let Some(ref target_jti) = token.payload.revokes {
                    // H-1: only accept revocation if revoker issued the target
                    // token. Refuse revocations of targets we don't know about —
                    // the prior "deferred" path let an attacker pre-publish a
                    // revocation for a predictable JTI and have it activate when
                    // the legitimate token arrived.
                    let revoker_iss = token.payload.iss.clone();
                    let target = self
                        .attestations
                        .get(target_jti)
                        .or_else(|| self.vouches.get(target_jti));
                    match target {
                        Some(t) if t.payload.iss == revoker_iss => {
                            self.revocations.insert(target_jti.clone(), revoker_iss);
                        }
                        Some(_) => {
                            return Err(TrustError::Unauthorized(
                                "revoker is not the issuer of the target token".into(),
                            ));
                        }
                        None => {
                            return Err(TrustError::Unauthorized(
                                "revocation target unknown — refuse to defer (would let \
                                 unauthorized peers seed revocations against future tokens)"
                                    .into(),
                            ));
                        }
                    }
                }
            }
            TokenKind::Burn => {
                // Burn the issuer's identity
                self.burned.insert(iss.clone());
                // Also revoke all tokens issued by this identity
                let iss_owned = iss.clone();
                let to_revoke: Vec<String> = self
                    .vouches
                    .iter()
                    .filter(|(_, t)| t.payload.iss == iss_owned)
                    .map(|(jti, _)| jti.clone())
                    .collect();
                for jti in to_revoke {
                    self.revocations.insert(jti, iss_owned.clone());
                }
            }
        }
        Ok(())
    }

    /// Check if a JTI has been revoked by an authorized revoker.
    /// A revocation is valid if the revoker is the same identity that issued the target token.
    pub fn is_revoked(&self, jti: &str) -> bool {
        if let Some(revoker_iss) = self.revocations.get(jti) {
            // Check if revoker matches issuer of target
            if let Some(target) = self.attestations.get(jti) {
                return target.payload.iss == *revoker_iss;
            }
            if let Some(target) = self.vouches.get(jti) {
                return target.payload.iss == *revoker_iss;
            }
            // Target not found — revocation is pending
            return true;
        }
        false
    }

    /// Check if an identity URN has been burned.
    pub fn is_burned(&self, urn: &str) -> bool {
        self.burned.contains(urn)
    }

    /// Check if a token is expired based on current system time.
    #[cfg(feature = "std")]
    fn is_expired(token: &Token) -> bool {
        if let Some(exp) = token.payload.exp {
            if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                return now.as_secs() > exp;
            }
        }
        false
    }

    #[cfg(not(feature = "std"))]
    fn is_expired(_token: &Token) -> bool {
        false
    }

    /// Sweep expired tokens from the trust graph. Returns the JTIs of removed tokens.
    #[cfg(feature = "std")]
    pub fn sweep_expired(&mut self) -> Vec<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expired_attestations: Vec<String> = self
            .attestations
            .iter()
            .filter(|(_, t)| t.payload.exp.is_some_and(|exp| now > exp))
            .map(|(jti, _)| jti.clone())
            .collect();
        for jti in &expired_attestations {
            if let Some(t) = self.attestations.remove(jti) {
                self.unindex_attestation(&t.payload.iss, jti);
            }
        }

        let expired_vouches: Vec<String> = self
            .vouches
            .iter()
            .filter(|(_, t)| t.payload.exp.is_some_and(|exp| now > exp))
            .map(|(jti, _)| jti.clone())
            .collect();
        for jti in &expired_vouches {
            if let Some(t) = self.vouches.remove(jti) {
                if let Some(ref subject) = t.payload.vch_iss {
                    self.unindex_vouch(subject, jti);
                }
            }
        }

        let mut all_expired = expired_attestations;
        all_expired.extend(expired_vouches);
        all_expired
    }

    /// Validate a trust chain from a subject back to a trusted root.
    ///
    /// Returns `Ok(chain)` with the chain of vouch JTIs from leaf to root,
    /// or an error if no valid chain exists.
    pub fn validate_chain(
        &self,
        subject_urn: &str,
        trusted_roots: &BTreeSet<String>,
    ) -> Result<Vec<String>, TrustError> {
        let mut chain = Vec::new();
        self.walk_chain(subject_urn, trusted_roots, &mut chain, 0)
            .map(|_| chain)
    }

    fn walk_chain(
        &self,
        current_urn: &str,
        trusted_roots: &BTreeSet<String>,
        chain: &mut Vec<String>,
        depth: usize,
    ) -> Result<(), TrustError> {
        if depth > self.max_chain_depth {
            return Err(TrustError::ChainTooDeep(self.max_chain_depth));
        }

        if self.burned.contains(current_urn) {
            return Err(TrustError::IdentityBurned(String::from(current_urn)));
        }

        // If this identity is a trusted root, chain is valid
        if trusted_roots.contains(current_urn) {
            return Ok(());
        }

        // Find vouches that vouch for this identity via the secondary
        // index — O(vouches-for-this-subject) instead of O(total-vouches).
        let vouches_for_current: Vec<&Token> = self
            .vouches_for_subject(current_urn)
            .filter(|t| !self.is_revoked(&t.payload.jti) && !Self::is_expired(t))
            .collect();

        if vouches_for_current.is_empty() {
            return Err(TrustError::NoValidChain);
        }

        // Try each vouch — if any leads to a trusted root, the chain is valid.
        //
        // **B-2 (security review):** require an *active* target
        // attestation for the current URN. `active_attestation_for_iss`
        // skips attestations that are revoked, expired, or whose
        // issuer is burned. When the vouch carries `vch_sum`, the
        // active attestation must hash to that value exactly; when
        // `vch_sum` is absent, any active attestation suffices
        // (legacy compat for vouches predating M-1).
        let mut last_err = TrustError::NoValidChain;
        for vouch in vouches_for_current {
            let target_token =
                self.active_attestation_for_iss(current_urn, vouch.payload.vch_sum.as_deref());

            if let Some(ref expected_hash) = vouch.payload.vch_sum {
                match target_token {
                    Some(target) => {
                        // Defensive: active_attestation_for_iss already
                        // matched the hash; surface a clearer error if
                        // it somehow drifted.
                        let actual_hash = target.payload_hash();
                        if !payload_hash_eq(expected_hash, &actual_hash) {
                            last_err = TrustError::VouchHashMismatch {
                                expected: expected_hash.clone(),
                                got: actual_hash,
                            };
                            continue;
                        }
                    }
                    None => {
                        // No active attestation matches the embedded
                        // hash — either revoked, expired, burned, or
                        // never seen. Skip this vouch.
                        continue;
                    }
                }
            } else if target_token.is_none() {
                // No active attestation at all for this issuer —
                // refuse to grant any purpose through this vouch.
                continue;
            }

            let voucher_urn = &vouch.payload.iss;
            chain.push(vouch.payload.jti.clone());

            match self.walk_chain(voucher_urn, trusted_roots, chain, depth + 1) {
                Ok(()) => return Ok(()),
                Err(e @ TrustError::ChainTooDeep(_)) => return Err(e),
                Err(e @ TrustError::IdentityBurned(_)) => return Err(e),
                Err(e) => {
                    last_err = e;
                    chain.pop(); // backtrack
                }
            }
        }

        Err(last_err)
    }

    /// Iterate over all vouches whose `vch_iss` equals `subject_urn`.
    /// Uses the `vouches_by_subject` index for O(matches) lookup. The
    /// returned iterator silently skips index entries whose underlying
    /// token has been removed (defensive — shouldn't happen if the index
    /// is maintained correctly).
    fn vouches_for_subject<'a>(&'a self, subject_urn: &str) -> impl Iterator<Item = &'a Token> {
        self.vouches_by_subject
            .get(subject_urn)
            .into_iter()
            .flat_map(|jtis| jtis.iter())
            .filter_map(move |jti| self.vouches.get(jti))
    }

    /// Look up an attestation by issuer URN that is **active** —
    /// i.e. not revoked, not expired, and whose issuer is not burned.
    ///
    /// **B-2 (security review):** purpose grants must be tied to a
    /// live target attestation. If the attestation is revoked, the
    /// vouch points at a target the issuer no longer claims;
    /// `purposes_for` / `has_purpose` previously only used the target
    /// for `vch_sum` hash comparison and would still grant the
    /// purpose after the target was revoked or expired. Returns
    /// `None` if no active attestation exists for the issuer; if
    /// multiple active attestations exist, returns the first whose
    /// payload-hash matches `expected_hash`, falling back to the
    /// first active one when `expected_hash` is `None`.
    fn active_attestation_for_iss(&self, iss: &str, expected_hash: Option<&str>) -> Option<&Token> {
        if self.burned.contains(iss) {
            return None;
        }
        let jtis = self.attestations_by_iss.get(iss)?;
        let mut fallback: Option<&Token> = None;
        for jti in jtis {
            let token = match self.attestations.get(jti) {
                Some(t) => t,
                None => continue,
            };
            if self.is_revoked(jti) || Self::is_expired(token) {
                continue;
            }
            match expected_hash {
                Some(expected) => {
                    let actual = token.payload_hash();
                    if payload_hash_eq(expected, &actual) {
                        return Some(token);
                    }
                }
                None => {
                    if fallback.is_none() {
                        fallback = Some(token);
                    }
                }
            }
        }
        // When expected_hash was Some, an exact match is required —
        // do not fall back to the first active attestation.
        if expected_hash.is_some() {
            None
        } else {
            fallback
        }
    }

    /// Check if a subject has a valid trust chain to any trusted root
    /// with a specific purpose.
    ///
    /// **B-2 (security review):** the grant requires a live target
    /// attestation — one that is not revoked, not expired, and whose
    /// issuer is not burned. When the vouch carries `vch_sum`, the
    /// grant additionally requires the target attestation to hash to
    /// exactly that value; the vouch is not allowed to fall back to
    /// "first attestation for issuer" if that attestation does not
    /// match the embedded hash.
    pub fn has_purpose(
        &self,
        subject_urn: &str,
        purpose: &str,
        trusted_roots: &BTreeSet<String>,
    ) -> bool {
        if self.burned.contains(subject_urn) {
            return false;
        }
        self.vouches_for_subject(subject_urn).any(|t| {
            if self.is_revoked(&t.payload.jti)
                || Self::is_expired(t)
                || t.payload.purpose.as_deref() != Some(purpose)
            {
                return false;
            }
            // B-2: a purpose grant requires an active target
            // attestation. When `vch_sum` is set, the active
            // attestation must hash to that value exactly; when
            // `vch_sum` is absent, any active attestation issued by
            // the subject suffices (legacy compat).
            if self
                .active_attestation_for_iss(subject_urn, t.payload.vch_sum.as_deref())
                .is_none()
            {
                return false;
            }
            self.validate_chain(&t.payload.iss, trusted_roots).is_ok()
        })
    }

    /// Get all purposes a subject has been vouched for (by trusted vouchers).
    ///
    /// **B-2 (security review):** see [`has_purpose`] — every grant
    /// in the returned set is backed by a live target attestation.
    pub fn purposes_for(
        &self,
        subject_urn: &str,
        trusted_roots: &BTreeSet<String>,
    ) -> BTreeSet<String> {
        if self.burned.contains(subject_urn) {
            return BTreeSet::new();
        }
        self.vouches_for_subject(subject_urn)
            .filter(|t| {
                if self.is_revoked(&t.payload.jti) || Self::is_expired(t) {
                    return false;
                }
                if self
                    .active_attestation_for_iss(subject_urn, t.payload.vch_sum.as_deref())
                    .is_none()
                {
                    return false;
                }
                self.validate_chain(&t.payload.iss, trusted_roots).is_ok()
            })
            .filter_map(|t| t.payload.purpose.clone())
            .collect()
    }

    /// Remove a token from the trust graph by JTI.
    ///
    /// Returns `true` if a token (attestation or vouch) with the given
    /// JTI was found and removed, `false` otherwise. Also clears any
    /// revocation entry under that JTI. Used by the expiry sweeper to
    /// drop expired tokens. Maintains the secondary indices.
    pub fn remove_token(&mut self, jti: &str) -> bool {
        let mut removed = false;
        if let Some(t) = self.attestations.remove(jti) {
            self.unindex_attestation(&t.payload.iss, jti);
            removed = true;
        }
        if let Some(t) = self.vouches.remove(jti) {
            if let Some(ref subject) = t.payload.vch_iss {
                self.unindex_vouch(subject, jti);
            }
            removed = true;
        }
        if self.revocations.remove(jti).is_some() {
            removed = true;
        }
        removed
    }

    fn unindex_attestation(&mut self, iss: &str, jti: &str) {
        if let Some(set) = self.attestations_by_iss.get_mut(iss) {
            set.remove(jti);
            if set.is_empty() {
                self.attestations_by_iss.remove(iss);
            }
        }
    }

    fn unindex_vouch(&mut self, subject: &str, jti: &str) {
        if let Some(set) = self.vouches_by_subject.get_mut(subject) {
            set.remove(jti);
            if set.is_empty() {
                self.vouches_by_subject.remove(subject);
            }
        }
    }

    /// Iterate over all (jti, exp) tuples for attestations and vouches.
    /// `exp` is `None` if the token has no expiry.
    pub fn token_expiries(&self) -> Vec<(String, Option<u64>)> {
        let mut out = Vec::new();
        for (jti, t) in &self.attestations {
            out.push((jti.clone(), t.payload.exp));
        }
        for (jti, t) in &self.vouches {
            out.push((jti.clone(), t.payload.exp));
        }
        out
    }

    /// Total number of tokens in the trust graph.
    pub fn token_count(&self) -> usize {
        self.attestations.len() + self.vouches.len() + self.revocations.len()
    }

    /// Get the number of attestations.
    pub fn attestation_count(&self) -> usize {
        self.attestations.len()
    }

    /// Get the number of vouches.
    pub fn vouch_count(&self) -> usize {
        self.vouches.len()
    }

    /// Get the number of revoked JTIs.
    pub fn revocation_count(&self) -> usize {
        self.revocations.len()
    }

    /// Get the number of burned identity URNs.
    pub fn burned_count(&self) -> usize {
        self.burned.len()
    }

    /// Iterate over every attestation token currently in the graph.
    /// Order is implementation-defined.
    ///
    /// Used by callers that need to walk all attestations to find
    /// ones embedding a specific domain document type — for example
    /// the Windows policy applier path in `dds-node` walks every
    /// attestation looking for `WindowsPolicyDocument` /
    /// `SoftwareAssignment` bodies scoped to a given device URN.
    /// Hot paths (`purposes_for`, `has_purpose`) still go through
    /// the secondary indices, so adding callers here does not
    /// regress the §10 ≤ 1 ms policy budget.
    pub fn attestations_iter(&self) -> impl Iterator<Item = &Token> + '_ {
        self.attestations.values()
    }
}

impl Default for TrustGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from trust graph operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    /// Token failed validation.
    TokenValidation(String),
    /// The trust chain exceeds the maximum depth.
    ChainTooDeep(usize),
    /// No valid trust chain found to a trusted root.
    NoValidChain,
    /// The identity has been permanently burned.
    IdentityBurned(String),
    /// The operation is not authorized.
    Unauthorized(String),
    /// The vouch hash does not match the target token.
    VouchHashMismatch { expected: String, got: String },
    /// A token with the same JTI is already in the graph.
    DuplicateJti(String),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustError::TokenValidation(e) => write!(f, "token validation failed: {}", e),
            TrustError::ChainTooDeep(max) => {
                write!(f, "trust chain exceeds max depth of {}", max)
            }
            TrustError::NoValidChain => write!(f, "no valid trust chain to a trusted root"),
            TrustError::IdentityBurned(urn) => write!(f, "identity has been burned: {}", urn),
            TrustError::Unauthorized(msg) => write!(f, "unauthorized: {}", msg),
            TrustError::VouchHashMismatch { expected, got } => {
                write!(f, "vouch hash mismatch: expected {}, got {}", expected, got)
            }
            TrustError::DuplicateJti(jti) => {
                write!(f, "duplicate JTI rejected: {}", jti)
            }
        }
    }
}

/// Constant-time equality on hex-encoded payload-hash strings. The hashes
/// themselves are public, but L-15 prefers ct_eq for discipline so future
/// per-comparison timing channels (e.g. early-exit byte loops introduced
/// by an unrelated change) cannot leak even when callers use
/// constant-time-naive comparisons elsewhere.
fn payload_hash_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::token::{Token, TokenKind, TokenPayload};
    use alloc::string::String;
    use rand::rngs::OsRng;

    fn make_attest(ident: &Identity) -> Token {
        let payload = TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: format!("attest-{}", ident.id.label()),
            sub: ident.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: Some(String::from("dds:directory-entry")),
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1000,
            exp: Some(4102444800), // 2100-01-01
            body_type: None,
            body_cbor: None,
        };
        Token::sign(payload, &ident.signing_key).unwrap()
    }

    fn make_vouch(
        voucher: &Identity,
        target: &Identity,
        target_token: &Token,
        purpose: &str,
        jti: &str,
    ) -> Token {
        let payload = TokenPayload {
            iss: voucher.id.to_urn(),
            iss_key: voucher.public_key.clone(),
            jti: String::from(jti),
            sub: target.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some(String::from(purpose)),
            vch_iss: Some(target.id.to_urn()),
            vch_sum: Some(target_token.payload_hash()),
            revokes: None,
            iat: 1000,
            exp: Some(4102444800), // 2100-01-01
            body_type: None,
            body_cbor: None,
        };
        Token::sign(payload, &voucher.signing_key).unwrap()
    }

    fn make_revoke(revoker: &Identity, target_jti: &str) -> Token {
        let payload = TokenPayload {
            iss: revoker.id.to_urn(),
            iss_key: revoker.public_key.clone(),
            jti: format!("revoke-{}", target_jti),
            sub: String::from("revoke-sub"),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: Some(String::from(target_jti)),
            iat: 2000,
            exp: None,
            body_type: None,
            body_cbor: None,
        };
        Token::sign(payload, &revoker.signing_key).unwrap()
    }

    fn make_burn(ident: &Identity) -> Token {
        let payload = TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: format!("burn-{}", ident.id.label()),
            sub: ident.id.to_urn(),
            kind: TokenKind::Burn,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 2000,
            exp: None,
            body_type: None,
            body_cbor: None,
        };
        Token::sign(payload, &ident.signing_key).unwrap()
    }

    fn roots_with(urn: &str) -> BTreeSet<String> {
        let mut set = BTreeSet::new();
        set.insert(String::from(urn));
        set
    }

    fn make_attest_with_exp(ident: &Identity, exp: Option<u64>) -> Token {
        let payload = TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: format!("attest-{}", ident.id.label()),
            sub: ident.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: Some(String::from("dds:directory-entry")),
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1000,
            exp,
            body_type: None,
            body_cbor: None,
        };
        Token::sign(payload, &ident.signing_key).unwrap()
    }

    fn make_vouch_with_exp(
        voucher: &Identity,
        target: &Identity,
        target_token: &Token,
        purpose: &str,
        jti: &str,
        exp: Option<u64>,
    ) -> Token {
        let payload = TokenPayload {
            iss: voucher.id.to_urn(),
            iss_key: voucher.public_key.clone(),
            jti: String::from(jti),
            sub: target.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some(String::from(purpose)),
            vch_iss: Some(target.id.to_urn()),
            vch_sum: Some(target_token.payload_hash()),
            revokes: None,
            iat: 1000,
            exp,
            body_type: None,
            body_cbor: None,
        };
        Token::sign(payload, &voucher.signing_key).unwrap()
    }

    #[test]
    fn test_new_trust_graph() {
        let g = TrustGraph::new();
        assert_eq!(g.attestation_count(), 0);
        assert_eq!(g.vouch_count(), 0);
        assert_eq!(g.revocation_count(), 0);
        assert_eq!(g.burned_count(), 0);
    }

    #[test]
    fn test_add_attestation() {
        let mut g = TrustGraph::new();
        let alice = Identity::generate("alice", &mut OsRng);
        let token = make_attest(&alice);
        g.add_token(token).unwrap();
        assert_eq!(g.attestation_count(), 1);
    }

    #[test]
    fn test_simple_trust_chain() {
        let mut g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let user_token = make_attest(&user);
        let vouch = make_vouch(&root, &user, &user_token, "group:dev", "vouch-1");

        g.add_token(user_token).unwrap();
        g.add_token(vouch).unwrap();

        let roots = roots_with(&root.id.to_urn());
        let chain = g.validate_chain(&user.id.to_urn(), &roots).unwrap();
        assert_eq!(chain, vec!["vouch-1"]);
    }

    #[test]
    fn test_chain_depth_2() {
        let mut g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let admin = Identity::generate("admin", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let admin_token = make_attest(&admin);
        let user_token = make_attest(&user);

        // root vouches for admin
        let v1 = make_vouch(&root, &admin, &admin_token, "admin", "v1");
        // admin vouches for user
        let v2 = make_vouch(&admin, &user, &user_token, "group:dev", "v2");

        g.add_token(admin_token).unwrap();
        g.add_token(user_token).unwrap();
        g.add_token(v1).unwrap();
        g.add_token(v2).unwrap();

        let roots = roots_with(&root.id.to_urn());
        let chain = g.validate_chain(&user.id.to_urn(), &roots).unwrap();
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn test_no_valid_chain() {
        let g = TrustGraph::new();
        let roots = roots_with("urn:vouchsafe:root.fakehash");
        let result = g.validate_chain("urn:vouchsafe:unknown.hash", &roots);
        assert_eq!(result, Err(TrustError::NoValidChain));
    }

    #[test]
    fn test_revocation_breaks_chain() {
        let mut g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let user_token = make_attest(&user);
        let vouch = make_vouch(&root, &user, &user_token, "group:dev", "vouch-1");
        let revoke = make_revoke(&root, "vouch-1");

        g.add_token(user_token).unwrap();
        g.add_token(vouch).unwrap();
        g.add_token(revoke).unwrap();

        let roots = roots_with(&root.id.to_urn());
        let result = g.validate_chain(&user.id.to_urn(), &roots);
        assert_eq!(result, Err(TrustError::NoValidChain));
        assert!(g.is_revoked("vouch-1"));
    }

    #[test]
    fn test_burn_identity() {
        let mut g = TrustGraph::new();
        let user = Identity::generate("user", &mut OsRng);

        let attest = make_attest(&user);
        g.add_token(attest).unwrap();

        let burn = make_burn(&user);
        g.add_token(burn).unwrap();

        assert!(g.is_burned(&user.id.to_urn()));
        assert_eq!(g.burned_count(), 1);
    }

    #[test]
    fn test_burned_identity_cannot_add_tokens() {
        let mut g = TrustGraph::new();
        let user = Identity::generate("user", &mut OsRng);

        let burn = make_burn(&user);
        g.add_token(burn).unwrap();

        let attest = make_attest(&user);
        let result = g.add_token(attest);
        assert!(matches!(result, Err(TrustError::IdentityBurned(_))));
    }

    #[test]
    fn test_burned_identity_breaks_chain() {
        let mut g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let admin = Identity::generate("admin", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let admin_token = make_attest(&admin);
        let user_token = make_attest(&user);
        let v1 = make_vouch(&root, &admin, &admin_token, "admin", "v1");
        let v2 = make_vouch(&admin, &user, &user_token, "group:dev", "v2");

        g.add_token(admin_token).unwrap();
        g.add_token(user_token).unwrap();
        g.add_token(v1).unwrap();
        g.add_token(v2).unwrap();

        // Chain works before burn
        let roots = roots_with(&root.id.to_urn());
        assert!(g.validate_chain(&user.id.to_urn(), &roots).is_ok());

        // Burn admin
        let burn = make_burn(&admin);
        g.add_token(burn).unwrap();

        // Chain is now broken
        let result = g.validate_chain(&user.id.to_urn(), &roots);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_too_deep() {
        let mut g = TrustGraph::new();
        g.set_max_chain_depth(1);

        let root = Identity::generate("root", &mut OsRng);
        let admin = Identity::generate("admin", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let admin_token = make_attest(&admin);
        let user_token = make_attest(&user);
        let v1 = make_vouch(&root, &admin, &admin_token, "admin", "v1");
        let v2 = make_vouch(&admin, &user, &user_token, "group:dev", "v2");

        g.add_token(admin_token).unwrap();
        g.add_token(user_token).unwrap();
        g.add_token(v1).unwrap();
        g.add_token(v2).unwrap();

        let roots = roots_with(&root.id.to_urn());
        let result = g.validate_chain(&user.id.to_urn(), &roots);
        assert_eq!(result, Err(TrustError::ChainTooDeep(1)));
    }

    #[test]
    fn test_has_purpose() {
        let mut g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let user_token = make_attest(&user);
        let vouch = make_vouch(&root, &user, &user_token, "group:backend", "v1");

        g.add_token(user_token).unwrap();
        g.add_token(vouch).unwrap();

        let roots = roots_with(&root.id.to_urn());
        assert!(g.has_purpose(&user.id.to_urn(), "group:backend", &roots));
        assert!(!g.has_purpose(&user.id.to_urn(), "group:frontend", &roots));
    }

    #[test]
    fn test_root_is_trusted() {
        let g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let roots = roots_with(&root.id.to_urn());
        // Root trusts itself
        let chain = g.validate_chain(&root.id.to_urn(), &roots).unwrap();
        assert!(chain.is_empty());
    }

    #[test]
    fn test_trust_error_display() {
        assert!(!format!("{}", TrustError::NoValidChain).is_empty());
        assert!(!format!("{}", TrustError::ChainTooDeep(5)).is_empty());
        assert!(!format!("{}", TrustError::IdentityBurned(String::from("x"))).is_empty());
        assert!(!format!("{}", TrustError::TokenValidation(String::from("bad"))).is_empty());
    }

    #[test]
    fn test_remove_token() {
        let mut g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);
        let user_token = make_attest(&user);
        let vouch = make_vouch(&root, &user, &user_token, "group:dev", "vouch-1");
        g.add_token(user_token).unwrap();
        g.add_token(vouch).unwrap();
        assert_eq!(g.vouch_count(), 1);

        assert!(g.remove_token("vouch-1"));
        assert_eq!(g.vouch_count(), 0);
        // chain no longer validates
        let roots = roots_with(&root.id.to_urn());
        assert!(g.validate_chain(&user.id.to_urn(), &roots).is_err());
        // idempotent
        assert!(!g.remove_token("vouch-1"));
    }

    #[test]
    fn test_token_expiries() {
        let mut g = TrustGraph::new();
        let user = Identity::generate("user", &mut OsRng);
        g.add_token(make_attest(&user)).unwrap();
        let exps = g.token_expiries();
        assert_eq!(exps.len(), 1);
        assert_eq!(exps[0].1, Some(4102444800));
    }

    #[test]
    fn test_default() {
        let g: TrustGraph = TrustGraph::default();
        assert_eq!(g.attestation_count(), 0);
    }

    #[test]
    fn test_unauthorized_revocation_rejected() {
        let mut graph = TrustGraph::new();
        let _root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);
        let attacker = Identity::generate("attacker", &mut OsRng);

        // Add user's attestation (issued by user)
        let attest = make_attest(&user);
        graph.add_token(attest).unwrap();

        // Attacker tries to revoke user's attestation
        let payload = TokenPayload {
            iss: attacker.id.to_urn(),
            iss_key: attacker.public_key.clone(),
            jti: "revoke-attack".into(),
            sub: "revoke-sub".into(),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: Some(format!("attest-{}", user.id.label())),
            iat: 2000,
            exp: None,
            body_type: None,
            body_cbor: None,
        };
        let revoke = Token::sign(payload, &attacker.signing_key).unwrap();
        let result = graph.add_token(revoke);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TrustError::Unauthorized(_)));
    }

    #[test]
    fn test_authorized_revocation_accepted() {
        let mut graph = TrustGraph::new();
        let user = Identity::generate("user", &mut OsRng);

        let attest = make_attest(&user);
        let jti = attest.payload.jti.clone();
        graph.add_token(attest).unwrap();

        // User revokes their own attestation
        let revoke = make_revoke(&user, &jti);
        assert!(graph.add_token(revoke).is_ok());
        assert!(graph.is_revoked(&jti));
    }

    /// H-1 regression: a revocation whose target JTI is unknown to the
    /// graph must be rejected, NOT deferred. Prior behaviour silently
    /// stored the revocation; when the legitimate token arrived later
    /// it was dead-on-arrival.
    #[test]
    fn revocation_for_unknown_target_is_rejected() {
        let mut graph = TrustGraph::new();
        let attacker = Identity::generate("attacker", &mut OsRng);

        // Attacker gossips a revocation for a JTI nobody has issued yet.
        let revoke = make_revoke(&attacker, "attest-victim");
        let err = graph.add_token(revoke).unwrap_err();
        assert!(
            matches!(err, TrustError::Unauthorized(_)),
            "expected Unauthorized, got {err:?}"
        );

        // The legitimate target arriving later must be ingested cleanly
        // and must NOT be marked revoked by the attacker's earlier attempt.
        let victim = Identity::generate("victim", &mut OsRng);
        let attest = make_attest(&victim);
        let jti = attest.payload.jti.clone();
        graph.add_token(attest).unwrap();
        assert!(
            !graph.is_revoked(&jti),
            "victim's token must not be revoked by attacker's pre-emptive revocation"
        );
    }

    /// H-4 regression: two attestations sharing a JTI (e.g. label
    /// collision) must not silently overwrite. The second insertion
    /// must be rejected as a duplicate.
    #[test]
    fn duplicate_attestation_jti_is_rejected() {
        let mut graph = TrustGraph::new();
        // Two distinct identities, but build a manual second token
        // sharing the first's JTI.
        let alice = Identity::generate("alice", &mut OsRng);
        let bob = Identity::generate("bob", &mut OsRng);

        let alice_token = make_attest(&alice);
        let shared_jti = alice_token.payload.jti.clone();
        graph.add_token(alice_token).unwrap();

        let mut bob_payload = TokenPayload {
            iss: bob.id.to_urn(),
            iss_key: bob.public_key.clone(),
            jti: shared_jti.clone(),
            sub: bob.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: Some(String::from("dds:directory-entry")),
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        };
        // Override the synthetic "attest-bob" jti with alice's:
        bob_payload.jti = shared_jti.clone();
        let bob_token = Token::sign(bob_payload, &bob.signing_key).unwrap();

        let err = graph.add_token(bob_token).unwrap_err();
        assert!(
            matches!(&err, TrustError::DuplicateJti(j) if j == &shared_jti),
            "expected DuplicateJti, got {err:?}"
        );
    }

    #[test]
    fn test_vch_sum_mismatch_breaks_chain() {
        let mut graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let attest = make_attest(&user);
        graph.add_token(attest).unwrap();

        // Vouch with WRONG hash
        let payload = TokenPayload {
            iss: root.id.to_urn(),
            iss_key: root.public_key.clone(),
            jti: "vouch-bad-hash".into(),
            sub: user.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: None,
            vch_iss: Some(user.id.to_urn()),
            vch_sum: Some("deadbeef-wrong-hash".into()),
            revokes: None,
            iat: 1000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        };
        let vouch = Token::sign(payload, &root.signing_key).unwrap();
        graph.add_token(vouch).unwrap();

        let roots: BTreeSet<String> = [root.id.to_urn()].into();
        let result = graph.validate_chain(&user.id.to_urn(), &roots);
        assert!(result.is_err());
    }

    #[test]
    fn test_vch_sum_correct_passes_chain() {
        let mut graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let attest = make_attest(&user);
        let correct_hash = attest.payload_hash();
        graph.add_token(attest).unwrap();

        // Vouch with CORRECT hash
        let payload = TokenPayload {
            iss: root.id.to_urn(),
            iss_key: root.public_key.clone(),
            jti: "vouch-good-hash".into(),
            sub: user.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: None,
            vch_iss: Some(user.id.to_urn()),
            vch_sum: Some(correct_hash),
            revokes: None,
            iat: 1000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        };
        let vouch = Token::sign(payload, &root.signing_key).unwrap();
        graph.add_token(vouch).unwrap();

        let roots: BTreeSet<String> = [root.id.to_urn()].into();
        let result = graph.validate_chain(&user.id.to_urn(), &roots);
        assert!(result.is_ok());
    }

    #[test]
    fn test_expired_vouch_ignored_in_walk_chain() {
        let mut graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let attest = make_attest(&user);
        let hash = attest.payload_hash();
        graph.add_token(attest.clone()).unwrap();

        // Vouch with already-expired timestamp
        let payload = TokenPayload {
            iss: root.id.to_urn(),
            iss_key: root.public_key.clone(),
            jti: "vouch-expired".into(),
            sub: user.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: None,
            vch_iss: Some(user.id.to_urn()),
            vch_sum: Some(hash),
            revokes: None,
            iat: 1000,
            exp: Some(1), // epoch second 1 — expired
            body_type: None,
            body_cbor: None,
        };
        let vouch = Token::sign(payload, &root.signing_key).unwrap();
        graph.add_token(vouch).unwrap();

        let roots: BTreeSet<String> = [root.id.to_urn()].into();
        // Should fail because the only vouch is expired
        let result = graph.validate_chain(&user.id.to_urn(), &roots);
        assert!(result.is_err());
    }

    /// **B-2 regression.** A vouch with `vch_sum` set must lose its
    /// purpose grant the moment the target attestation it points at
    /// is revoked. Before B-2, `has_purpose` / `purposes_for` only
    /// used the target attestation for `vch_sum` hash comparison and
    /// happily returned the purpose even after the target was
    /// revoked.
    #[test]
    fn b2_purpose_grant_drops_when_target_attestation_revoked() {
        let mut graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let user_attest = make_attest(&user);
        let user_attest_jti = user_attest.payload.jti.clone();
        let vouch = make_vouch(&root, &user, &user_attest, "group:dev", "vouch-1");

        graph.add_token(user_attest).unwrap();
        graph.add_token(vouch).unwrap();

        let roots = roots_with(&root.id.to_urn());

        // Pre-revoke: the grant exists.
        assert!(graph.has_purpose(&user.id.to_urn(), "group:dev", &roots));
        assert!(
            graph
                .purposes_for(&user.id.to_urn(), &roots)
                .contains("group:dev")
        );

        // Revoke the target attestation (the user's self-issued
        // attestation). The vouch is still present and not directly
        // revoked.
        let revoke = make_revoke(&user, &user_attest_jti);
        graph.add_token(revoke).unwrap();

        assert!(
            !graph.has_purpose(&user.id.to_urn(), "group:dev", &roots),
            "B-2: grant must drop after target attestation revoke"
        );
        assert!(
            !graph
                .purposes_for(&user.id.to_urn(), &roots)
                .contains("group:dev"),
            "B-2: purposes_for must not include the grant after target attestation revoke"
        );
    }

    /// **B-2 regression.** Once the target attestation is burned
    /// (issuer-level retirement), the grant is gone.
    #[test]
    fn b2_purpose_grant_drops_when_subject_burned() {
        let mut graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let user_attest = make_attest(&user);
        let vouch = make_vouch(&root, &user, &user_attest, "group:dev", "vouch-1");

        graph.add_token(user_attest).unwrap();
        graph.add_token(vouch).unwrap();

        let roots = roots_with(&root.id.to_urn());
        assert!(graph.has_purpose(&user.id.to_urn(), "group:dev", &roots));

        graph.add_token(make_burn(&user)).unwrap();

        assert!(
            !graph.has_purpose(&user.id.to_urn(), "group:dev", &roots),
            "B-2: grant must drop after burning the subject identity"
        );
    }

    /// **B-2 regression.** `Token::validate` and `TrustGraph::add_token`
    /// must reject a signed `Vouch` token whose `vch_iss` / `vch_sum`
    /// fields are `None`. Before B-2, only `Token::create` enforced
    /// these — a foreign signer that emitted a CBOR-correct,
    /// signature-valid vouch without the embedded target reference
    /// was accepted.
    #[test]
    fn b2_validate_rejects_vouch_missing_vch_fields() {
        use crate::token::TokenError;
        let voucher = Identity::generate("voucher", &mut OsRng);
        let target = Identity::generate("target", &mut OsRng);

        let payload = TokenPayload {
            iss: voucher.id.to_urn(),
            iss_key: voucher.public_key.clone(),
            jti: String::from("malformed-vouch"),
            sub: target.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some(String::from("group:dev")),
            // Both fields intentionally None — Token::create would
            // reject this; we go through `create_with_version`'s
            // legacy path... but actually that also rejects now. To
            // simulate the foreign-signer attack, build the Token
            // manually by signing without going through the shape
            // gate.
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        };

        // Construction must reject the malformed payload outright.
        let err = Token::sign(payload, &voucher.signing_key).unwrap_err();
        assert!(
            matches!(err, TokenError::VouchMissingFields),
            "Token::sign must refuse malformed Vouch payload, got {err:?}"
        );
    }

    /// **B-2 regression.** Even when `vch_sum` is not set (legacy
    /// vouch), `has_purpose` requires an active target attestation.
    /// Without an attestation for the subject, the grant cannot be
    /// honored — any caller could otherwise vouch for an arbitrary
    /// URN that has no live identity claim.
    #[test]
    fn b2_purpose_grant_requires_target_attestation_even_without_vch_sum() {
        let graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        // A *legacy* vouch path: pre-M-1 producers may have emitted
        // vouches without `vch_sum`. We construct one via direct
        // Token::sign with `vch_iss` set (required by shape) but
        // `vch_sum = None`.
        let payload = TokenPayload {
            iss: root.id.to_urn(),
            iss_key: root.public_key.clone(),
            jti: String::from("legacy-vouch"),
            sub: user.id.to_urn(),
            kind: TokenKind::Vouch,
            purpose: Some(String::from("group:dev")),
            vch_iss: Some(user.id.to_urn()),
            vch_sum: None,
            revokes: None,
            iat: 1000,
            exp: Some(4102444800),
            body_type: None,
            body_cbor: None,
        };
        // Pre-B-2 shape required vch_sum for vouches. We don't have a
        // way to bypass that any longer — confirm the shape gate
        // rejects it (which itself partially closes B-2).
        use crate::token::TokenError;
        let err = Token::sign(payload, &root.signing_key).unwrap_err();
        assert!(
            matches!(err, TokenError::VouchMissingFields),
            "B-2: a vouch missing vch_sum must be rejected at sign time"
        );
        // The trust graph reflects this: with no vouch in the graph,
        // purposes_for is empty.
        let roots = roots_with(&root.id.to_urn());
        assert!(graph.purposes_for(&user.id.to_urn(), &roots).is_empty());
    }

    /// Regression gate for B5 (the 2026-04-09 chaos soak finding):
    /// `purposes_for` and `walk_chain` previously scanned every vouch in
    /// the graph on every call, which made `evaluate_policy` p99 climb
    /// from 0.5 ms (500 vouches) → 10.8 ms (14K vouches) over a 2.5h
    /// soak — well past the §10 ≤ 1 ms KPI.
    ///
    /// This test builds a graph with 10,000 unrelated vouches plus one
    /// real vouch chain, then asserts that `purposes_for` resolves the
    /// real subject in well under the §10 budget. With the secondary
    /// indices the lookup is O(matches-for-subject), independent of the
    /// 10K bystanders. Without the indices, this test fails.
    #[test]
    #[ignore] // Slow in debug mode on CI (~200s for 10K keygen); run with --release or --include-ignored
    fn test_purposes_for_scales_to_10k_vouches() {
        use std::time::Instant;

        let root = Identity::generate("perf-root", &mut OsRng);
        let target = Identity::generate("perf-target", &mut OsRng);
        let target_attest = make_attest(&target);
        let target_urn = target.id.to_urn();
        let real_vouch = make_vouch(
            &root,
            &target,
            &target_attest,
            "perf:resource",
            "vouch-perf-real",
        );

        let mut graph = TrustGraph::new();
        graph.add_token(target_attest).unwrap();
        graph.add_token(real_vouch).unwrap();

        // Insert 10,000 unrelated vouches that target other identities,
        // so the only way to find the real one is via the index. Each
        // bystander has its own (root, target) pair so the chain stays
        // valid for the bystanders too — we don't want to short-circuit
        // on validation errors.
        for i in 0..10_000 {
            let bystand_root = Identity::generate(&format!("br-{i}"), &mut OsRng);
            let bystand_target = Identity::generate(&format!("bt-{i}"), &mut OsRng);
            let bystand_attest = make_attest(&bystand_target);
            let bystand_vouch = make_vouch(
                &bystand_root,
                &bystand_target,
                &bystand_attest,
                "noise:resource",
                &format!("vouch-bystander-{i}"),
            );
            graph.add_token(bystand_attest).unwrap();
            graph.add_token(bystand_vouch).unwrap();
        }
        assert_eq!(graph.vouch_count(), 10_001);

        let roots = roots_with(&root.id.to_urn());

        // Warm up — the first call exercises any lazy state.
        let _ = graph.purposes_for(&target_urn, &roots);

        // Measure: 1000 lookups, take the worst.
        let mut worst = std::time::Duration::ZERO;
        for _ in 0..1000 {
            let t0 = Instant::now();
            let purposes = graph.purposes_for(&target_urn, &roots);
            let dt = t0.elapsed();
            assert!(purposes.contains("perf:resource"));
            if dt > worst {
                worst = dt;
            }
        }

        // §10 budget for the entire local auth decision is 1 ms — give
        // `purposes_for` 0.5 ms of that, leaving headroom for the rest of
        // `evaluate_policy`. With the index this should land in single-
        // digit µs (3 µs on the 2026-04-09 dev host); without it, the
        // chaos soak measured > 10 ms at 14K vouches.
        assert!(
            worst < std::time::Duration::from_micros(500),
            "purposes_for worst-case took {:?} on a 10K-vouch graph — \
             B5 regression: trust graph queries are no longer sublinear",
            worst
        );
    }

    /// **Real-time expiry regression** (closes threat-model-review §8
    /// item 13). `has_purpose` and `purposes_for` must drop an expired
    /// vouch in the same call where it crosses its `exp` — they cannot
    /// rely on the periodic `sweep_expired` having run. The hot paths
    /// already filter via `is_expired()` against system time; this
    /// test pins that contract so a future refactor cannot reintroduce
    /// the sweep-only window. The test never calls `sweep_expired()`.
    #[test]
    fn realtime_expiry_drops_grant_in_has_purpose_and_purposes_for() {
        let mut graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let user_attest = make_attest(&user);
        // Vouch that is already past its `exp` at the moment we add it
        // (epoch second 1 is Jan 1 1970). No sweep call.
        let vouch = make_vouch_with_exp(
            &root,
            &user,
            &user_attest,
            "group:dev",
            "vouch-expired",
            Some(1),
        );

        graph.add_token(user_attest).unwrap();
        graph.add_token(vouch).unwrap();

        let roots = roots_with(&root.id.to_urn());

        assert!(
            !graph.has_purpose(&user.id.to_urn(), "group:dev", &roots),
            "has_purpose must filter expired vouches inline, without waiting for sweep"
        );
        assert!(
            !graph
                .purposes_for(&user.id.to_urn(), &roots)
                .contains("group:dev"),
            "purposes_for must filter expired vouches inline, without waiting for sweep"
        );
        // Validate_chain (the lower-level building block that
        // `has_purpose` ultimately calls into) must agree.
        assert!(
            graph.validate_chain(&user.id.to_urn(), &roots).is_err(),
            "validate_chain must reject a chain whose only vouch is expired"
        );

        // The vouch is still in the graph — it has not been swept. The
        // sweep-vs-evaluate distinction is the whole point of this test.
        assert_eq!(graph.vouch_count(), 1);
    }

    /// **Real-time expiry regression**. The grant must also drop when
    /// the *target attestation* (the one whose hash is pinned in the
    /// vouch's `vch_sum`) is past `exp` — even though the vouch
    /// itself is fresh. `active_attestation_for_iss` filters expired
    /// attestations the same way `walk_chain` filters expired vouches.
    #[test]
    fn realtime_expiry_in_target_attestation_drops_grant() {
        let mut graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        // Target attestation expires at epoch 1 (already past).
        let user_attest = make_attest_with_exp(&user, Some(1));
        // Vouch is fresh (exp 2100-01-01).
        let vouch = make_vouch(&root, &user, &user_attest, "group:dev", "vouch-fresh");

        graph.add_token(user_attest).unwrap();
        graph.add_token(vouch).unwrap();

        let roots = roots_with(&root.id.to_urn());

        assert!(
            !graph.has_purpose(&user.id.to_urn(), "group:dev", &roots),
            "B-2 / real-time expiry: grant must drop when target attestation is expired"
        );
        assert!(
            !graph
                .purposes_for(&user.id.to_urn(), &roots)
                .contains("group:dev"),
            "B-2 / real-time expiry: purposes_for must drop the grant"
        );
        // Sweep was never called.
        assert_eq!(graph.attestation_count(), 1);
    }

    /// **Real-time expiry regression** at chain depth 2: an
    /// intermediate vouch (root → admin) that is expired must break
    /// the chain for the user vouched by that admin, even when the
    /// leaf vouch (admin → user) is still fresh.
    #[test]
    fn realtime_expiry_breaks_chain_at_intermediate_vouch() {
        let mut graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let admin = Identity::generate("admin", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let admin_attest = make_attest(&admin);
        let user_attest = make_attest(&user);

        // Root → admin vouch is *expired* (exp = 1).
        let v1 = make_vouch_with_exp(&root, &admin, &admin_attest, "admin", "v1-expired", Some(1));
        // Admin → user vouch is fresh.
        let v2 = make_vouch(&admin, &user, &user_attest, "group:dev", "v2-fresh");

        graph.add_token(admin_attest).unwrap();
        graph.add_token(user_attest).unwrap();
        graph.add_token(v1).unwrap();
        graph.add_token(v2).unwrap();

        let roots = roots_with(&root.id.to_urn());

        assert!(
            !graph.has_purpose(&user.id.to_urn(), "group:dev", &roots),
            "real-time expiry: an expired intermediate vouch must break the chain"
        );
        assert!(
            graph.validate_chain(&user.id.to_urn(), &roots).is_err(),
            "real-time expiry: validate_chain must surface NoValidChain"
        );

        // Sanity: the structure is correct (the leaf vouch is fresh and
        // would resolve if the intermediate were not expired).
        assert_eq!(graph.vouch_count(), 2);
    }
}
