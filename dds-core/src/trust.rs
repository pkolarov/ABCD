//! Trust graph traversal and chain validation.
//!
//! Walks the Vouchsafe vouch chain from a principal back to a trusted root,
//! validating signatures and checking for revocations at each step.
//! Maximum chain depth is configurable (default: 5).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::token::{Token, TokenKind};

/// Default maximum trust chain depth.
pub const DEFAULT_MAX_CHAIN_DEPTH: usize = 5;

/// The trust graph: stores tokens and revocations, and validates trust chains.
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
        }
    }

    /// Set the maximum chain depth.
    pub fn set_max_chain_depth(&mut self, depth: usize) {
        self.max_chain_depth = depth;
    }

    /// Add a token to the trust graph. Validates signature and issuer binding
    /// (but not expiry — expired tokens are handled during evaluation and sweep).
    pub fn add_token(&mut self, token: Token) -> Result<(), TrustError> {
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
                self.attestations.insert(token.payload.jti.clone(), token);
            }
            TokenKind::Vouch => {
                self.vouches.insert(token.payload.jti.clone(), token);
            }
            TokenKind::Revoke => {
                if let Some(ref target_jti) = token.payload.revokes {
                    // Only accept revocation if revoker issued the target token,
                    // or if target is not yet known (store for deferred check).
                    let revoker_iss = token.payload.iss.clone();
                    let authorized = self
                        .attestations
                        .get(target_jti)
                        .map(|t| t.payload.iss == revoker_iss)
                        .unwrap_or(false)
                        || self
                            .vouches
                            .get(target_jti)
                            .map(|t| t.payload.iss == revoker_iss)
                            .unwrap_or(false);

                    if !authorized {
                        // Check if the target is unknown yet — reject outright
                        let target_known = self.attestations.contains_key(target_jti)
                            || self.vouches.contains_key(target_jti);
                        if target_known {
                            return Err(TrustError::Unauthorized(
                                "revoker is not the issuer of the target token".into(),
                            ));
                        }
                    }

                    self.revocations
                        .insert(target_jti.clone(), revoker_iss);
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
            .filter(|(_, t)| t.payload.exp.map_or(false, |exp| now > exp))
            .map(|(jti, _)| jti.clone())
            .collect();
        for jti in &expired_attestations {
            self.attestations.remove(jti);
        }

        let expired_vouches: Vec<String> = self
            .vouches
            .iter()
            .filter(|(_, t)| t.payload.exp.map_or(false, |exp| now > exp))
            .map(|(jti, _)| jti.clone())
            .collect();
        for jti in &expired_vouches {
            self.vouches.remove(jti);
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

        // Find vouches that vouch for this identity
        let vouches_for_current: Vec<&Token> = self
            .vouches
            .values()
            .filter(|t| {
                t.payload.vch_iss.as_deref() == Some(current_urn)
                    && !self.is_revoked(&t.payload.jti)
                    && !Self::is_expired(t)
            })
            .collect();

        if vouches_for_current.is_empty() {
            return Err(TrustError::NoValidChain);
        }

        // Resolve the target token (attestation of current_urn) for vch_sum verification
        let target_token = self.attestations.values().find(|t| t.payload.iss == current_urn);

        // Try each vouch — if any leads to a trusted root, the chain is valid
        let mut last_err = TrustError::NoValidChain;
        for vouch in vouches_for_current {
            // Enforce vch_sum: if the vouch specifies a hash, it must match the target
            if let Some(ref expected_hash) = vouch.payload.vch_sum {
                if let Some(target) = target_token {
                    let actual_hash = target.payload_hash();
                    if *expected_hash != actual_hash {
                        last_err = TrustError::VouchHashMismatch {
                            expected: expected_hash.clone(),
                            got: actual_hash,
                        };
                        continue;
                    }
                }
                // If target token is unknown, we cannot verify — skip this vouch
                else {
                    continue;
                }
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

    /// Check if a subject has a valid trust chain to any trusted root
    /// with a specific purpose.
    pub fn has_purpose(
        &self,
        subject_urn: &str,
        purpose: &str,
        trusted_roots: &BTreeSet<String>,
    ) -> bool {
        let target_token = self.attestations.values().find(|t| t.payload.iss == subject_urn);

        self.vouches.values().any(|t| {
            if t.payload.vch_iss.as_deref() != Some(subject_urn)
                || self.is_revoked(&t.payload.jti)
                || Self::is_expired(t)
                || t.payload.purpose.as_deref() != Some(purpose)
            {
                return false;
            }
            // Enforce vch_sum
            if let Some(ref expected_hash) = t.payload.vch_sum {
                match target_token {
                    Some(target) => {
                        if target.payload_hash() != *expected_hash {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
            self.validate_chain(&t.payload.iss, trusted_roots).is_ok()
        })
    }

    /// Get all purposes a subject has been vouched for (by trusted vouchers).
    pub fn purposes_for(
        &self,
        subject_urn: &str,
        trusted_roots: &BTreeSet<String>,
    ) -> BTreeSet<String> {
        let target_token = self.attestations.values().find(|t| t.payload.iss == subject_urn);

        self.vouches
            .values()
            .filter(|t| {
                if t.payload.vch_iss.as_deref() != Some(subject_urn)
                    || self.is_revoked(&t.payload.jti)
                    || Self::is_expired(t)
                {
                    return false;
                }
                // Enforce vch_sum
                if let Some(ref expected_hash) = t.payload.vch_sum {
                    match target_token {
                        Some(target) => {
                            if target.payload_hash() != *expected_hash {
                                return false;
                            }
                        }
                        None => return false,
                    }
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
    /// drop expired tokens.
    pub fn remove_token(&mut self, jti: &str) -> bool {
        let mut removed = false;
        if self.attestations.remove(jti).is_some() {
            removed = true;
        }
        if self.vouches.remove(jti).is_some() {
            removed = true;
        }
        if self.revocations.remove(jti).is_some() {
            removed = true;
        }
        removed
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
        }
    }
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

    #[test]
    fn test_new_trust_graph() {
        let g = TrustGraph::new();
        assert_eq!(g.attestation_count(), 0);
        assert_eq!(g.vouch_count(), 0);
        assert_eq!(g.revocation_count(), 0);
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
        let root = Identity::generate("root", &mut OsRng);
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
}
