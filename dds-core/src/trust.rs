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
    /// Set of revoked JTIs.
    revoked: BTreeSet<String>,
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
            revoked: BTreeSet::new(),
            burned: BTreeSet::new(),
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
        }
    }

    /// Set the maximum chain depth.
    pub fn set_max_chain_depth(&mut self, depth: usize) {
        self.max_chain_depth = depth;
    }

    /// Add a token to the trust graph. Validates the token before adding.
    pub fn add_token(&mut self, token: Token) -> Result<(), TrustError> {
        token.validate().map_err(|e| TrustError::TokenValidation(e.to_string()))?;

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
                    self.revoked.insert(target_jti.clone());
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
                    self.revoked.insert(jti);
                }
            }
        }
        Ok(())
    }

    /// Check if a JTI has been revoked.
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked.contains(jti)
    }

    /// Check if an identity URN has been burned.
    pub fn is_burned(&self, urn: &str) -> bool {
        self.burned.contains(urn)
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
                    && !self.revoked.contains(&t.payload.jti)
            })
            .collect();

        if vouches_for_current.is_empty() {
            return Err(TrustError::NoValidChain);
        }

        // Try each vouch — if any leads to a trusted root, the chain is valid
        let mut last_err = TrustError::NoValidChain;
        for vouch in vouches_for_current {
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
        // Find vouches for this subject with matching purpose
        self.vouches.values().any(|t| {
            t.payload.vch_iss.as_deref() == Some(subject_urn)
                && !self.revoked.contains(&t.payload.jti)
                && t.payload.purpose.as_deref() == Some(purpose)
                && self
                    .validate_chain(&t.payload.iss, trusted_roots)
                    .is_ok()
        })
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
        self.revoked.len()
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
            exp: Some(9999),
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
            exp: Some(9999),
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
        assert!(
            !format!("{}", TrustError::IdentityBurned(String::from("x"))).is_empty()
        );
        assert!(
            !format!("{}", TrustError::TokenValidation(String::from("bad"))).is_empty()
        );
    }

    #[test]
    fn test_default() {
        let g: TrustGraph = TrustGraph::default();
        assert_eq!(g.attestation_count(), 0);
    }
}
