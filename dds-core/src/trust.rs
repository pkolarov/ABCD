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
    /// Revoked JTI -> `iat` of the revoke (or burn) token that revoked
    /// it. Lets the unanchored-identity pruner date the moment a subject
    /// lost its vouch (single-node review 2026-10-13, R1).
    revoked_at: BTreeMap<String, u64>,
    /// Target JTI → JTIs of the authorized revocation tokens that revoked
    /// it. **Third review round (2026-10-17)**: when a target token leaves
    /// the node (expired, or pruned as unanchored), the revocations that
    /// name it must leave too — a peer that never held the target can
    /// never merge them, so they would be re-served to it every
    /// anti-entropy round forever. This index is how the node finds them.
    revocation_tokens: BTreeMap<String, BTreeSet<String>>,
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
    /// Secondary index: vouch issuer URN → set of vouch JTIs that issuer
    /// signed. Makes `Burn` O(vouches-by-this-issuer) instead of a scan
    /// of every vouch in the graph — an admitted peer can mint burns for
    /// unlimited fresh identities, so the per-burn cost must not grow
    /// with the size of the graph (single-node review 2026-10-13).
    vouches_by_issuer: BTreeMap<String, BTreeSet<String>>,
}

impl TrustGraph {
    /// Create a new empty trust graph with default max chain depth.
    pub fn new() -> Self {
        Self {
            attestations: BTreeMap::new(),
            vouches: BTreeMap::new(),
            revocations: BTreeMap::new(),
            revoked_at: BTreeMap::new(),
            revocation_tokens: BTreeMap::new(),
            burned: BTreeSet::new(),
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
            vouches_by_subject: BTreeMap::new(),
            attestations_by_iss: BTreeMap::new(),
            vouches_by_issuer: BTreeMap::new(),
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
                self.vouches_by_issuer
                    .entry(token.payload.iss.clone())
                    .or_default()
                    .insert(jti.clone());
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
                            self.revoked_at
                                .insert(target_jti.clone(), token.payload.iat);
                            self.revocations.insert(target_jti.clone(), revoker_iss);
                            self.revocation_tokens
                                .entry(target_jti.clone())
                                .or_default()
                                .insert(token.payload.jti.clone());
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
                // Also revoke all vouches issued by this identity. Walk the
                // issuer index rather than every vouch in the graph: burns
                // are self-signed and unlimited, so this path must stay
                // O(k) in the burned identity's own vouch count.
                let iss_owned = iss.clone();
                let to_revoke: Vec<String> = self
                    .vouches_by_issuer
                    .get(&iss_owned)
                    .map(|jtis| jtis.iter().cloned().collect())
                    .unwrap_or_default();
                for jti in to_revoke {
                    self.revoked_at.insert(jti.clone(), token.payload.iat);
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
                self.unindex_vouch_issuer(&t.payload.iss, jti);
            }
        }

        let mut all_expired = expired_attestations;
        all_expired.extend(expired_vouches);
        all_expired
    }

    /// Validate a trust chain from a subject back to a trusted root.
    ///
    /// Returns `Ok(chain)` with the vouch JTIs from the subject's own vouch
    /// up to the vouch issued by the trusted root (leaf → root), or an
    /// error if no valid chain exists within `max_chain_depth` hops.
    ///
    /// **Single-node review 2026-10-13.** This is a breadth-first search
    /// over effective vouches, not the earlier depth-first walk. The DFS
    /// treated `ChainTooDeep` as fatal for the *whole* query the moment
    /// any one branch exceeded the depth cap, and marked a URN "visited"
    /// at whatever depth it was first reached. Any admitted peer can mint
    /// vouches from throw-away identities, so an attacker could attach a
    /// six-hop decoy chain to a legitimately vouched subject (or to one of
    /// its vouchers) with a vouch JTI that sorts first and veto the real
    /// one-hop chain for everyone — a domain-wide lockout of every grant
    /// that passes through a non-root voucher. BFS finds the shortest
    /// chain, so a decoy branch can never shadow a shorter genuine one, and
    /// the first visit of a URN is always at its minimal depth, so the
    /// visited set is correct under the depth bound. Cost is
    /// O(reachable vouches) — the same bound the cycle guard already gave
    /// the DFS (AUDIT-2026-06-11 #30).
    pub fn validate_chain(
        &self,
        subject_urn: &str,
        trusted_roots: &BTreeSet<String>,
    ) -> Result<Vec<String>, TrustError> {
        use alloc::collections::VecDeque;

        if self.burned.contains(subject_urn) {
            return Err(TrustError::IdentityBurned(String::from(subject_urn)));
        }
        // A trusted root needs no chain.
        if trusted_roots.contains(subject_urn) {
            return Ok(Vec::new());
        }

        // `parent` maps each discovered voucher URN to the vouch (JTI)
        // through which it was first reached and the URN that vouch
        // targets, so the chain can be rebuilt once a root is found. It
        // doubles as the visited set.
        let mut parent: BTreeMap<String, (String, String)> = BTreeMap::new();
        let mut queue: VecDeque<(String, usize)> = VecDeque::new();
        queue.push_back((String::from(subject_urn), 0));
        // Set when a branch had further effective vouches past the depth
        // cap, so the caller can tell "no chain at all" from "a chain
        // exists but exceeds `max_chain_depth`".
        let mut truncated = false;

        while let Some((current, depth)) = queue.pop_front() {
            for vouch in self.effective_vouches_for_subject(&current) {
                let voucher = &vouch.payload.iss;
                // A burned voucher's vouches are revoked on burn, so this
                // is only reachable through an ordering race; never follow
                // a burned identity.
                if self.burned.contains(voucher) {
                    continue;
                }
                if depth >= self.max_chain_depth {
                    truncated = true;
                    break;
                }
                if voucher == subject_urn || parent.contains_key(voucher) {
                    // Already reached at an equal or shallower depth.
                    continue;
                }
                parent.insert(
                    voucher.clone(),
                    (vouch.payload.jti.clone(), current.clone()),
                );
                if trusted_roots.contains(voucher) {
                    let mut chain = Vec::new();
                    let mut cursor = voucher.clone();
                    while let Some((jti, target)) = parent.get(&cursor) {
                        chain.push(jti.clone());
                        cursor = target.clone();
                    }
                    chain.reverse();
                    return Ok(chain);
                }
                queue.push_back((voucher.clone(), depth + 1));
            }
        }

        if truncated {
            Err(TrustError::ChainTooDeep(self.max_chain_depth))
        } else {
            Err(TrustError::NoValidChain)
        }
    }

    /// Vouches targeting `subject_urn` that currently count: not revoked,
    /// not expired, and pinning an active attestation the subject issued
    /// (**B-2**: exact `vch_sum` match when present; any active
    /// attestation for legacy vouches without one).
    fn effective_vouches_for_subject<'a>(
        &'a self,
        subject_urn: &'a str,
    ) -> impl Iterator<Item = &'a Token> + 'a {
        self.vouches_for_subject(subject_urn).filter(move |t| {
            !self.is_revoked(&t.payload.jti)
                && !Self::is_expired(t)
                && self
                    .active_attestation_for_iss(subject_urn, t.payload.vch_sum.as_deref())
                    .is_some()
        })
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

    /// Public snapshot of every vouch targeting `subject_urn`, with its
    /// revocation/expiry status. Powers the admin lifecycle surfaces
    /// (offboarding wizard, `/v1/admin/revoke-vouch`): the caller needs
    /// the JTI + issuer of each live vouch to decide which it can
    /// H-1-revoke (issuer == its own admin identity) and which require
    /// a different admin.
    pub fn vouch_summaries_for_subject(&self, subject_urn: &str) -> Vec<VouchSummary> {
        self.vouches_for_subject(subject_urn)
            .map(|t| VouchSummary {
                jti: t.payload.jti.clone(),
                issuer: t.payload.iss.clone(),
                purpose: t.payload.purpose.clone(),
                revoked: self.is_revoked(&t.payload.jti),
                expired: Self::is_expired(t),
            })
            .collect()
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
    /// **AUDIT-2026-06-11 #3** — purposes whose grant is *attenuated*: a vouch
    /// conferring one is honored only if the voucher is a trusted root or
    /// itself holds it. These are the capabilities that confer power — publish
    /// managed policy/software, push self-updates, act as or delegate admin,
    /// claim a device scope. Group memberships (notably `dds:group:*`) are
    /// deliberately NOT attenuated: admins routinely assign users to groups
    /// they are not members of, so groups keep the looser chain-to-root model.
    fn is_privileged_capability(purpose: &str) -> bool {
        use crate::token::purpose as p;
        purpose == p::POLICY_PUBLISHER_WINDOWS
            || purpose == p::POLICY_PUBLISHER_MACOS
            || purpose == p::POLICY_PUBLISHER_LINUX
            || purpose == p::SOFTWARE_PUBLISHER
            || purpose == p::SELF_UPDATE_PUBLISHER
            || purpose == p::ADMIN
            || purpose == p::DEVICE_SCOPE
            || purpose.starts_with("dds:admin-vouch:")
    }

    pub fn has_purpose(
        &self,
        subject_urn: &str,
        purpose: &str,
        trusted_roots: &BTreeSet<String>,
    ) -> bool {
        let mut visited = BTreeSet::new();
        self.has_purpose_inner(subject_urn, purpose, trusted_roots, &mut visited)
    }

    /// Cycle-guarded core of [`has_purpose`]. `visited` accumulates subjects
    /// already being evaluated for this purpose so the privileged-purpose
    /// attenuation recursion (below) can't loop on a `A grants P to B,
    /// B grants P to A` cycle.
    fn has_purpose_inner(
        &self,
        subject_urn: &str,
        purpose: &str,
        trusted_roots: &BTreeSet<String>,
        visited: &mut BTreeSet<String>,
    ) -> bool {
        if self.burned.contains(subject_urn) {
            return false;
        }
        if !visited.insert(subject_urn.to_string()) {
            return false;
        }
        // **AUDIT-2026-06-11 #3**: privileged `dds:` capabilities are
        // *attenuated* — a vouch granting one is honored only if the voucher is
        // a trusted root or itself holds that exact capability. Without this,
        // any identity merely chain-connected to a root (e.g. a plain group
        // member) could mint a `dds:policy-publisher-*` / `dds:dds-self-update-
        // publisher` / `dds:admin-*` vouch and have it honored — a privilege
        // escalation that also inflates the self-update quorum's M. Non-`dds:`
        // purposes (group memberships) keep the looser chain-to-root model:
        // admins routinely assign users to groups they are not members of.
        let privileged = Self::is_privileged_capability(purpose);
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
            if self.validate_chain(&t.payload.iss, trusted_roots).is_err() {
                return false;
            }
            if privileged {
                let voucher = &t.payload.iss;
                if !trusted_roots.contains(voucher)
                    && !self.has_purpose_inner(voucher, purpose, trusted_roots, visited)
                {
                    return false;
                }
            }
            true
        })
    }

    /// Count how many distinct identities hold a valid purpose grant for
    /// `purpose` reachable from a trusted root.
    ///
    /// Used by Phase D.2 to compute M (total self-update-publisher holders)
    /// so the quorum threshold K = max(2, ceil(M/2)) can be derived.
    /// O(V) in the vouch count — acceptable since it is called only on
    /// `DdsSelfUpdateDocument` ingest, not on the hot evaluation path.
    pub fn count_purpose_holders(&self, purpose: &str, trusted_roots: &BTreeSet<String>) -> usize {
        let mut holders: BTreeSet<&str> = BTreeSet::new();
        for vouch in self.vouches.values() {
            if vouch.payload.purpose.as_deref() != Some(purpose) {
                continue;
            }
            let subject = match vouch.payload.vch_iss.as_deref() {
                Some(s) => s,
                None => continue,
            };
            if holders.contains(subject) {
                continue;
            }
            // **AUDIT-2026-06-11 #3**: route through the attenuated `has_purpose`
            // so a privileged capability (e.g. the self-update-publisher count M
            // that sets the K-of-M quorum threshold) can't be inflated by an
            // unauthorized chain member granting the purpose to extra subjects.
            if self.has_purpose(subject, purpose, trusted_roots) {
                holders.insert(subject);
            }
        }
        holders.len()
    }

    /// Get all purposes a subject has been vouched for (by trusted vouchers).
    ///
    /// **B-2 (security review):** see [`has_purpose`] — every grant
    /// in the returned set is backed by a live target attestation.
    /// Shared effectiveness test for a vouch on `subject_urn`: not
    /// revoked, not expired, pins an active attestation the subject
    /// issued (`vch_sum`), chains to a trusted root, and, for a
    /// privileged capability, was granted by a voucher authorized to
    /// grant it. Used by [`Self::purposes_for`] and
    /// [`Self::attestation_is_vouched`] so both agree on which vouches
    /// count.
    fn vouch_is_effective(
        &self,
        t: &Token,
        subject_urn: &str,
        trusted_roots: &BTreeSet<String>,
    ) -> bool {
        if self.is_revoked(&t.payload.jti) || Self::is_expired(t) {
            return false;
        }
        if self
            .active_attestation_for_iss(subject_urn, t.payload.vch_sum.as_deref())
            .is_none()
        {
            return false;
        }
        if self.validate_chain(&t.payload.iss, trusted_roots).is_err() {
            return false;
        }
        // **AUDIT-2026-06-11 #3**: don't surface a privileged capability
        // unless the voucher was authorized to grant it (trusted root or
        // holds it itself), matching `has_purpose`.
        if let Some(p) = t.payload.purpose.as_deref() {
            if Self::is_privileged_capability(p) {
                let voucher = &t.payload.iss;
                if !trusted_roots.contains(voucher) && !self.has_purpose(voucher, p, trusted_roots)
                {
                    return false;
                }
            }
        }
        true
    }

    pub fn purposes_for(
        &self,
        subject_urn: &str,
        trusted_roots: &BTreeSet<String>,
    ) -> BTreeSet<String> {
        if self.burned.contains(subject_urn) {
            return BTreeSet::new();
        }
        self.vouches_for_subject(subject_urn)
            .filter(|t| self.vouch_is_effective(t, subject_urn, trusted_roots))
            .filter_map(|t| t.payload.purpose.clone())
            .collect()
    }

    /// **F1 (2026-09-07 security review).** Whether the attestation with
    /// payload hash `attest_hash` is the one an effective vouch for
    /// `subject_urn` pins through `vch_sum`. The FIDO2 session path uses
    /// this to refuse a credential attestation that is not the enrollment
    /// an administrator actually vouched for, so a second self-issued
    /// attestation under the same URN cannot borrow the vouched one's
    /// grants. Constant-time on the hash comparison, like the rest of the
    /// `vch_sum` handling.
    pub fn attestation_is_vouched(
        &self,
        subject_urn: &str,
        attest_hash: &str,
        trusted_roots: &BTreeSet<String>,
    ) -> bool {
        if self.burned.contains(subject_urn) {
            return false;
        }
        self.vouches_for_subject(subject_urn)
            .filter(|t| self.vouch_is_effective(t, subject_urn, trusted_roots))
            .any(|t| {
                t.payload
                    .vch_sum
                    .as_deref()
                    .map(|pinned| payload_hash_eq(pinned, attest_hash))
                    .unwrap_or(false)
            })
    }

    /// Remove a token from the trust graph by JTI.
    ///
    /// Returns `true` if a token (attestation or vouch) with the given
    /// JTI was found and removed, `false` otherwise. Also clears any
    /// revocation entry under that JTI. Used by the expiry sweeper to
    /// drop expired tokens — an expired token fails validation if it is
    /// ever replayed, so its revocation record has nothing left to
    /// protect. Maintains the secondary indices. For tokens that are
    /// still valid use [`Self::remove_token_keep_revocation`].
    pub fn remove_token(&mut self, jti: &str) -> bool {
        let mut removed = self.remove_token_keep_revocation(jti);
        if self.revocations.remove(jti).is_some() {
            removed = true;
        }
        self.revoked_at.remove(jti);
        self.revocation_tokens.remove(jti);
        removed
    }

    /// JTIs of the authorized revocation tokens that revoked `target`
    /// (normally one; a revoker may have issued more than one).
    pub fn revocation_token_jtis(&self, target: &str) -> Vec<String> {
        self.revocation_tokens
            .get(target)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Drop the revocation-token index entry for `target` once the node
    /// has retired those revocation tokens. The revocation *record*
    /// (`is_revoked` / `has_revocation_record`) is untouched.
    pub fn forget_revocation_tokens(&mut self, target: &str) {
        self.revocation_tokens.remove(target);
    }

    /// Whether some vouch that is neither revoked nor expired pins
    /// `token` through `vch_sum` (any issuer). Such a vouch could make
    /// the token count again if it were replayed somewhere its
    /// revocation is unknown, so the unanchored-identity pruner keeps a
    /// revoked token that is pinned like this — together with its
    /// revocation — instead of removing both. Third review round
    /// (2026-10-17).
    pub fn attestation_is_pinned(&self, token: &Token) -> bool {
        let hash = token.payload_hash();
        self.vouches_for_subject(&token.payload.iss).any(|v| {
            !self.is_revoked(&v.payload.jti)
                && !Self::is_expired(v)
                && v.payload
                    .vch_sum
                    .as_deref()
                    .map(|pinned| payload_hash_eq(pinned, &hash))
                    .unwrap_or(false)
        })
    }

    /// Remove a token like [`Self::remove_token`] but **keep** its
    /// revocation record (`revocations` / `revoked_at`).
    ///
    /// **Follow-up review (2026-10-13), finding 1.** The unanchored-
    /// identity pruner removes tokens that are still *valid*. If it
    /// dropped their revocation records too, a copy of a revoked token
    /// replayed by a lagging or hostile peer after the prune would
    /// re-enter the graph as a live token — the revocation would have
    /// been undone by housekeeping. With the record kept the JTI stays
    /// revoked ([`Self::is_revoked`] treats a record without its target
    /// as a pending revocation, and re-adding the target makes it an
    /// applied one), and the ingest gates refuse the replay outright via
    /// [`Self::has_revocation_record`]. Returns `true` if an attestation
    /// or vouch was removed.
    pub fn remove_token_keep_revocation(&mut self, jti: &str) -> bool {
        let mut removed = false;
        if let Some(t) = self.attestations.remove(jti) {
            self.unindex_attestation(&t.payload.iss, jti);
            removed = true;
        }
        if let Some(t) = self.vouches.remove(jti) {
            if let Some(ref subject) = t.payload.vch_iss {
                self.unindex_vouch(subject, jti);
            }
            self.unindex_vouch_issuer(&t.payload.iss, jti);
            removed = true;
        }
        removed
    }

    /// Whether the graph holds an authorized revocation record for
    /// `jti`, whether or not the target token is (still) present. Unlike
    /// [`Self::is_revoked`] this is a plain lookup with no issuer
    /// re-check, meant for ingest gates that must refuse a token whose
    /// JTI was revoked before it was pruned.
    pub fn has_revocation_record(&self, jti: &str) -> bool {
        self.revocations.contains_key(jti)
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

    fn unindex_vouch_issuer(&mut self, issuer: &str, jti: &str) {
        if let Some(set) = self.vouches_by_issuer.get_mut(issuer) {
            set.remove(jti);
            if set.is_empty() {
                self.vouches_by_issuer.remove(issuer);
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

    /// Iterate over every vouch token currently in the graph. Order is
    /// implementation-defined. Used by the trusted-roots reconciler in
    /// `dds-node` to discover `dds:admin` promotions that arrived via
    /// gossip/sync; deployments have few vouches relative to the hot
    /// paths, and those still go through the secondary indices.
    pub fn vouches_iter(&self) -> impl Iterator<Item = &Token> + '_ {
        self.vouches.values()
    }

    /// Look up a vouch token by its JTI. Used by revocation-ingest
    /// hooks that need to know what a just-revoked target *was*
    /// (e.g. whether it carried the `dds:admin` purpose and therefore
    /// demotes its subject from the trusted roots).
    pub fn vouch_by_jti(&self, jti: &str) -> Option<&Token> {
        self.vouches.get(jti)
    }

    // ---- identity-level queries (single-node review 2026-10-13, R1) ----

    /// Whether the graph holds any token (attestation or vouch) issued by
    /// `urn`. A token from an issuer this returns `false` for is a *fresh
    /// identity* as far as this node is concerned — the unit the
    /// identity-flood budget in `dds-node` counts.
    pub fn knows_issuer(&self, urn: &str) -> bool {
        self.attestations_by_iss.contains_key(urn) || self.vouches_by_issuer.contains_key(urn)
    }

    /// Whether any vouch targets `subject`, live or not. Cheap evidence
    /// that *someone* has claimed the identity; see
    /// [`Self::has_effective_vouch`] for the authoritative check.
    pub fn has_any_vouch_for(&self, subject: &str) -> bool {
        self.vouches_by_subject
            .get(subject)
            .is_some_and(|s| !s.is_empty())
    }

    /// Whether `subject` holds at least one effective vouch (not revoked,
    /// not expired, pinning an active attestation, issued by a voucher
    /// that chains to a trusted root, and — for a privileged capability —
    /// by a voucher authorized to grant it). An identity with an
    /// effective vouch is *anchored*: somebody with a chain to a root has
    /// signed for it, which an attacker holding only self-made identities
    /// cannot produce.
    pub fn has_effective_vouch(&self, subject: &str, trusted_roots: &BTreeSet<String>) -> bool {
        if self.burned.contains(subject) {
            return false;
        }
        self.vouches_for_subject(subject)
            .any(|t| self.vouch_is_effective(t, subject, trusted_roots))
    }

    /// Every issuer URN with at least one attestation or vouch in the
    /// graph.
    pub fn issuers(&self) -> BTreeSet<String> {
        self.attestations_by_iss
            .keys()
            .chain(self.vouches_by_issuer.keys())
            .cloned()
            .collect()
    }

    /// All tokens issued by `urn`: its attestations, then its vouches.
    pub fn tokens_issued_by(&self, urn: &str) -> Vec<&Token> {
        let mut out: Vec<&Token> = Vec::new();
        if let Some(jtis) = self.attestations_by_iss.get(urn) {
            out.extend(jtis.iter().filter_map(|j| self.attestations.get(j)));
        }
        if let Some(jtis) = self.vouches_by_issuer.get(urn) {
            out.extend(jtis.iter().filter_map(|j| self.vouches.get(j)));
        }
        out
    }

    /// `iat` of the revoke/burn token that revoked `jti`, when known.
    pub fn revoked_at(&self, jti: &str) -> Option<u64> {
        self.revoked_at.get(jti).copied()
    }

    /// The moment `urn` last had a claim on the graph other than its own
    /// signature: the later of its **first** own token's `iat` and the
    /// latest vouch evidence for it — the `exp` of an expired vouch, the
    /// revocation time of a revoked vouch, or the `iat` of a live vouch
    /// that is not effective (voucher without a chain). `None` when the
    /// graph holds no token issued by `urn`. The unanchored-identity
    /// pruner removes an identity once `now > unanchored_since + ttl`
    /// and it still has no effective vouch, so a user whose vouch was
    /// revoked or expired is kept for the full grace period after that
    /// event, not after their enrollment.
    ///
    /// **Follow-up review (2026-10-13), finding 3.** The clock used to
    /// start at the identity's *newest* own token, so an identity that
    /// kept issuing never aged and was never pruned. An identity nobody
    /// has ever vouched is judged from its first appearance: it either
    /// gets anchored within the TTL or it goes.
    pub fn unanchored_since(&self, urn: &str) -> Option<u64> {
        let own_first = self
            .tokens_issued_by(urn)
            .iter()
            .map(|t| t.payload.iat)
            .min()?;
        let vouch_evidence = self
            .vouches_for_subject(urn)
            .map(|v| {
                let jti = &v.payload.jti;
                if self.is_revoked(jti) {
                    self.revoked_at(jti).unwrap_or(v.payload.iat)
                } else if Self::is_expired(v) {
                    v.payload.exp.unwrap_or(v.payload.iat)
                } else {
                    v.payload.iat
                }
            })
            .max()
            .unwrap_or(0);
        Some(own_first.max(vouch_evidence))
    }
}

impl Default for TrustGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Status snapshot of one vouch targeting a subject, as returned by
/// [`TrustGraph::vouch_summaries_for_subject`]. `revoked` reflects the
/// graph's H-1-validated revocation set; `expired` is wall-clock expiry
/// (always `false` in `no_std` builds, which have no clock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VouchSummary {
    /// The vouch token's JTI (the revocation target for offboarding).
    pub jti: String,
    /// URN of the admin that issued the vouch. Only this identity can
    /// mint an H-1-valid revocation of it.
    pub issuer: String,
    /// The vouch's purpose (e.g. `dds:session`, `dds:admin`).
    pub purpose: Option<String>,
    /// Whether an authorized revocation for this vouch is in the graph.
    pub revoked: bool,
    /// Whether the vouch is past its `exp`.
    pub expired: bool,
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

    /// `vouch_summaries_for_subject` must report every vouch targeting a
    /// subject with its issuer and revocation status — the input the
    /// offboarding wizard uses to split "vouches I can revoke" (issuer
    /// == me) from "vouches another admin must revoke".
    #[test]
    fn vouch_summaries_report_issuer_and_revocation_status() {
        let admin_a = Identity::generate("admin-a", &mut OsRng);
        let admin_b = Identity::generate("admin-b", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);
        let user_attest = make_attest(&user);

        let mut g = TrustGraph::new();
        g.add_token(make_attest(&admin_a)).unwrap();
        g.add_token(make_attest(&admin_b)).unwrap();
        g.add_token(user_attest.clone()).unwrap();
        // Two admins each vouch the same user for dds:session.
        let v_a = make_vouch(&admin_a, &user, &user_attest, "dds:session", "vouch-a");
        let v_b = make_vouch(&admin_b, &user, &user_attest, "dds:session", "vouch-b");
        g.add_token(v_a).unwrap();
        g.add_token(v_b).unwrap();
        // admin_a revokes its own vouch.
        g.add_token(make_revoke(&admin_a, "vouch-a")).unwrap();

        let summaries = g.vouch_summaries_for_subject(&user.id.to_urn());
        assert_eq!(summaries.len(), 2, "both vouches must be reported");
        let a = summaries.iter().find(|s| s.jti == "vouch-a").unwrap();
        assert_eq!(a.issuer, admin_a.id.to_urn());
        assert!(a.revoked, "admin_a's vouch is revoked");
        let b = summaries.iter().find(|s| s.jti == "vouch-b").unwrap();
        assert_eq!(b.issuer, admin_b.id.to_urn());
        assert!(!b.revoked, "admin_b's vouch is still live");
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

    /// **Single-node review 2026-10-13.** A decoy chain deeper than
    /// `max_chain_depth`, attached to a legitimately vouched subject with a
    /// vouch JTI that sorts before the genuine one, must not veto the
    /// genuine one-hop chain. The old depth-first walk returned
    /// `ChainTooDeep` for the whole query as soon as the decoy branch hit
    /// the cap, so any admitted peer could lock out every subject (or every
    /// grant through any non-root voucher) with six throw-away identities.
    #[test]
    fn deep_decoy_chain_cannot_veto_direct_root_vouch() {
        let mut g = TrustGraph::new(); // default depth 5
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);
        let user_token = make_attest(&user);
        g.add_token(user_token.clone()).unwrap();
        // Genuine: root vouches the user directly. JTI chosen to sort LAST.
        g.add_token(make_vouch(
            &root,
            &user,
            &user_token,
            "group:dev",
            "zz-legit",
        ))
        .unwrap();

        // Decoy: b1 -> b2 -> ... -> b6 -> user, six hops, nobody at the
        // top is a root. Every identity is throw-away.
        let decoys: Vec<Identity> = (0..6)
            .map(|i| Identity::generate(&format!("decoy{i}"), &mut OsRng))
            .collect();
        for d in &decoys {
            g.add_token(make_attest(d)).unwrap();
        }
        // b6 vouches the user with a JTI that sorts FIRST ("!" < "z").
        let b6_attest = make_attest(&decoys[5]);
        g.add_token(make_vouch(
            &decoys[5],
            &user,
            &user_token,
            "group:dev",
            "!decoy-6",
        ))
        .unwrap();
        let _ = b6_attest;
        // b(i) vouches b(i+1) up the chain.
        for i in (0..5).rev() {
            let target = &decoys[i + 1];
            let target_attest = make_attest(target);
            g.add_token(make_vouch(
                &decoys[i],
                target,
                &target_attest,
                "group:dev",
                &format!("!decoy-{i}"),
            ))
            .unwrap();
        }

        let roots = roots_with(&root.id.to_urn());
        assert_eq!(
            g.validate_chain(&user.id.to_urn(), &roots),
            Ok(vec![String::from("zz-legit")]),
            "the genuine one-hop chain must win over the deep decoy"
        );
        assert!(g.has_purpose(&user.id.to_urn(), "group:dev", &roots));

        // Sanity: with the genuine vouch gone, the decoy alone is not a
        // chain (too deep / no root at the top).
        assert!(g.remove_token("zz-legit"));
        assert!(g.validate_chain(&user.id.to_urn(), &roots).is_err());
    }

    /// **Single-node review 2026-10-13.** A legitimate intermediate voucher
    /// reached first through a deep decoy path must still be explored at
    /// its real (shallow) depth. The DFS marked it visited at the deep
    /// depth, hit the cap one hop later, and failed the whole query.
    #[test]
    fn intermediate_reached_via_decoy_is_still_found_at_its_real_depth() {
        let mut g = TrustGraph::new(); // default depth 5
        let root = Identity::generate("root", &mut OsRng);
        let mid = Identity::generate("mid", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);
        let mid_attest = make_attest(&mid);
        let user_attest = make_attest(&user);
        g.add_token(mid_attest.clone()).unwrap();
        g.add_token(user_attest.clone()).unwrap();
        // Genuine 2-hop chain: root -> mid -> user (JTIs sort last).
        g.add_token(make_vouch(
            &root,
            &mid,
            &mid_attest,
            "group:dev",
            "zz-root-mid",
        ))
        .unwrap();
        g.add_token(make_vouch(
            &mid,
            &user,
            &user_attest,
            "group:dev",
            "zz-mid-user",
        ))
        .unwrap();
        // Decoy: mid -> b1 -> b2 -> b3 -> b4 -> user. `mid` sits at depth
        // 5 on this path, so root would be at depth 6 (> 5).
        let decoys: Vec<Identity> = (0..4)
            .map(|i| Identity::generate(&format!("decoy{i}"), &mut OsRng))
            .collect();
        for d in &decoys {
            g.add_token(make_attest(d)).unwrap();
        }
        g.add_token(make_vouch(
            &decoys[3],
            &user,
            &user_attest,
            "group:dev",
            "!d3-user",
        ))
        .unwrap();
        for i in (0..3).rev() {
            let t = make_attest(&decoys[i + 1]);
            g.add_token(make_vouch(
                &decoys[i],
                &decoys[i + 1],
                &t,
                "group:dev",
                &format!("!d{i}"),
            ))
            .unwrap();
        }
        let d0 = make_attest(&decoys[0]);
        g.add_token(make_vouch(&mid, &decoys[0], &d0, "group:dev", "!mid-d0"))
            .unwrap();

        let roots = roots_with(&root.id.to_urn());
        assert_eq!(
            g.validate_chain(&user.id.to_urn(), &roots),
            Ok(vec![
                String::from("zz-mid-user"),
                String::from("zz-root-mid")
            ]),
        );
    }

    /// **R1 (single-node review 2026-10-13).** Identity-level queries the
    /// unanchored-identity pruner and the fresh-identity budget rely on.
    #[test]
    fn identity_queries_report_anchoring_and_unanchored_since() {
        let mut g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);
        let nobody = Identity::generate("nobody", &mut OsRng);
        let roots = roots_with(&root.id.to_urn());

        assert!(!g.knows_issuer(&user.id.to_urn()));
        assert_eq!(g.unanchored_since(&user.id.to_urn()), None);

        let user_attest = make_attest(&user); // iat 1000
        g.add_token(user_attest.clone()).unwrap();
        assert!(g.knows_issuer(&user.id.to_urn()));
        assert!(!g.has_any_vouch_for(&user.id.to_urn()));
        assert!(!g.has_effective_vouch(&user.id.to_urn(), &roots));
        assert_eq!(g.unanchored_since(&user.id.to_urn()), Some(1000));
        assert!(g.issuers().contains(&user.id.to_urn()));

        // A vouch from a non-root nobody claims the identity but does not
        // anchor it; it only moves `unanchored_since` to its own iat.
        g.add_token(make_attest(&nobody)).unwrap();
        g.add_token(make_vouch(
            &nobody,
            &user,
            &user_attest,
            "group:x",
            "v-nobody",
        ))
        .unwrap();
        assert!(g.has_any_vouch_for(&user.id.to_urn()));
        assert!(!g.has_effective_vouch(&user.id.to_urn(), &roots));
        assert_eq!(g.unanchored_since(&user.id.to_urn()), Some(1000));

        // A root vouch anchors.
        g.add_token(make_vouch(&root, &user, &user_attest, "group:x", "v-root"))
            .unwrap();
        assert!(g.has_effective_vouch(&user.id.to_urn(), &roots));

        // Revoking it (revoke iat 2000, from `make_revoke`) un-anchors and
        // dates the loss of the vouch at the revocation, not at enrollment.
        g.add_token(make_revoke(&root, "v-root")).unwrap();
        assert!(!g.has_effective_vouch(&user.id.to_urn(), &roots));
        assert_eq!(g.revoked_at("v-root"), Some(2000));
        assert_eq!(g.unanchored_since(&user.id.to_urn()), Some(2000));
        assert_eq!(g.tokens_issued_by(&user.id.to_urn()).len(), 1);
    }

    /// **Follow-up review (2026-10-13), findings 1 and 3.** The unanchored
    /// clock starts at an identity's FIRST own token, so issuing more
    /// tokens cannot postpone pruning; and removing a token with
    /// `remove_token_keep_revocation` leaves its JTI revoked, so a
    /// replayed copy comes back revoked instead of live.
    #[test]
    fn unanchored_clock_uses_first_own_token_and_prune_keeps_revocations() {
        let mut g = TrustGraph::new();
        let user = Identity::generate("user", &mut OsRng);
        let roots = roots_with("urn:dds:nobody");

        let first = make_attest(&user); // iat 1000
        let later = Token::sign(
            TokenPayload {
                iss: user.id.to_urn(),
                iss_key: user.public_key.clone(),
                jti: String::from("attest-user-later"),
                sub: user.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: Some(String::from("test")),
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 9000,
                exp: None,
                body_type: None,
                body_cbor: None,
            },
            &user.signing_key,
        )
        .unwrap();
        let first_jti = first.payload.jti.clone();
        g.add_token(first.clone()).unwrap();
        g.add_token(later).unwrap();
        assert_eq!(
            g.unanchored_since(&user.id.to_urn()),
            Some(1000),
            "a newer own token must not reset the unanchored clock"
        );

        // The user revokes its first attestation (authorized: same issuer).
        g.add_token(make_revoke(&user, &first_jti)).unwrap();
        assert!(g.is_revoked(&first_jti));

        // Pruned, but the revocation record stays.
        assert!(g.remove_token_keep_revocation(&first_jti));
        assert!(!g.remove_token_keep_revocation(&first_jti));
        assert!(g.has_revocation_record(&first_jti));
        assert!(
            g.is_revoked(&first_jti),
            "pending revocation survives the prune"
        );
        assert!(!g.has_purpose(&user.id.to_urn(), "test", &roots));

        // A replayed copy re-enters revoked, never live.
        g.add_token(first).unwrap();
        assert!(g.is_revoked(&first_jti));
        assert!(g.has_revocation_record(&first_jti));

        // `remove_token` (expiry sweeper) is the one that drops the record.
        assert!(g.remove_token(&first_jti));
        assert!(!g.has_revocation_record(&first_jti));
        assert!(!g.is_revoked(&first_jti));
    }

    /// A burn revokes exactly the burned identity's own vouches (served from
    /// the issuer index), leaving another voucher's chain intact.
    #[test]
    fn burn_revokes_only_the_burned_issuers_vouches() {
        let mut g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let other = Identity::generate("other", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);
        let other_attest = make_attest(&other);
        let user_attest = make_attest(&user);
        g.add_token(other_attest.clone()).unwrap();
        g.add_token(user_attest.clone()).unwrap();
        g.add_token(make_vouch(
            &root,
            &other,
            &other_attest,
            "admin",
            "v-root-other",
        ))
        .unwrap();
        g.add_token(make_vouch(
            &other,
            &user,
            &user_attest,
            "group:dev",
            "v-other-user",
        ))
        .unwrap();
        g.add_token(make_vouch(
            &root,
            &user,
            &user_attest,
            "group:dev",
            "v-root-user",
        ))
        .unwrap();
        g.add_token(make_burn(&other)).unwrap();
        assert!(g.is_revoked("v-other-user"));
        assert!(!g.is_revoked("v-root-user"));
        assert!(!g.is_revoked("v-root-other"));
        let roots = roots_with(&root.id.to_urn());
        assert_eq!(
            g.validate_chain(&user.id.to_urn(), &roots),
            Ok(vec![String::from("v-root-user")])
        );
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

    /// AUDIT-2026-06-11 #3 — a chain-connected identity that does NOT hold a
    /// privileged `dds:` capability cannot grant it. (A plain group member
    /// must not be able to mint a self-update-publisher capability.)
    #[test]
    fn privileged_purpose_requires_authorized_voucher() {
        let mut g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let admin = Identity::generate("admin", &mut OsRng); // holds only a group
        let target = Identity::generate("target", &mut OsRng);
        const CAP: &str = "dds:dds-self-update-publisher";

        let admin_token = make_attest(&admin);
        let target_token = make_attest(&target);
        // root → admin for a GROUP (not the capability)
        let v1 = make_vouch(&root, &admin, &admin_token, "group:ops", "v1");
        // admin → target for the privileged capability (admin does not hold it)
        let v2 = make_vouch(&admin, &target, &target_token, CAP, "v2");
        g.add_token(admin_token).unwrap();
        g.add_token(target_token).unwrap();
        g.add_token(v1).unwrap();
        g.add_token(v2).unwrap();

        let roots = roots_with(&root.id.to_urn());
        assert!(
            !g.has_purpose(&target.id.to_urn(), CAP, &roots),
            "unauthorized voucher must not be able to grant a dds: capability"
        );
        assert_eq!(g.count_purpose_holders(CAP, &roots), 0);
        assert!(!g.purposes_for(&target.id.to_urn(), &roots).contains(CAP));
        // The non-privileged group purpose still resolves through the chain.
        assert!(g.has_purpose(&admin.id.to_urn(), "group:ops", &roots));
    }

    /// AUDIT-2026-06-11 #3 — attenuated delegation IS honored: root grants the
    /// capability to admin, admin (now a holder) delegates to a second
    /// publisher. Both count toward `count_purpose_holders` (the quorum M).
    #[test]
    fn privileged_purpose_attenuated_delegation_is_honored() {
        let mut g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let admin = Identity::generate("admin", &mut OsRng);
        let pub2 = Identity::generate("pub2", &mut OsRng);
        const CAP: &str = "dds:dds-self-update-publisher";

        let admin_token = make_attest(&admin);
        let pub2_token = make_attest(&pub2);
        let v1 = make_vouch(&root, &admin, &admin_token, CAP, "v1");
        let v2 = make_vouch(&admin, &pub2, &pub2_token, CAP, "v2");
        g.add_token(admin_token).unwrap();
        g.add_token(pub2_token).unwrap();
        g.add_token(v1).unwrap();
        g.add_token(v2).unwrap();

        let roots = roots_with(&root.id.to_urn());
        assert!(g.has_purpose(&admin.id.to_urn(), CAP, &roots));
        assert!(
            g.has_purpose(&pub2.id.to_urn(), CAP, &roots),
            "a holder may delegate a dds: capability it itself holds"
        );
        assert_eq!(g.count_purpose_holders(CAP, &roots), 2);
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

    /// Phase D.2 — `count_purpose_holders` returns 0 for an empty graph.
    #[test]
    fn count_purpose_holders_empty_graph() {
        let graph = TrustGraph::new();
        let roots: BTreeSet<String> = BTreeSet::new();
        assert_eq!(
            graph.count_purpose_holders("dds:dds-self-update-publisher", &roots),
            0
        );
    }

    /// Phase D.2 — `count_purpose_holders` returns 1 when exactly one
    /// identity has been granted the purpose by a trusted root.
    #[test]
    fn count_purpose_holders_one_holder() {
        let mut graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let admin = Identity::generate("admin", &mut OsRng);
        let admin_attest = make_attest(&admin);
        let vouch = make_vouch(
            &root,
            &admin,
            &admin_attest,
            "dds:dds-self-update-publisher",
            "vouch-admin1",
        );
        graph.add_token(admin_attest).unwrap();
        graph.add_token(vouch).unwrap();
        let roots = roots_with(&root.id.to_urn());
        assert_eq!(
            graph.count_purpose_holders("dds:dds-self-update-publisher", &roots),
            1
        );
    }

    /// Phase D.2 — `count_purpose_holders` returns 2 when two distinct
    /// admins each hold the purpose.
    #[test]
    fn count_purpose_holders_two_holders() {
        let mut graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let admin1 = Identity::generate("admin1", &mut OsRng);
        let admin2 = Identity::generate("admin2", &mut OsRng);
        let a1_attest = make_attest(&admin1);
        let a2_attest = make_attest(&admin2);
        let v1 = make_vouch(
            &root,
            &admin1,
            &a1_attest,
            "dds:dds-self-update-publisher",
            "vouch-admin1",
        );
        let v2 = make_vouch(
            &root,
            &admin2,
            &a2_attest,
            "dds:dds-self-update-publisher",
            "vouch-admin2",
        );
        graph.add_token(a1_attest).unwrap();
        graph.add_token(a2_attest).unwrap();
        graph.add_token(v1).unwrap();
        graph.add_token(v2).unwrap();
        let roots = roots_with(&root.id.to_urn());
        assert_eq!(
            graph.count_purpose_holders("dds:dds-self-update-publisher", &roots),
            2
        );
    }

    /// Phase D.2 — an identity vouched by an untrusted root does not
    /// count as a holder.
    #[test]
    fn count_purpose_holders_untrusted_root_not_counted() {
        let mut graph = TrustGraph::new();
        let untrusted_root = Identity::generate("rogue-root", &mut OsRng);
        let admin = Identity::generate("admin", &mut OsRng);
        let admin_attest = make_attest(&admin);
        let vouch = make_vouch(
            &untrusted_root,
            &admin,
            &admin_attest,
            "dds:dds-self-update-publisher",
            "vouch-admin",
        );
        graph.add_token(admin_attest).unwrap();
        graph.add_token(vouch).unwrap();
        // Trusted roots is empty — untrusted_root is not in it.
        let roots: BTreeSet<String> = BTreeSet::new();
        assert_eq!(
            graph.count_purpose_holders("dds:dds-self-update-publisher", &roots),
            0
        );
    }

    /// Phase D.2 — a revoked vouch does not count toward the holder total.
    #[test]
    fn count_purpose_holders_revoked_vouch_not_counted() {
        let mut graph = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let admin = Identity::generate("admin", &mut OsRng);
        let admin_attest = make_attest(&admin);
        let vouch = make_vouch(
            &root,
            &admin,
            &admin_attest,
            "dds:dds-self-update-publisher",
            "vouch-to-revoke",
        );
        graph.add_token(admin_attest).unwrap();
        graph.add_token(vouch.clone()).unwrap();
        // Root revokes its own vouch.
        let revoke_payload = TokenPayload {
            iss: root.id.to_urn(),
            iss_key: root.public_key.clone(),
            jti: "revoke-vouch".to_string(),
            sub: root.id.to_urn(),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: Some(vouch.payload.jti.clone()),
            iat: 1000,
            exp: None,
            body_type: None,
            body_cbor: None,
        };
        let revoke = Token::sign(revoke_payload, &root.signing_key).unwrap();
        graph.add_token(revoke).unwrap();
        let roots = roots_with(&root.id.to_urn());
        assert_eq!(
            graph.count_purpose_holders("dds:dds-self-update-publisher", &roots),
            0,
            "revoked vouch must not count toward holder total"
        );
    }

    #[test]
    fn attestation_is_vouched_only_for_the_pinned_enrollment() {
        // F1 (2026-09-07 review): a vouch pins one attestation by hash; a
        // second self-issued attestation under the same URN must not count
        // as vouched, and a revoked vouch withdraws the pinning.
        let root = Identity::generate("root", &mut OsRng);
        let alice = Identity::generate("alice", &mut OsRng);
        let mut g = TrustGraph::new();
        g.add_token(make_attest(&root)).unwrap();
        let pinned = make_attest(&alice);
        let pinned_hash = pinned.payload_hash();
        g.add_token(pinned.clone()).unwrap();
        let other = Token::sign(
            TokenPayload {
                iss: alice.id.to_urn(),
                iss_key: alice.public_key.clone(),
                jti: "attest-alice-second".into(),
                sub: alice.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 1000,
                exp: None,
                body_type: None,
                body_cbor: None,
            },
            &alice.signing_key,
        )
        .unwrap();
        let other_hash = other.payload_hash();
        g.add_token(other).unwrap();
        let roots = roots_with(&root.id.to_urn());

        assert!(
            !g.attestation_is_vouched(&alice.id.to_urn(), &pinned_hash, &roots),
            "no vouch yet: nothing is vouched"
        );
        g.add_token(make_vouch(
            &root,
            &alice,
            &pinned,
            "dds:session",
            "vouch-alice",
        ))
        .unwrap();
        assert!(g.attestation_is_vouched(&alice.id.to_urn(), &pinned_hash, &roots));
        assert!(
            !g.attestation_is_vouched(&alice.id.to_urn(), &other_hash, &roots),
            "an attestation no vouch pins must not be treated as vouched"
        );
        assert!(!g.attestation_is_vouched("urn:vouchsafe:nobody", &pinned_hash, &roots));

        g.add_token(make_revoke(&root, "vouch-alice")).unwrap();
        assert!(
            !g.attestation_is_vouched(&alice.id.to_urn(), &pinned_hash, &roots),
            "a revoked vouch no longer pins the enrollment"
        );
        assert!(g.purposes_for(&alice.id.to_urn(), &roots).is_empty());
    }
}
