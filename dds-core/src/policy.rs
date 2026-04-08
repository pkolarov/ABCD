//! Policy evaluation engine.
//!
//! Evaluates access control decisions locally using the directory state.
//! Supports allow/deny rules scoped by group membership and purpose.
//!
//! Policy evaluation is a pure computation with no I/O — designed to run
//! on embedded devices in < 0.1ms.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

use crate::trust::TrustGraph;

/// The effect of a policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

/// A single policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Allow or Deny.
    pub effect: Effect,
    /// Required purpose (group membership) for this rule to apply.
    /// e.g., "dds:group:backend-devs"
    pub required_purpose: String,
    /// The resource this rule applies to.
    pub resource: String,
    /// The actions permitted/denied.
    pub actions: Vec<String>,
}

/// The policy engine: evaluates access decisions against the trust graph.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Create a new empty policy engine.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a policy rule.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Get all rules.
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Evaluate whether a subject is allowed to perform an action on a resource.
    ///
    /// Logic:
    /// 1. Collect all matching rules (resource + action match).
    /// 2. For each matching rule, check if the subject has the required purpose
    ///    in the trust graph.
    /// 3. If any **Deny** rule matches and the subject has the purpose → DENY.
    /// 4. If any **Allow** rule matches and the subject has the purpose → ALLOW.
    /// 5. Default: DENY (closed by default).
    pub fn evaluate(
        &self,
        subject_urn: &str,
        resource: &str,
        action: &str,
        trust_graph: &TrustGraph,
        trusted_roots: &BTreeSet<String>,
    ) -> PolicyDecision {
        let matching_rules: Vec<&PolicyRule> = self
            .rules
            .iter()
            .filter(|r| r.resource == resource && r.actions.iter().any(|a| a == action))
            .collect();

        if matching_rules.is_empty() {
            return PolicyDecision::Denied(DenyReason::NoMatchingRule);
        }

        // Check deny rules first (deny takes precedence)
        for rule in &matching_rules {
            if rule.effect == Effect::Deny
                && trust_graph.has_purpose(subject_urn, &rule.required_purpose, trusted_roots)
            {
                return PolicyDecision::Denied(DenyReason::ExplicitDeny(
                    rule.required_purpose.clone(),
                ));
            }
        }

        // Check allow rules
        for rule in &matching_rules {
            if rule.effect == Effect::Allow
                && trust_graph.has_purpose(subject_urn, &rule.required_purpose, trusted_roots)
            {
                return PolicyDecision::Allowed(rule.required_purpose.clone());
            }
        }

        PolicyDecision::Denied(DenyReason::InsufficientPurpose)
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Access allowed, with the purpose that granted it.
    Allowed(String),
    /// Access denied, with the reason.
    Denied(DenyReason),
}

impl PolicyDecision {
    /// Returns `true` if access was allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allowed(_))
    }

    /// Returns `true` if access was denied.
    pub fn is_denied(&self) -> bool {
        matches!(self, PolicyDecision::Denied(_))
    }
}

/// Reason for denying access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// No policy rule matched the resource/action.
    NoMatchingRule,
    /// A deny rule explicitly matched.
    ExplicitDeny(String),
    /// The subject lacks the required purpose (group membership).
    InsufficientPurpose,
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyDecision::Allowed(purpose) => write!(f, "ALLOW ({})", purpose),
            PolicyDecision::Denied(reason) => write!(f, "DENY ({})", reason),
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenyReason::NoMatchingRule => write!(f, "no matching policy rule"),
            DenyReason::ExplicitDeny(purpose) => {
                write!(f, "explicit deny via {}", purpose)
            }
            DenyReason::InsufficientPurpose => {
                write!(f, "insufficient purpose/group membership")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::token::{Token, TokenKind, TokenPayload};
    use crate::trust::TrustGraph;
    use alloc::string::String;
    use rand::rngs::OsRng;

    fn setup_trust_graph() -> (TrustGraph, Identity, Identity, BTreeSet<String>) {
        let mut g = TrustGraph::new();
        let root = Identity::generate("root", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let user_token = Token::sign(
            TokenPayload {
                iss: user.id.to_urn(),
                iss_key: user.public_key.clone(),
                jti: String::from("attest-user"),
                sub: user.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 1000,
                exp: Some(4102444800),
                body_type: None,
                body_cbor: None,
            },
            &user.signing_key,
        )
        .unwrap();

        let vouch = Token::sign(
            TokenPayload {
                iss: root.id.to_urn(),
                iss_key: root.public_key.clone(),
                jti: String::from("vouch-backend"),
                sub: user.id.to_urn(),
                kind: TokenKind::Vouch,
                purpose: Some(String::from("dds:group:backend-devs")),
                vch_iss: Some(user.id.to_urn()),
                vch_sum: Some(user_token.payload_hash()),
                revokes: None,
                iat: 1000,
                exp: Some(4102444800),
                body_type: None,
                body_cbor: None,
            },
            &root.signing_key,
        )
        .unwrap();

        g.add_token(user_token).unwrap();
        g.add_token(vouch).unwrap();

        let mut roots = BTreeSet::new();
        roots.insert(root.id.to_urn());

        (g, root, user, roots)
    }

    #[test]
    fn test_allow_with_matching_purpose() {
        let (graph, _root, user, roots) = setup_trust_graph();
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            effect: Effect::Allow,
            required_purpose: String::from("dds:group:backend-devs"),
            resource: String::from("repo:main-service"),
            actions: vec![String::from("read"), String::from("write")],
        });

        let decision = engine.evaluate(
            &user.id.to_urn(),
            "repo:main-service",
            "read",
            &graph,
            &roots,
        );
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_deny_no_matching_rule() {
        let (graph, _root, user, roots) = setup_trust_graph();
        let engine = PolicyEngine::new(); // no rules

        let decision = engine.evaluate(
            &user.id.to_urn(),
            "repo:main-service",
            "read",
            &graph,
            &roots,
        );
        assert!(decision.is_denied());
        assert_eq!(decision, PolicyDecision::Denied(DenyReason::NoMatchingRule));
    }

    #[test]
    fn test_deny_insufficient_purpose() {
        let (graph, _root, user, roots) = setup_trust_graph();
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            effect: Effect::Allow,
            required_purpose: String::from("dds:group:frontend-devs"), // user doesn't have this
            resource: String::from("repo:main-service"),
            actions: vec![String::from("read")],
        });

        let decision = engine.evaluate(
            &user.id.to_urn(),
            "repo:main-service",
            "read",
            &graph,
            &roots,
        );
        assert_eq!(
            decision,
            PolicyDecision::Denied(DenyReason::InsufficientPurpose)
        );
    }

    #[test]
    fn test_deny_wrong_action() {
        let (graph, _root, user, roots) = setup_trust_graph();
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            effect: Effect::Allow,
            required_purpose: String::from("dds:group:backend-devs"),
            resource: String::from("repo:main-service"),
            actions: vec![String::from("read")], // only read
        });

        let decision = engine.evaluate(
            &user.id.to_urn(),
            "repo:main-service",
            "delete",
            &graph,
            &roots,
        );
        assert_eq!(decision, PolicyDecision::Denied(DenyReason::NoMatchingRule));
    }

    #[test]
    fn test_deny_wrong_resource() {
        let (graph, _root, user, roots) = setup_trust_graph();
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            effect: Effect::Allow,
            required_purpose: String::from("dds:group:backend-devs"),
            resource: String::from("repo:other-service"),
            actions: vec![String::from("read")],
        });

        let decision = engine.evaluate(
            &user.id.to_urn(),
            "repo:main-service",
            "read",
            &graph,
            &roots,
        );
        assert_eq!(decision, PolicyDecision::Denied(DenyReason::NoMatchingRule));
    }

    #[test]
    fn test_explicit_deny_overrides_allow() {
        let (graph, _root, user, roots) = setup_trust_graph();
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            effect: Effect::Allow,
            required_purpose: String::from("dds:group:backend-devs"),
            resource: String::from("repo:main-service"),
            actions: vec![String::from("read")],
        });
        engine.add_rule(PolicyRule {
            effect: Effect::Deny,
            required_purpose: String::from("dds:group:backend-devs"),
            resource: String::from("repo:main-service"),
            actions: vec![String::from("read")],
        });

        let decision = engine.evaluate(
            &user.id.to_urn(),
            "repo:main-service",
            "read",
            &graph,
            &roots,
        );
        assert!(decision.is_denied());
        assert!(matches!(
            decision,
            PolicyDecision::Denied(DenyReason::ExplicitDeny(_))
        ));
    }

    #[test]
    fn test_default_deny() {
        let (graph, _root, _user, roots) = setup_trust_graph();
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            effect: Effect::Allow,
            required_purpose: String::from("dds:group:backend-devs"),
            resource: String::from("repo:main-service"),
            actions: vec![String::from("read")],
        });

        // Unknown user
        let decision = engine.evaluate(
            "urn:vouchsafe:unknown.hash",
            "repo:main-service",
            "read",
            &graph,
            &roots,
        );
        assert!(decision.is_denied());
    }

    #[test]
    fn test_policy_decision_display() {
        let allowed = PolicyDecision::Allowed(String::from("group:a"));
        assert!(format!("{}", allowed).contains("ALLOW"));

        let denied = PolicyDecision::Denied(DenyReason::NoMatchingRule);
        assert!(format!("{}", denied).contains("DENY"));
    }

    #[test]
    fn test_deny_reason_display() {
        assert!(!format!("{}", DenyReason::NoMatchingRule).is_empty());
        assert!(!format!("{}", DenyReason::InsufficientPurpose).is_empty());
        assert!(!format!("{}", DenyReason::ExplicitDeny(String::from("x"))).is_empty());
    }

    #[test]
    fn test_rules_accessor() {
        let mut engine = PolicyEngine::new();
        assert!(engine.rules().is_empty());
        engine.add_rule(PolicyRule {
            effect: Effect::Allow,
            required_purpose: String::from("p"),
            resource: String::from("r"),
            actions: vec![String::from("a")],
        });
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn test_default() {
        let engine: PolicyEngine = PolicyEngine::default();
        assert!(engine.rules().is_empty());
    }
}
