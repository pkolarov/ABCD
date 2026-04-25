//! Synthetic workload generation: realistic-looking labels, hostnames,
//! orgs, and request builders for the LocalService API.

use dds_domain::fido2::build_none_attestation;
use dds_node::service::{EnrollDeviceRequest, EnrollUserRequest, SessionRequest};
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;

const FIRST_NAMES: &[&str] = &[
    "alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi", "ivan", "judy", "ken",
    "lara", "mallory", "niaj", "olivia", "peggy", "rupert", "sybil", "trent", "uma", "victor",
    "wendy", "xena", "yves", "zoe",
];

const ORGS: &[&str] = &[
    "engineering",
    "sales",
    "support",
    "finance",
    "ops",
    "research",
    "design",
    "legal",
];

const OSES: &[(&str, &str)] = &[
    ("Windows 11", "24H2"),
    ("Windows 10", "22H2"),
    ("macOS", "15.2"),
    ("macOS", "14.6"),
    ("Ubuntu", "24.04"),
    ("Ubuntu", "22.04"),
    ("Fedora", "40"),
];

const TAGS: &[&str] = &[
    "developer",
    "laptop",
    "desktop",
    "server",
    "vm",
    "kiosk",
    "byod",
    "managed",
];

pub struct Synth {
    rng: StdRng,
    seq: u64,
}

impl Synth {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            seq: 0,
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    pub fn user_request(&mut self) -> EnrollUserRequest {
        let n = FIRST_NAMES.choose(&mut self.rng).copied().unwrap_or("user");
        let s = self.next_seq();
        let label = format!("{n}-{s:06}");
        let cred_sk = SigningKey::generate(&mut self.rng);
        let cred_id = format!("cred-{s:08x}");
        let attestation =
            build_none_attestation("dds.local", cred_id.as_bytes(), &cred_sk.verifying_key());
        EnrollUserRequest {
            label,
            credential_id: cred_id,
            attestation_object: attestation,
            client_data_hash: vec![0xAB; 32],
            rp_id: "dds.local".into(),
            display_name: format!("User {s}"),
            authenticator_type: "platform".into(),
            client_data_json: None,
            challenge_id: None,
        }
    }

    pub fn device_request(&mut self) -> EnrollDeviceRequest {
        let s = self.next_seq();
        let (os, ver) = OSES
            .choose(&mut self.rng)
            .copied()
            .unwrap_or(("Linux", "1"));
        let ou = ORGS.choose(&mut self.rng).copied().unwrap_or("ops");
        let tag = TAGS.choose(&mut self.rng).copied().unwrap_or("managed");
        EnrollDeviceRequest {
            label: format!("dev-{s:06}"),
            device_id: format!("HW-{s:010x}"),
            hostname: format!("host-{ou}-{s:05}"),
            os: os.into(),
            os_version: ver.into(),
            tpm_ek_hash: Some(format!("sha256:{s:064x}")),
            org_unit: Some(ou.into()),
            tags: vec![tag.into()],
        }
    }

    pub fn session_request(&mut self, subject_urn: String) -> SessionRequest {
        let _ = self.next_seq();
        SessionRequest {
            subject_urn,
            device_urn: None,
            // Must match the purpose granted by the harness's vouch token,
            // otherwise authorized_resources comes back empty.
            requested_resources: vec!["repo:proj".into()],
            // 5 min — short, so the expiry sweep can keep the graph bounded.
            duration_secs: 300,
            mfa_verified: true,
            tls_binding: None,
        }
    }
}
