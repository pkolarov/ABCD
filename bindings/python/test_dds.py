"""
DDS Python binding tests — run against the compiled shared library.

Prerequisites:
    cargo build -p dds-ffi --release

Run:
    cd bindings/python && python -m pytest test_dds.py -v
"""

import os
import sys
import pytest

# Add parent for import resolution
sys.path.insert(0, os.path.dirname(__file__))

from dds import DDS, DDSError


@pytest.fixture(scope="session")
def client():
    """Load the DDS shared library."""
    # Look for library relative to workspace root
    workspace = os.path.join(os.path.dirname(__file__), "..", "..")
    lib_candidates = [
        os.path.join(workspace, "target", "release", "libdds_ffi.dylib"),
        os.path.join(workspace, "target", "release", "libdds_ffi.so"),
        os.path.join(workspace, "target", "debug", "libdds_ffi.dylib"),
        os.path.join(workspace, "target", "debug", "libdds_ffi.so"),
    ]
    for path in lib_candidates:
        if os.path.exists(path):
            return DDS(path)
    pytest.skip("libdds_ffi not found — run: cargo build -p dds-ffi --release")


# ---- Version ----

class TestVersion:
    def test_version_is_semver(self, client):
        v = client.version()
        parts = v.split(".")
        assert len(parts) >= 2, f"Not semver: {v}"
        assert all(p.isdigit() for p in parts), f"Not semver: {v}"


# ---- Identity ----

class TestIdentity:
    def test_create_classical(self, client):
        result = client.identity_create("pytest-alice")
        assert result["urn"].startswith("urn:vouchsafe:pytest-alice.")
        assert result["scheme"] == "Ed25519"
        assert result["pubkey_len"] == 32
        # I-9: secret signing key must not be exposed across the FFI.
        assert "signing_key_hex" not in result
        assert "signing_key" not in result

    def test_create_hybrid(self, client):
        result = client.identity_create_hybrid("pytest-quantum")
        assert result["urn"].startswith("urn:vouchsafe:pytest-quantum.")
        assert result["scheme"] == "Ed25519+ML-DSA-65"
        assert result["pubkey_len"] == 1984

    def test_parse_urn_valid(self, client):
        result = client.identity_parse_urn("urn:vouchsafe:alice.abc123")
        assert result["label"] == "alice"
        assert result["hash"] == "abc123"
        assert result["urn"] == "urn:vouchsafe:alice.abc123"

    def test_parse_urn_invalid(self, client):
        with pytest.raises(DDSError) as exc_info:
            client.identity_parse_urn("not-a-urn")
        assert exc_info.value.code == -1

    def test_create_roundtrip(self, client):
        """Create identity, then parse the URN back."""
        created = client.identity_create("roundtrip-py")
        parsed = client.identity_parse_urn(created["urn"])
        assert parsed["label"] == "roundtrip-py"
        assert parsed["urn"] == created["urn"]


# ---- Token ----

class TestToken:
    def test_create_and_validate_attest(self, client):
        result = client.token_create_attest("token-test")
        assert result["jti"].startswith("attest-")
        assert len(result["token_cbor_hex"]) > 0
        assert len(result["payload_hash"]) > 0

        # Validate the token
        validated = client.token_validate(result["token_cbor_hex"])
        assert validated["valid"] is True
        assert validated["kind"] == "Attest"
        assert validated["jti"] == result["jti"]

    def test_create_with_purpose(self, client):
        result = client.token_create_attest("purpose-test", purpose="dds:directory-entry")
        assert result["jti"].startswith("attest-")

    def test_validate_invalid_hex(self, client):
        with pytest.raises(DDSError) as exc_info:
            client.token_validate("not-hex!!")
        assert exc_info.value.code == -1

    def test_validate_invalid_cbor(self, client):
        with pytest.raises(DDSError) as exc_info:
            client.token_validate("deadbeef")
        assert exc_info.value.code == -3  # DDS_ERR_TOKEN


# ---- Policy ----

class TestPolicy:
    def test_deny_no_trust(self, client):
        result = client.policy_evaluate(
            subject_urn="urn:vouchsafe:nobody.hash",
            resource="repo:main",
            action="read",
            trusted_roots=[],
            rules=[{
                "effect": "Allow",
                "required_purpose": "group:dev",
                "resource": "repo:main",
                "actions": ["read"],
            }],
        )
        assert result["decision"] == "DENY"

    def test_deny_no_rules(self, client):
        result = client.policy_evaluate(
            subject_urn="urn:vouchsafe:alice.hash",
            resource="repo:main",
            action="read",
            trusted_roots=["urn:vouchsafe:root.hash"],
            rules=[],
        )
        assert result["decision"] == "DENY"

    def test_invalid_json_input(self, client):
        """Passing a non-empty but invalid subject should produce DENY (no matching rules)."""
        result = client.policy_evaluate(
            subject_urn="invalid",
            resource="x",
            action="y",
            trusted_roots=[],
            rules=[],
        )
        assert result["decision"] == "DENY"
