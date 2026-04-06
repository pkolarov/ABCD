// DDS Swift unit tests — XCTest.
//
// Prerequisites:
//   cargo build -p dds-ffi --release
//   swift test -Xlinker -L<workspace>/target/release

import XCTest
@testable import DDS

final class DDSTests: XCTestCase {

    // MARK: - Version
    func testVersion() throws {
        let v = try DDS.version()
        XCTAssertTrue(v.contains("."), "Version should be semver: \(v)")
    }

    // MARK: - Identity
    func testIdentityCreateClassical() throws {
        let result = try DDS.Identity.create(label: "swift-alice")
        let urn = result["urn"] as! String
        XCTAssertTrue(urn.hasPrefix("urn:vouchsafe:swift-alice."))
        XCTAssertEqual(result["scheme"] as? String, "Ed25519")
        XCTAssertEqual(result["pubkey_len"] as? Int, 32)
    }

    func testIdentityCreateHybrid() throws {
        let result = try DDS.Identity.createHybrid(label: "swift-quantum")
        XCTAssertEqual(result["scheme"] as? String, "Ed25519+ML-DSA-65")
        XCTAssertEqual(result["pubkey_len"] as? Int, 1984)
    }

    func testIdentityParseUrnValid() throws {
        let result = try DDS.Identity.parseUrn("urn:vouchsafe:alice.abc123")
        XCTAssertEqual(result["label"] as? String, "alice")
        XCTAssertEqual(result["hash"] as? String, "abc123")
    }

    func testIdentityParseUrnInvalid() {
        XCTAssertThrowsError(try DDS.Identity.parseUrn("not-a-urn"))
    }

    func testIdentityRoundtrip() throws {
        let created = try DDS.Identity.create(label: "swift-rt")
        let urn = created["urn"] as! String
        let parsed = try DDS.Identity.parseUrn(urn)
        XCTAssertEqual(parsed["label"] as? String, "swift-rt")
    }

    // MARK: - Token
    func testTokenCreateAndValidate() throws {
        let created = try DDS.Token.createAttest(config: ["label": "swift-tok"])
        let jti = created["jti"] as! String
        XCTAssertTrue(jti.hasPrefix("attest-"))

        let hex = created["token_cbor_hex"] as! String
        let validated = try DDS.Token.validate(tokenCborHex: hex)
        XCTAssertEqual(validated["valid"] as? Bool, true)
        XCTAssertEqual(validated["kind"] as? String, "Attest")
    }

    func testTokenValidateInvalidHex() {
        XCTAssertThrowsError(try DDS.Token.validate(tokenCborHex: "not-hex!!"))
    }

    // MARK: - Policy
    func testPolicyDenyNoTrust() throws {
        let config: [String: Any] = [
            "subject_urn": "urn:vouchsafe:nobody.hash",
            "resource": "repo:main",
            "action": "read",
            "trusted_roots": [] as [String],
            "rules": [
                ["effect": "Allow", "required_purpose": "group:dev",
                 "resource": "repo:main", "actions": ["read"]]
            ],
            "tokens_cbor_hex": [] as [String]
        ]
        let result = try DDS.Policy.evaluate(config: config)
        XCTAssertEqual(result["decision"] as? String, "DENY")
    }
}
