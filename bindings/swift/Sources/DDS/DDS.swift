// DDS Swift bindings — C interop wrapper for libdds_ffi.
//
// Usage:
//   let ident = try DDS.Identity.create(label: "alice")
//   print(ident.urn)
//
// Link against libdds_ffi.dylib / .so.

import Foundation

// Import the C header module
@_implementationOnly import CDDS

/// Error codes from the DDS library.
public enum DDSErrorCode: Int32 {
    case ok = 0
    case invalidInput = -1
    case crypto = -2
    case token = -3
    case trust = -4
    case policyDenied = -5
    case `internal` = -99
}

/// Error thrown by DDS operations.
public struct DDSError: Error, CustomStringConvertible {
    public let code: DDSErrorCode
    public let detail: String
    public var description: String { "DDS error \(code): \(detail)" }
}

// MARK: - Internal Helpers

private func callJSON(_ block: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Int32) throws -> [String: Any] {
    var out: UnsafeMutablePointer<CChar>? = nil
    let rc = block(&out)
    var json: [String: Any] = [:]
    if let ptr = out {
        let str = String(cString: ptr)
        dds_free_string(ptr)
        if let data = str.data(using: .utf8),
           let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            json = parsed
        }
    }
    guard rc == DDSErrorCode.ok.rawValue else {
        throw DDSError(code: DDSErrorCode(rawValue: rc) ?? .internal,
                       detail: json["error"] as? String ?? "")
    }
    return json
}

// MARK: - Public API

public enum DDS {

    /// Get the library version.
    public static func version() throws -> String {
        var out: UnsafeMutablePointer<CChar>? = nil
        let rc = dds_version(&out)
        guard rc == DDSErrorCode.ok.rawValue, let ptr = out else {
            throw DDSError(code: .internal, detail: "version failed")
        }
        let v = String(cString: ptr)
        dds_free_string(ptr)
        return v
    }

    // MARK: Identity
    public enum Identity {
        public static func create(label: String) throws -> [String: Any] {
            try callJSON { dds_identity_create(label, $0) }
        }

        public static func createHybrid(label: String) throws -> [String: Any] {
            try callJSON { dds_identity_create_hybrid(label, $0) }
        }

        public static func parseUrn(_ urn: String) throws -> [String: Any] {
            try callJSON { dds_identity_parse_urn(urn, $0) }
        }
    }

    // MARK: Token
    public enum Token {
        public static func createAttest(config: [String: Any]) throws -> [String: Any] {
            let data = try JSONSerialization.data(withJSONObject: config)
            let json = String(data: data, encoding: .utf8)!
            return try callJSON { dds_token_create_attest(json, $0) }
        }

        public static func validate(tokenCborHex: String) throws -> [String: Any] {
            try callJSON { dds_token_validate(tokenCborHex, $0) }
        }
    }

    // MARK: Policy
    public enum Policy {
        public static func evaluate(config: [String: Any]) throws -> [String: Any] {
            let data = try JSONSerialization.data(withJSONObject: config)
            let json = String(data: data, encoding: .utf8)!
            return try callJSON { dds_policy_evaluate(json, $0) }
        }
    }
}
