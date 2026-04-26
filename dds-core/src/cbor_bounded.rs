//! **I-6 (security review)** — depth-bounded CBOR decoder.
//!
//! `ciborium`'s default `from_reader` allows recursion up to 256
//! levels, which is generally safe but considerably deeper than any
//! shape DDS actually emits on the wire. A peer that sends a
//! pathologically-nested CBOR blob (256 nested arrays = ~256 bytes)
//! can drive ciborium's recursive deserializer to grow the host
//! thread's stack toward exhaustion. Tokio worker threads default to
//! a 2 MiB stack; libp2p task stacks may be smaller.
//!
//! This module exposes [`from_reader`] — a thin wrapper over
//! `ciborium::de::from_reader_with_recursion_limit` that pins the
//! cap at [`MAX_DEPTH`] = 16. Sixteen levels comfortably covers
//! every legitimate DDS shape (deepest observed: token payload =
//! map → bytes-payload → map → vec → struct ≈ 6 levels) and matches
//! the C++ CTAP2 decoder's `kMaxCborDepth` introduced for M-17.
//!
//! Use [`from_reader`] at every untrusted-input boundary
//! (gossip/sync ingest, peer admission handshake, FIDO2 attestation,
//! provisioning bundle import). Local trusted files (own identity
//! key, own domain key) keep the standard ciborium reader because
//! the attacker model there is filesystem-write — already covered
//! by L-2 / L-3 / L-4 / M-10 / M-14 — not depth bombs.

/// Maximum CBOR nesting accepted on any untrusted-input boundary.
/// Matches `kMaxCborDepth` in the C++ CTAP2 decoder (M-17).
pub const MAX_DEPTH: usize = 16;

/// Deserialize from a CBOR reader with a hard recursion cap of
/// [`MAX_DEPTH`]. The signature mirrors `ciborium::from_reader` —
/// callers can swap the call without changing error-handling
/// shape. A depth-bomb input fails with
/// `ciborium::de::Error::RecursionLimitExceeded` rather than
/// growing the stack to the depth the attacker requested.
pub fn from_reader<T, R>(reader: R) -> Result<T, ciborium::de::Error<R::Error>>
where
    T: serde::de::DeserializeOwned,
    R: ciborium_io::Read,
    R::Error: core::fmt::Debug,
{
    ciborium::de::from_reader_with_recursion_limit(reader, MAX_DEPTH)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a CBOR blob that nests `n` levels deep using
    /// definite-length arrays of length 1: `0x81 0x81 ... 0x00`.
    /// A blob of `n = 256` is only `n + 1 = 257` bytes — small
    /// enough that a naive byte-cap does not catch it.
    fn nested_arrays(n: usize) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0x81; n]; // n × array(1)
        buf.push(0x00); // unsigned int 0 — innermost leaf
        buf
    }

    #[test]
    fn accepts_well_formed_input() {
        // A 3-level nested map / array / int — well within MAX_DEPTH.
        // Manually encoded: { "a": [[1]] }
        let bytes: &[u8] = &[
            0xa1, // map(1)
            0x61, b'a', // text "a"
            0x81, // array(1)
            0x81, // array(1)
            0x01, // unsigned 1
        ];
        let v: ciborium::value::Value = from_reader(bytes).expect("well-formed input must decode");
        let map = match v {
            ciborium::value::Value::Map(m) => m,
            other => panic!("expected map, got {other:?}"),
        };
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn refuses_depth_bomb_just_above_cap() {
        // A payload one frame past MAX_DEPTH must be rejected
        // cleanly with `RecursionLimitExceeded` — no panic, no stack
        // exhaustion.
        let bytes = nested_arrays(MAX_DEPTH + 1);
        let res: Result<ciborium::value::Value, _> = from_reader(&bytes[..]);
        match res {
            Err(ciborium::de::Error::RecursionLimitExceeded) => {}
            Err(other) => panic!("expected RecursionLimitExceeded, got {other:?}"),
            Ok(_) => panic!("depth-{} blob must be rejected", MAX_DEPTH + 1),
        }
    }

    #[test]
    fn refuses_extreme_depth_bomb() {
        // 4 KiB of nested arrays — the kind of input an attacker
        // would actually send. Must be rejected without growing the
        // stack to 4 KiB of frames.
        let bytes = nested_arrays(4096);
        let res: Result<ciborium::value::Value, _> = from_reader(&bytes[..]);
        assert!(matches!(
            res,
            Err(ciborium::de::Error::RecursionLimitExceeded)
        ));
    }

    #[test]
    fn accepts_just_below_cap() {
        // Boundary check: one level below the cap must still decode.
        // (`MAX_DEPTH - 1` arrays + 1 leaf int = MAX_DEPTH frames in
        // ciborium's accounting; the limit is the maximum number of
        // simultaneously-open frames.)
        let bytes = nested_arrays(MAX_DEPTH - 1);
        let res: Result<ciborium::value::Value, _> = from_reader(&bytes[..]);
        assert!(
            res.is_ok(),
            "depth-{} blob must decode (one below cap)",
            MAX_DEPTH - 1
        );
    }
}
