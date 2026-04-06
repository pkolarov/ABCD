"""
DDS Python bindings — ctypes wrapper around libdds_ffi shared library.

Usage:
    from dds import DDS
    client = DDS("/path/to/libdds_ffi.dylib")  # or .so / .dll
    ident = client.identity_create("alice")
    print(ident["urn"])
"""

import ctypes
import json
import os
import sys
from pathlib import Path


class DDSError(Exception):
    """Error from DDS library."""

    CODES = {
        -1: "Invalid input",
        -2: "Crypto error",
        -3: "Token error",
        -4: "Trust error",
        -5: "Policy denied",
        -99: "Internal error",
    }

    def __init__(self, code: int, detail: str = ""):
        self.code = code
        msg = self.CODES.get(code, f"Unknown error ({code})")
        super().__init__(f"{msg}: {detail}" if detail else msg)


class DDS:
    """Python wrapper for the DDS C FFI."""

    def __init__(self, lib_path: str | None = None):
        if lib_path is None:
            lib_path = self._find_library()
        self._lib = ctypes.cdll.LoadLibrary(lib_path)
        self._setup_signatures()

    @staticmethod
    def _find_library() -> str:
        """Auto-discover the shared library in common locations."""
        candidates = [
            "target/release/libdds_ffi.dylib",
            "target/release/libdds_ffi.so",
            "target/release/dds_ffi.dll",
            "target/debug/libdds_ffi.dylib",
            "target/debug/libdds_ffi.so",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        raise FileNotFoundError("Cannot find libdds_ffi. Build with: cargo build -p dds-ffi --release")

    def _setup_signatures(self):
        """Declare C function signatures for type safety."""
        c = self._lib
        c.dds_identity_create.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
        c.dds_identity_create.restype = ctypes.c_int32
        c.dds_identity_create_hybrid.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
        c.dds_identity_create_hybrid.restype = ctypes.c_int32
        c.dds_identity_parse_urn.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
        c.dds_identity_parse_urn.restype = ctypes.c_int32
        c.dds_token_create_attest.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
        c.dds_token_create_attest.restype = ctypes.c_int32
        c.dds_token_validate.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
        c.dds_token_validate.restype = ctypes.c_int32
        c.dds_policy_evaluate.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
        c.dds_policy_evaluate.restype = ctypes.c_int32
        c.dds_free_string.argtypes = [ctypes.c_char_p]
        c.dds_free_string.restype = None
        c.dds_version.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
        c.dds_version.restype = ctypes.c_int32

    def _call_json(self, func, *args) -> dict:
        """Call a DDS function that returns JSON via out parameter."""
        out = ctypes.c_char_p()
        all_args = list(args) + [ctypes.byref(out)]
        rc = func(*all_args)
        if out.value:
            result = json.loads(out.value.decode("utf-8"))
            self._lib.dds_free_string(out)
        else:
            result = {}
        if rc != 0:
            raise DDSError(rc, result.get("error", ""))
        return result

    def version(self) -> str:
        out = ctypes.c_char_p()
        rc = self._lib.dds_version(ctypes.byref(out))
        if rc != 0:
            raise DDSError(rc)
        v = out.value.decode("utf-8")
        self._lib.dds_free_string(out)
        return v

    def identity_create(self, label: str) -> dict:
        return self._call_json(self._lib.dds_identity_create, label.encode())

    def identity_create_hybrid(self, label: str) -> dict:
        return self._call_json(self._lib.dds_identity_create_hybrid, label.encode())

    def identity_parse_urn(self, urn: str) -> dict:
        return self._call_json(self._lib.dds_identity_parse_urn, urn.encode())

    def token_create_attest(self, label: str, purpose: str | None = None) -> dict:
        config = {"label": label}
        if purpose:
            config["purpose"] = purpose
        return self._call_json(self._lib.dds_token_create_attest, json.dumps(config).encode())

    def token_validate(self, token_cbor_hex: str) -> dict:
        return self._call_json(self._lib.dds_token_validate, token_cbor_hex.encode())

    def policy_evaluate(self, subject_urn: str, resource: str, action: str,
                        trusted_roots: list[str], rules: list[dict],
                        tokens_cbor_hex: list[str] | None = None) -> dict:
        config = {
            "subject_urn": subject_urn,
            "resource": resource,
            "action": action,
            "trusted_roots": trusted_roots,
            "rules": rules,
            "tokens_cbor_hex": tokens_cbor_hex or [],
        }
        return self._call_json(self._lib.dds_policy_evaluate, json.dumps(config).encode())
