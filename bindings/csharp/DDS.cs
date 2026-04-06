// DDS C# bindings — P/Invoke wrapper for libdds_ffi.
//
// Usage:
//   var ident = DDS.Identity.Create("alice");
//   Console.WriteLine(ident.Urn);
//
// The native library (libdds_ffi.dylib/.so/dds_ffi.dll) must be
// in the application's library search path.

using System;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Vouchsafe.DDS
{
    /// <summary>Error codes from the DDS library.</summary>
    public enum DDSError : int
    {
        Ok = 0,
        InvalidInput = -1,
        Crypto = -2,
        Token = -3,
        Trust = -4,
        PolicyDenied = -5,
        Internal = -99,
    }

    /// <summary>Exception thrown by DDS operations.</summary>
    public class DDSException : Exception
    {
        public DDSError Code { get; }
        public DDSException(DDSError code, string detail = "")
            : base($"DDS error {code}: {detail}") { Code = code; }
    }

    /// <summary>Native P/Invoke declarations.</summary>
    internal static class Native
    {
        private const string Lib = "dds_ffi";

        [DllImport(Lib)] public static extern int dds_identity_create(string label, out IntPtr result);
        [DllImport(Lib)] public static extern int dds_identity_create_hybrid(string label, out IntPtr result);
        [DllImport(Lib)] public static extern int dds_identity_parse_urn(string urn, out IntPtr result);
        [DllImport(Lib)] public static extern int dds_token_create_attest(string configJson, out IntPtr result);
        [DllImport(Lib)] public static extern int dds_token_validate(string tokenHex, out IntPtr result);
        [DllImport(Lib)] public static extern int dds_policy_evaluate(string configJson, out IntPtr result);
        [DllImport(Lib)] public static extern int dds_version(out IntPtr result);
        [DllImport(Lib)] public static extern void dds_free_string(IntPtr s);
    }

    /// <summary>Core DDS client.</summary>
    public static class Client
    {
        internal static JsonDocument CallJson(Func<IntPtr, int> func)
        {
            IntPtr ptr;
            int rc = func(out ptr);
            string json = ptr != IntPtr.Zero ? Marshal.PtrToStringUTF8(ptr)! : "{}";
            if (ptr != IntPtr.Zero) Native.dds_free_string(ptr);
            if (rc != 0) throw new DDSException((DDSError)rc, json);
            return JsonDocument.Parse(json);
        }

        public static string Version()
        {
            IntPtr ptr;
            int rc = Native.dds_version(out ptr);
            if (rc != 0) throw new DDSException((DDSError)rc);
            string v = Marshal.PtrToStringUTF8(ptr)!;
            Native.dds_free_string(ptr);
            return v;
        }
    }

    /// <summary>Identity operations.</summary>
    public static class Identity
    {
        public static JsonDocument Create(string label)
            => Client.CallJson(ptr => Native.dds_identity_create(label, out ptr));

        public static JsonDocument CreateHybrid(string label)
            => Client.CallJson(ptr => Native.dds_identity_create_hybrid(label, out ptr));

        public static JsonDocument ParseUrn(string urn)
            => Client.CallJson(ptr => Native.dds_identity_parse_urn(urn, out ptr));
    }

    /// <summary>Token operations.</summary>
    public static class TokenOps
    {
        public static JsonDocument CreateAttest(string configJson)
            => Client.CallJson(ptr => Native.dds_token_create_attest(configJson, out ptr));

        public static JsonDocument Validate(string tokenCborHex)
            => Client.CallJson(ptr => Native.dds_token_validate(tokenCborHex, out ptr));
    }

    /// <summary>Policy operations.</summary>
    public static class Policy
    {
        public static JsonDocument Evaluate(string configJson)
            => Client.CallJson(ptr => Native.dds_policy_evaluate(configJson, out ptr));
    }
}
