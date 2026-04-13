// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;
using System.Text.Json;
using DDS.PolicyAgent.Enforcers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;

namespace DDS.PolicyAgent.Tests.Integration;

/// <summary>
/// Integration tests for <see cref="WindowsRegistryOperations"/> and
/// <see cref="RegistryEnforcer"/> against the real Windows registry.
///
/// <b>Tier 1</b> tests use <c>HKCU\Software\DDS\Test</c> (no elevation
/// required). <b>Tier 2</b> tests use <c>HKLM\SOFTWARE\Policies\DDS\Test</c>
/// and skip at runtime when not elevated.
///
/// All test keys are cleaned up in <see cref="Dispose"/>.
/// </summary>
[Trait("Category", "Integration")]
[SupportedOSPlatform("windows")]
public sealed class RegistryEnforcerIntegrationTests : IDisposable
{
    private readonly WindowsRegistryOperations _ops = new();
    private readonly string _suffix = Guid.NewGuid().ToString("N")[..8];

    // ----------------------------------------------------------------
    // Tier 1 — HKCU (no elevation)
    // ----------------------------------------------------------------

    [SkippableFact]
    public void Hkcu_SetValue_Dword_RoundTrips()
    {
        SkipIfNotWindows();
        var subKey = HkcuKey("Dword");
        _ops.SetValue("CurrentUser", subKey, "TestVal", (uint)42, RegValueKind.Dword);
        var read = _ops.GetValue("CurrentUser", subKey, "TestVal");
        Assert.Equal(42, read);
    }

    [SkippableFact]
    public void Hkcu_SetValue_String_RoundTrips()
    {
        SkipIfNotWindows();
        var subKey = HkcuKey("String");
        _ops.SetValue("CurrentUser", subKey, "TestVal", "hello-dds", RegValueKind.String);
        var read = _ops.GetValue("CurrentUser", subKey, "TestVal");
        Assert.Equal("hello-dds", read);
    }

    [SkippableFact]
    public void Hkcu_SetValue_ExpandString_RoundTrips()
    {
        SkipIfNotWindows();
        var subKey = HkcuKey("ExpandString");
        _ops.SetValue("CurrentUser", subKey, "TestVal", @"%SystemRoot%\System32", RegValueKind.ExpandString);
        // Registry.GetValue with RegistryValueOptions.DoNotExpandEnvironmentNames
        // is not exposed through our interface, so the returned value may be
        // expanded. Just verify it's non-null and contains System32.
        var read = _ops.GetValue("CurrentUser", subKey, "TestVal") as string;
        Assert.NotNull(read);
        Assert.Contains("System32", read);
    }

    [SkippableFact]
    public void Hkcu_SetValue_Qword_RoundTrips()
    {
        SkipIfNotWindows();
        var subKey = HkcuKey("Qword");
        _ops.SetValue("CurrentUser", subKey, "TestVal", (ulong)9_999_999_999, RegValueKind.Qword);
        var read = _ops.GetValue("CurrentUser", subKey, "TestVal");
        Assert.Equal((long)9_999_999_999, read);
    }

    [SkippableFact]
    public void Hkcu_SetValue_MultiString_RoundTrips()
    {
        SkipIfNotWindows();
        var subKey = HkcuKey("MultiString");
        _ops.SetValue("CurrentUser", subKey, "TestVal", new[] { "a", "b", "c" }, RegValueKind.MultiString);
        var read = _ops.GetValue("CurrentUser", subKey, "TestVal") as string[];
        Assert.NotNull(read);
        Assert.Equal(["a", "b", "c"], read);
    }

    [SkippableFact]
    public void Hkcu_SetValue_Binary_RoundTrips()
    {
        SkipIfNotWindows();
        var subKey = HkcuKey("Binary");
        var data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        _ops.SetValue("CurrentUser", subKey, "TestVal", data, RegValueKind.Binary);
        var read = _ops.GetValue("CurrentUser", subKey, "TestVal") as byte[];
        Assert.NotNull(read);
        Assert.Equal(data, read);
    }

    [SkippableFact]
    public void Hkcu_DeleteValue_Removes_Existing_Value()
    {
        SkipIfNotWindows();
        var subKey = HkcuKey("DelVal");
        _ops.SetValue("CurrentUser", subKey, "Gone", "bye", RegValueKind.String);
        Assert.NotNull(_ops.GetValue("CurrentUser", subKey, "Gone"));

        _ops.DeleteValue("CurrentUser", subKey, "Gone");
        Assert.Null(_ops.GetValue("CurrentUser", subKey, "Gone"));
    }

    [SkippableFact]
    public void Hkcu_DeleteKey_Removes_Subkey()
    {
        SkipIfNotWindows();
        var subKey = HkcuKey("DelKey");
        _ops.SetValue("CurrentUser", subKey, "X", "v", RegValueKind.String);
        Assert.True(_ops.KeyExists("CurrentUser", subKey));

        _ops.DeleteKey("CurrentUser", subKey);
        Assert.False(_ops.KeyExists("CurrentUser", subKey));
    }

    [SkippableFact]
    public void Hkcu_KeyExists_Returns_True_For_Existing_Key()
    {
        SkipIfNotWindows();
        var subKey = HkcuKey("Exists");
        _ops.SetValue("CurrentUser", subKey, "X", (uint)1, RegValueKind.Dword);
        Assert.True(_ops.KeyExists("CurrentUser", subKey));
    }

    [SkippableFact]
    public void Hkcu_KeyExists_Returns_False_For_Missing_Key()
    {
        SkipIfNotWindows();
        Assert.False(_ops.KeyExists("CurrentUser", HkcuKey("NoSuchKey")));
    }

    [SkippableFact]
    public void Hkcu_GetValue_Returns_Null_For_Missing_Value()
    {
        SkipIfNotWindows();
        Assert.Null(_ops.GetValue("CurrentUser", HkcuKey("Ghost"), "NoVal"));
    }

    // ----------------------------------------------------------------
    // Tier 2 — HKLM (requires elevation) + full enforcer pipeline
    // ----------------------------------------------------------------

    [SkippableFact]
    public void Hklm_SetValue_Dword_RoundTrips()
    {
        SkipIfNotAdmin();
        var subKey = HklmKey("Dword");
        _ops.SetValue("LocalMachine", subKey, "TestVal", (uint)99, RegValueKind.Dword);
        var read = _ops.GetValue("LocalMachine", subKey, "TestVal");
        Assert.Equal(99, read);
    }

    [SkippableFact]
    public async Task Full_Enforcer_Applies_HKLM_Policy()
    {
        SkipIfNotAdmin();
        var subKey = HklmKey("Enforcer");
        var enforcer = new RegistryEnforcer(_ops, NullLogger<RegistryEnforcer>.Instance);

        var json = $$"""
        [
            {"hive":"LocalMachine","key":"{{subKey.Replace(@"\", @"\\")}}","name":"IntegDword","value":{"Dword":7},"action":"Set"},
            {"hive":"LocalMachine","key":"{{subKey.Replace(@"\", @"\\")}}","name":"IntegStr","value":{"String":"dds-e2e"},"action":"Set"}
        ]
        """;
        var directive = JsonDocument.Parse(json).RootElement;
        var result = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, result.Status);
        Assert.Equal(2, result.Changes!.Count);
        Assert.Equal(7, _ops.GetValue("LocalMachine", subKey, "IntegDword"));
        Assert.Equal("dds-e2e", _ops.GetValue("LocalMachine", subKey, "IntegStr"));
    }

    [SkippableFact]
    public async Task Full_Enforcer_Idempotent_On_Second_Apply()
    {
        SkipIfNotAdmin();
        var subKey = HklmKey("Idempotent");
        var enforcer = new RegistryEnforcer(_ops, NullLogger<RegistryEnforcer>.Instance);

        var json = $$"""
        [{"hive":"LocalMachine","key":"{{subKey.Replace(@"\", @"\\")}}","name":"V","value":{"Dword":1},"action":"Set"}]
        """;
        var directive = JsonDocument.Parse(json).RootElement;

        var r1 = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r1.Status);
        Assert.DoesNotContain("NO-OP", r1.Changes![0]);

        var r2 = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);
        Assert.Equal(EnforcementStatus.Ok, r2.Status);
        Assert.Contains("NO-OP", r2.Changes![0]);
    }

    [SkippableFact]
    public async Task Full_Enforcer_Delete_Cleans_Up()
    {
        SkipIfNotAdmin();
        var subKey = HklmKey("Delete");
        var enforcer = new RegistryEnforcer(_ops, NullLogger<RegistryEnforcer>.Instance);

        // Create a value first
        _ops.SetValue("LocalMachine", subKey, "Temp", "will-go", RegValueKind.String);
        Assert.NotNull(_ops.GetValue("LocalMachine", subKey, "Temp"));

        var json = $$"""
        [{"hive":"LocalMachine","key":"{{subKey.Replace(@"\", @"\\")}}","name":"Temp","action":"Delete"}]
        """;
        var directive = JsonDocument.Parse(json).RootElement;
        var result = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, result.Status);
        Assert.Null(_ops.GetValue("LocalMachine", subKey, "Temp"));
    }

    // ----------------------------------------------------------------
    // Cleanup
    // ----------------------------------------------------------------

    public void Dispose()
    {
        TryDeleteTree(Registry.CurrentUser, $@"{IntegrationTestHelpers.HkcuTestRoot}\{_suffix}");
        if (IntegrationTestHelpers.IsElevated)
            TryDeleteTree(Registry.LocalMachine, $@"{IntegrationTestHelpers.HklmTestRoot}\{_suffix}");
    }

    private static void TryDeleteTree(RegistryKey root, string subKey)
    {
        try { root.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false); }
        catch { /* best-effort cleanup */ }
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    private string HkcuKey(string leaf) => $@"{IntegrationTestHelpers.HkcuTestRoot}\{_suffix}\{leaf}";
    private string HklmKey(string leaf) => $@"{IntegrationTestHelpers.HklmTestRoot}\{_suffix}\{leaf}";

    private static void SkipIfNotWindows()
    {
        var reason = IntegrationTestHelpers.SkipIfNotWindows();
        Skip.IfNot(string.IsNullOrEmpty(reason), reason);
    }

    private static void SkipIfNotAdmin()
    {
        SkipIfNotWindows();
        var reason = IntegrationTestHelpers.SkipIfNotAdmin();
        Skip.IfNot(string.IsNullOrEmpty(reason), reason);
    }
}
