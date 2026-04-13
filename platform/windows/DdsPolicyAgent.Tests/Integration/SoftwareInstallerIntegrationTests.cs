// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using DDS.PolicyAgent.Enforcers;
using Microsoft.Extensions.Logging.Abstractions;

namespace DDS.PolicyAgent.Tests.Integration;

/// <summary>
/// Integration tests for <see cref="WindowsSoftwareOperations"/> and
/// <see cref="SoftwareInstaller"/> using a real test MSI package.
///
/// All tests require elevation. The test MSI installs a single file
/// to <c>%ProgramFiles%\DDS-Test\readme.txt</c> and is uninstalled
/// in <see cref="Dispose"/>.
/// </summary>
[Trait("Category", "Integration")]
[SupportedOSPlatform("windows")]
public sealed class SoftwareInstallerIntegrationTests : IDisposable
{
    private const string ProductCode = "{D1E2F3A4-B5C6-4D7E-8F9A-0B1C2D3E4F5A}";
    // MSI ProgramFilesFolder resolves to Program Files (x86) on ARM64.
    // Check both locations.
    private static readonly string[] PossibleInstallDirs =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DDS-Test"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "DDS-Test"),
    ];

    private static string? FindInstallDir() =>
        PossibleInstallDirs.FirstOrDefault(Directory.Exists);

    private readonly WindowsSoftwareOperations _ops = new();
    private bool _installed;

    private static string TestMsiPath =>
        Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "Integration", "TestData", "TestPackage.msi");

    private static string GetTestMsiFullPath()
    {
        var path = Path.GetFullPath(TestMsiPath);
        if (!File.Exists(path))
            throw new FileNotFoundException($"Test MSI not found at {path}. Build it with: wix build TestPackage.wxs -o TestPackage.msi");
        return path;
    }

    // ----------------------------------------------------------------
    // WindowsSoftwareOperations — direct API tests
    // ----------------------------------------------------------------

    [SkippableFact]
    public void InstallMsi_Installs_TestPackage()
    {
        SkipIfNotAdmin();
        var msiPath = GetTestMsiFullPath();

        var exitCode = _ops.InstallMsi(msiPath);
        _installed = true;

        Assert.Equal(0, exitCode);
        var installDir = FindInstallDir();
        Assert.NotNull(installDir);
        Assert.True(File.Exists(Path.Combine(installDir, "readme.txt")));
    }

    [SkippableFact]
    public void UninstallMsi_Removes_TestPackage()
    {
        SkipIfNotAdmin();
        var msiPath = GetTestMsiFullPath();

        // Install first
        var installCode = _ops.InstallMsi(msiPath);
        Assert.Equal(0, installCode);
        _installed = true;

        // Uninstall
        var uninstallCode = _ops.UninstallMsi(ProductCode);
        _installed = false;

        Assert.Equal(0, uninstallCode);
        // After uninstall, readme.txt should be gone from all possible locations
        Assert.All(PossibleInstallDirs, dir =>
            Assert.False(File.Exists(Path.Combine(dir, "readme.txt")),
                $"readme.txt should be removed from {dir} after uninstall"));
    }

    [SkippableFact]
    public void IsInstalled_Returns_True_After_Install()
    {
        SkipIfNotAdmin();
        var msiPath = GetTestMsiFullPath();

        Assert.False(_ops.IsInstalled("DDS Test Package"));

        _ops.InstallMsi(msiPath);
        _installed = true;

        Assert.True(_ops.IsInstalled("DDS Test Package"));
    }

    // ----------------------------------------------------------------
    // Download + SHA-256 verification
    // ----------------------------------------------------------------

    [SkippableFact]
    public async Task DownloadAndVerify_Accepts_Correct_Hash()
    {
        SkipIfNotAdmin();
        var msiPath = GetTestMsiFullPath();
        var expectedHash = await ComputeHashAsync(msiPath);

        // Start a local HTTP server to serve the MSI
        using var server = new TestHttpServer(msiPath);
        var url = server.Url + "/TestPackage.msi";

        var localPath = await _ops.DownloadAndVerifyAsync(url, expectedHash);
        try
        {
            Assert.True(File.Exists(localPath));
            Assert.True(new FileInfo(localPath).Length > 0);
        }
        finally
        {
            try { File.Delete(localPath); } catch { }
        }
    }

    [SkippableFact]
    public async Task DownloadAndVerify_Rejects_Wrong_Hash()
    {
        SkipIfNotAdmin();
        var msiPath = GetTestMsiFullPath();

        using var server = new TestHttpServer(msiPath);
        var url = server.Url + "/TestPackage.msi";

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _ops.DownloadAndVerifyAsync(url, "0000000000000000000000000000000000000000000000000000000000000000"));
    }

    // ----------------------------------------------------------------
    // Full enforcer pipeline
    // ----------------------------------------------------------------

    [SkippableFact]
    public async Task Full_Enforcer_Installs_Via_Local_Http()
    {
        SkipIfNotAdmin();
        var msiPath = GetTestMsiFullPath();
        var sha256 = await ComputeHashAsync(msiPath);

        using var server = new TestHttpServer(msiPath);
        var url = server.Url + "/TestPackage.msi";

        var enforcer = new SoftwareInstaller(_ops, NullLogger<SoftwareInstaller>.Instance);
        var json = $$"""
        {
            "package_id":"DDS Test Package","version":"1.0",
            "action":"Install","installer_type":"msi",
            "source_url":"{{url}}","sha256":"{{sha256}}"
        }
        """;
        var directive = JsonDocument.Parse(json).RootElement;
        var result = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);

        _installed = true;

        Assert.Equal(EnforcementStatus.Ok, result.Status);
        Assert.Single(result.Changes!);
        var enforcerInstallDir = FindInstallDir();
        Assert.NotNull(enforcerInstallDir);
        Assert.True(File.Exists(Path.Combine(enforcerInstallDir, "readme.txt")));
    }

    [SkippableFact]
    public async Task Full_Enforcer_Skips_Already_Installed()
    {
        SkipIfNotAdmin();
        var msiPath = GetTestMsiFullPath();

        // Pre-install
        _ops.InstallMsi(msiPath);
        _installed = true;

        var enforcer = new SoftwareInstaller(_ops, NullLogger<SoftwareInstaller>.Instance);
        var json = """
        {
            "package_id":"DDS Test Package","version":"1.0",
            "action":"Install","installer_type":"msi",
            "source_url":"https://unused","sha256":"unused"
        }
        """;
        var directive = JsonDocument.Parse(json).RootElement;
        var result = await enforcer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, result.Status);
        Assert.Contains("NO-OP", result.Changes![0]);
    }

    // ----------------------------------------------------------------
    // Cleanup
    // ----------------------------------------------------------------

    public void Dispose()
    {
        if (_installed)
        {
            try { _ops.UninstallMsi(ProductCode); } catch { }
        }
        // Belt-and-suspenders: remove install dir if it persists
        foreach (var dir in PossibleInstallDirs)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
        }
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    private static async Task<string> ComputeHashAsync(string path)
    {
        await using var fs = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(fs);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static void SkipIfNotAdmin()
    {
        var reason = IntegrationTestHelpers.SkipIfNotWindows();
        Skip.IfNot(string.IsNullOrEmpty(reason), reason);
        reason = IntegrationTestHelpers.SkipIfNotAdmin();
        Skip.IfNot(string.IsNullOrEmpty(reason), reason);
    }

    /// <summary>
    /// Minimal HTTP server that serves a single file for download tests.
    /// </summary>
    private sealed class TestHttpServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly string _filePath;
        private readonly Task _task;
        private readonly CancellationTokenSource _cts = new();

        public string Url { get; }

        public TestHttpServer(string filePath)
        {
            _filePath = filePath;
            // Find a free port
            var port = new Random().Next(49152, 65535);
            Url = $"http://localhost:{port}";
            _listener = new HttpListener();
            _listener.Prefixes.Add(Url + "/");
            _listener.Start();
            _task = Task.Run(ServeLoop);
        }

        private async Task ServeLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    var ctx = await _listener.GetContextAsync();
                    var response = ctx.Response;
                    var fileBytes = await File.ReadAllBytesAsync(_filePath);
                    response.ContentLength64 = fileBytes.Length;
                    response.ContentType = "application/octet-stream";
                    await response.OutputStream.WriteAsync(fileBytes);
                    response.Close();
                }
                catch (HttpListenerException) { break; }
                catch (ObjectDisposedException) { break; }
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
            _listener.Close();
            try { _task.Wait(TimeSpan.FromSeconds(2)); } catch { }
            _cts.Dispose();
        }
    }
}
