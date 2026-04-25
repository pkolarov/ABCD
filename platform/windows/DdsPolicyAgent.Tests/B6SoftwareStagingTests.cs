// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using DDS.PolicyAgent.Enforcers;

// CA1416: WindowsSoftwareOperations is annotated [SupportedOSPlatform("windows")];
// the tests run cross-platform (cache_dir override sidesteps the
// Windows-only DACL helper) so we silence the analyzer for the
// whole file.
#pragma warning disable CA1416

namespace DDS.PolicyAgent.Tests;

/// <summary>
/// <b>B-6 (security review)</b>: regression tests covering the
/// post-hash TOCTOU defense. Pre-B-6 the staged installer lived in
/// <c>%TEMP%\dds-software</c> (typically world-readable on Windows
/// hosts) and <see cref="WindowsSoftwareOperations.InstallMsi"/>
/// re-opened the path without verifying it had not been tampered
/// with between the SHA-256 verify and <c>Process.Start</c>. The
/// fix:
/// <list type="bullet">
///   <item>Stage under <c>%ProgramData%\DDS\software-cache</c>
///         with a SYSTEM/Administrators-only DACL on Windows.</item>
///   <item>Pin the post-verify file size + last-write timestamp,
///         and re-check both immediately before launch — any tamper
///         updates at least one of them.</item>
/// </list>
/// These tests run on every platform; the DACL portion of the fix
/// is exercised on Windows CI and is structurally a no-op
/// elsewhere.
/// </summary>
public class B6SoftwareStagingTests : IDisposable
{
    private readonly string _tempCache;

    public B6SoftwareStagingTests()
    {
        // Use a per-test sandbox so the suite runs uniformly on
        // Windows / macOS / Linux without needing the protected
        // %ProgramData% location.
        _tempCache = Path.Combine(Path.GetTempPath(), "dds-b6-tests-" + Guid.NewGuid().ToString("N"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempCache, recursive: true); } catch { /* best-effort */ }
    }

    private WindowsSoftwareOperations NewOps() =>
        new(httpClient: null, maxPackageBytes: WindowsSoftwareOperations.DefaultMaxPackageBytes, cacheDir: _tempCache);

    /// <summary>
    /// A staged file whose size has been swapped between verify and
    /// launch must be rejected with an
    /// <see cref="InvalidOperationException"/>.
    /// </summary>
    [Fact]
    public async Task B6_install_rejects_tamper_after_download()
    {
        var realBytes = Encoding.UTF8.GetBytes("real installer payload");
        var realHash = Convert.ToHexString(SHA256.HashData(realBytes)).ToLowerInvariant();

        using var server = new SimpleHttpServer(realBytes);
        var ops = NewOps();

        // Download succeeds — file is in the protected cache and
        // its size + mtime are pinned.
        var staged = await ops.DownloadAndVerifyAsync(server.Url, realHash);
        try
        {
            Assert.True(File.Exists(staged));

            // Simulate a TOCTOU swap: replace the file content with
            // a different, larger payload after the SHA-256 verify
            // but before InstallMsi launches.
            var tampered = new byte[realBytes.Length * 2];
            Array.Fill(tampered, (byte)'X');
            File.WriteAllBytes(staged, tampered);

            var ex = Assert.Throws<InvalidOperationException>(
                () => ops.InstallMsi(staged));
            Assert.Contains("modified between verify and launch", ex.Message);
        }
        finally
        {
            try { File.Delete(staged); } catch { /* best-effort */ }
        }
    }

    /// <summary>
    /// Identical content but a refreshed last-write timestamp
    /// (<c>File.SetLastWriteTimeUtc</c>) is also rejected. Without
    /// this, an attacker who can preserve the file size could touch
    /// the file in place and bypass the size check.
    /// </summary>
    [Fact]
    public async Task B6_install_rejects_mtime_only_tamper()
    {
        var realBytes = Encoding.UTF8.GetBytes("payload-mtime-only");
        var realHash = Convert.ToHexString(SHA256.HashData(realBytes)).ToLowerInvariant();

        using var server = new SimpleHttpServer(realBytes);
        var ops = NewOps();
        var staged = await ops.DownloadAndVerifyAsync(server.Url, realHash);
        try
        {
            File.SetLastWriteTimeUtc(staged, DateTime.UtcNow.AddSeconds(60));

            var ex = Assert.Throws<InvalidOperationException>(
                () => ops.InstallMsi(staged));
            Assert.Contains("modified between verify and launch", ex.Message);
        }
        finally
        {
            try { File.Delete(staged); } catch { /* best-effort */ }
        }
    }

    /// <summary>
    /// A path that was never produced by
    /// <see cref="WindowsSoftwareOperations.DownloadAndVerifyAsync"/>
    /// is allowed through (test convenience); only the file-existence
    /// check applies. The TOCTOU window does not exist for direct
    /// callers because they did not stage the file in our cache.
    /// </summary>
    [Fact]
    public void B6_install_accepts_external_path_with_existence_check()
    {
        var tmp = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tmp, "external");
            var ops = NewOps();
            // We cannot actually run msiexec from a unit test, but
            // we can exercise the pre-launch verifier by deleting
            // the file and asserting the right error type.
            File.Delete(tmp);
            var ex = Assert.Throws<FileNotFoundException>(
                () => ops.InstallMsi(tmp));
            Assert.Contains("staged installer disappeared", ex.Message);
        }
        finally
        {
            try { File.Delete(tmp); } catch { /* best-effort */ }
        }
    }

    /// <summary>
    /// The staged file must land inside the configured cache
    /// directory. In production this is
    /// <c>%ProgramData%\DDS\software-cache</c> with a
    /// SYSTEM/Administrators-only DACL; in this test it is the
    /// per-test sandbox seeded by the constructor.
    /// </summary>
    [Fact]
    public async Task B6_staging_uses_configured_cache_dir()
    {
        var realBytes = Encoding.UTF8.GetBytes("cache-location-check");
        var realHash = Convert.ToHexString(SHA256.HashData(realBytes)).ToLowerInvariant();

        using var server = new SimpleHttpServer(realBytes);
        var ops = NewOps();
        var staged = await ops.DownloadAndVerifyAsync(server.Url, realHash);
        try
        {
            Assert.StartsWith(
                Path.GetFullPath(_tempCache),
                Path.GetFullPath(staged),
                StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { File.Delete(staged); } catch { /* best-effort */ }
        }
    }
}

/// <summary>
/// Minimal one-off HTTP server that serves a single byte payload
/// on every GET. Used by the B-6 tests to drive
/// <see cref="WindowsSoftwareOperations.DownloadAndVerifyAsync"/>
/// without needing a real installer or external network.
/// </summary>
internal sealed class SimpleHttpServer : IDisposable
{
    private readonly HttpListener _listener;
    private readonly byte[] _payload;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public string Url { get; }

    public SimpleHttpServer(byte[] payload)
    {
        _payload = payload;
        var port = GetFreePort();
        Url = $"http://127.0.0.1:{port}/payload.bin";
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        _listener.Start();
        _loop = Task.Run(ServeAsync);
    }

    private async Task ServeAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener.GetContextAsync();
                }
                catch
                {
                    return;
                }
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "application/octet-stream";
                ctx.Response.ContentLength64 = _payload.Length;
                await ctx.Response.OutputStream.WriteAsync(
                    _payload.AsMemory(0, _payload.Length), _cts.Token);
                ctx.Response.OutputStream.Close();
            }
        }
        catch
        {
            // Listener disposed mid-request — ignore.
        }
    }

    private static int GetFreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { /* best-effort */ }
        try { _listener.Close(); } catch { /* best-effort */ }
        try { _loop.Wait(TimeSpan.FromSeconds(2)); } catch { /* best-effort */ }
        _cts.Dispose();
    }
}
