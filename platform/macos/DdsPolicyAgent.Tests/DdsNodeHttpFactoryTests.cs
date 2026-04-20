// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Net;
using System.Net.Sockets;
using System.Text;
using DDS.PolicyAgent.MacOS.Client;

namespace DDS.PolicyAgent.MacOS.Tests;

/// <summary>
/// Tests for the H-7 step-2b transport factory. The UDS end-to-end
/// test spins up a minimal HTTP/1 echo responder on a Unix domain
/// socket in a temp dir, pointed to by the factory-built
/// <see cref="HttpClient"/>, and asserts the client actually reaches
/// it. Verifying that <c>ConnectCallback</c> is wired up correctly
/// closes the loop against the Rust <c>serve_unix</c> implementation
/// landed in the same remediation slice.
/// </summary>
public class DdsNodeHttpFactoryTests
{
    [Theory]
    [InlineData("unix:/tmp/dds.sock", true)]
    [InlineData("Unix:/tmp/dds.sock", true)]
    [InlineData("UNIX:/var/run/dds.sock", true)]
    [InlineData("http://127.0.0.1:5551", false)]
    [InlineData("https://node.example/", false)]
    [InlineData("", false)]
    public void IsUnixSocket_RecognisesScheme(string url, bool expected)
    {
        Assert.Equal(expected, DdsNodeHttpFactory.IsUnixSocket(url));
    }

    [Fact]
    public void IsUnixSocket_NullIsFalse()
    {
        Assert.False(DdsNodeHttpFactory.IsUnixSocket(null));
    }

    [Fact]
    public void ExtractSocketPath_ReturnsPath()
    {
        Assert.Equal("/tmp/dds.sock", DdsNodeHttpFactory.ExtractSocketPath("unix:/tmp/dds.sock"));
        Assert.Equal("/var/run/dds.sock",
            DdsNodeHttpFactory.ExtractSocketPath("Unix:/var/run/dds.sock"));
    }

    [Fact]
    public void ExtractSocketPath_RejectsNonUnixUrl()
    {
        Assert.Throws<ArgumentException>(() =>
            DdsNodeHttpFactory.ExtractSocketPath("http://127.0.0.1:5551"));
    }

    [Fact]
    public void ExtractSocketPath_RejectsEmptyPath()
    {
        Assert.Throws<ArgumentException>(() =>
            DdsNodeHttpFactory.ExtractSocketPath("unix:"));
    }

    [Fact]
    public void ResolveBaseAddress_UnixIsHttpLocalhost()
    {
        var uri = DdsNodeHttpFactory.ResolveBaseAddress("unix:/tmp/dds.sock");
        Assert.Equal("http", uri.Scheme);
        Assert.Equal("localhost", uri.Host);
        Assert.Equal("/", uri.AbsolutePath);
    }

    [Fact]
    public void ResolveBaseAddress_TcpPreservesHost()
    {
        var uri = DdsNodeHttpFactory.ResolveBaseAddress("http://127.0.0.1:5551");
        Assert.Equal("127.0.0.1", uri.Host);
        Assert.Equal(5551, uri.Port);
        Assert.EndsWith("/", uri.AbsolutePath);
    }

    [Fact]
    public void BuildHandler_TcpReturnsSocketsHttpHandler()
    {
        using var handler = DdsNodeHttpFactory.BuildHandler("http://127.0.0.1:5551");
        Assert.IsType<SocketsHttpHandler>(handler);
        var sh = (SocketsHttpHandler)handler;
        // TCP path: ConnectCallback is left null so the default TCP
        // connector is used — confirms we haven't accidentally wrapped
        // the handler for non-UDS URLs.
        Assert.Null(sh.ConnectCallback);
    }

    [Fact]
    public void BuildHandler_UnixInstallsConnectCallback()
    {
        using var handler = DdsNodeHttpFactory.BuildHandler("unix:/tmp/dds.sock");
        var sh = Assert.IsType<SocketsHttpHandler>(handler);
        Assert.NotNull(sh.ConnectCallback);
    }

    /// <summary>
    /// End-to-end verification: wire up an HttpClient via
    /// <see cref="DdsNodeHttpFactory"/> against a local UDS responder
    /// and assert the request actually reaches the socket. If
    /// <c>ConnectCallback</c> is broken the request either times out
    /// or fails with an I/O error.
    /// </summary>
    [Fact]
    public async Task UnixHandler_E2E_ConnectsToLocalSocket()
    {
        if (!Socket.OSSupportsUnixDomainSockets)
        {
            // Skip silently on platforms without UDS.
            return;
        }

        var tmp = Directory.CreateTempSubdirectory("dds-uds-");
        try
        {
            var sockPath = Path.Combine(tmp.FullName, "dds.sock");
            using var responder = await StartEchoResponder(sockPath);

            var baseAddress = DdsNodeHttpFactory.ResolveBaseAddress("unix:" + sockPath);
            using var handler = DdsNodeHttpFactory.BuildHandler("unix:" + sockPath);
            using var http = new HttpClient(handler) { BaseAddress = baseAddress };

            var resp = await http.GetAsync("v1/ping");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            var body = await resp.Content.ReadAsStringAsync();
            Assert.Contains("GET /v1/ping", body);

            responder.Stop();
        }
        finally
        {
            try { tmp.Delete(recursive: true); } catch { /* ignore */ }
        }
    }

    /// <summary>
    /// Minimal HTTP/1.1 responder that echoes the request line + headers
    /// back in the response body. Not a general-purpose server — it
    /// handles exactly one request per connection, reads until the
    /// CRLFCRLF header-end marker, then responds.
    /// </summary>
    private static Task<EchoResponder> StartEchoResponder(string sockPath)
    {
        var endpoint = new UnixDomainSocketEndPoint(sockPath);
        var listener = new Socket(
            AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        listener.Bind(endpoint);
        listener.Listen(10);

        var cts = new CancellationTokenSource();
        var loop = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                Socket client;
                try
                {
                    client = await listener.AcceptAsync(cts.Token);
                }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }

                _ = Task.Run(async () =>
                {
                    using var c = client;
                    using var stream = new NetworkStream(c, ownsSocket: false);
                    var buf = new byte[4096];
                    var read = 0;
                    while (read < buf.Length)
                    {
                        var n = await stream.ReadAsync(buf.AsMemory(read, buf.Length - read))
                            ;
                        if (n == 0) break;
                        read += n;
                        // Header end marker.
                        var text = Encoding.ASCII.GetString(buf, 0, read);
                        if (text.Contains("\r\n\r\n", StringComparison.Ordinal)) break;
                    }
                    var reqText = Encoding.ASCII.GetString(buf, 0, read);
                    // Extract request line.
                    var firstLine = reqText.Split("\r\n", 2, StringSplitOptions.None)[0];
                    var body = firstLine;
                    var resp = new StringBuilder();
                    resp.Append("HTTP/1.1 200 OK\r\n");
                    resp.Append("Content-Type: text/plain\r\n");
                    resp.Append($"Content-Length: {body.Length}\r\n");
                    resp.Append("Connection: close\r\n");
                    resp.Append("\r\n");
                    resp.Append(body);
                    var bytes = Encoding.ASCII.GetBytes(resp.ToString());
                    await stream.WriteAsync(bytes);
                });
            }
        }, cts.Token);

        return Task.FromResult(new EchoResponder(listener, loop, cts, sockPath));
    }

    private sealed class EchoResponder : IDisposable
    {
        private readonly Socket _listener;
        private readonly Task _loop;
        private readonly CancellationTokenSource _cts;
        private readonly string _sockPath;

        public EchoResponder(Socket listener, Task loop, CancellationTokenSource cts, string sockPath)
        {
            _listener = listener;
            _loop = loop;
            _cts = cts;
            _sockPath = sockPath;
        }

        public void Stop()
        {
            try { _cts.Cancel(); } catch { /* ignore */ }
            try { _listener.Close(); } catch { /* ignore */ }
        }

        public void Dispose()
        {
            Stop();
            try { _loop.Wait(TimeSpan.FromSeconds(1)); } catch { /* ignore */ }
            try { if (File.Exists(_sockPath)) File.Delete(_sockPath); } catch { /* ignore */ }
            _cts.Dispose();
            _listener.Dispose();
        }
    }
}
