// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Net;
using System.Net.Sockets;
using System.Text;
using DDS.PolicyAgent.Linux.Client;

namespace DDS.PolicyAgent.Linux.Tests;

public sealed class DdsNodeHttpFactoryTests
{
    [Fact]
    public void ResolvesUnixSocketToPlaceholderHttpBase()
    {
        Assert.Equal(new Uri("http://localhost/"),
            DdsNodeHttpFactory.ResolveBaseAddress("unix:/var/lib/dds/dds.sock"));
    }

    [Fact]
    public void ExtractsUnixSocketPath()
    {
        Assert.Equal("/var/lib/dds/dds.sock",
            DdsNodeHttpFactory.ExtractSocketPath("unix:/var/lib/dds/dds.sock"));
    }

    [Fact]
    public void RejectsEmptyUnixSocketPath()
    {
        Assert.Throws<ArgumentException>(() => DdsNodeHttpFactory.ExtractSocketPath("unix:"));
    }

    [Fact]
    public void PreservesTcpBaseAddress()
    {
        Assert.Equal(new Uri("http://127.0.0.1:5551/"),
            DdsNodeHttpFactory.ResolveBaseAddress("http://127.0.0.1:5551"));
    }

    [Theory]
    [InlineData("unix:/var/lib/dds/dds.sock", true)]
    [InlineData("Unix:/var/lib/dds/dds.sock", true)]
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
    public void ExtractSocketPath_RejectsNonUnixUrl()
    {
        Assert.Throws<ArgumentException>(() =>
            DdsNodeHttpFactory.ExtractSocketPath("http://127.0.0.1:5551"));
    }

    [Fact]
    public void BuildHandler_TcpReturnsSocketsHttpHandler()
    {
        using var handler = DdsNodeHttpFactory.BuildHandler("http://127.0.0.1:5551");
        Assert.IsType<SocketsHttpHandler>(handler);
        var sh = (SocketsHttpHandler)handler;
        Assert.Null(sh.ConnectCallback);
    }

    [Fact]
    public void BuildHandler_UnixInstallsConnectCallback()
    {
        using var handler = DdsNodeHttpFactory.BuildHandler("unix:/var/lib/dds/dds.sock");
        var sh = Assert.IsType<SocketsHttpHandler>(handler);
        Assert.NotNull(sh.ConnectCallback);
    }

    [Fact]
    public async Task UnixHandler_E2E_ConnectsToLocalSocket()
    {
        if (!Socket.OSSupportsUnixDomainSockets)
            return;

        var tmp = Directory.CreateTempSubdirectory("dds-uds-linux-");
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
                try { client = await listener.AcceptAsync(cts.Token); }
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
                        var n = await stream.ReadAsync(buf.AsMemory(read, buf.Length - read));
                        if (n == 0) break;
                        read += n;
                        var text = Encoding.ASCII.GetString(buf, 0, read);
                        if (text.Contains("\r\n\r\n", StringComparison.Ordinal)) break;
                    }
                    var reqText = Encoding.ASCII.GetString(buf, 0, read);
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
