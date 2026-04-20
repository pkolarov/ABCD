// SPDX-License-Identifier: MIT OR Apache-2.0

using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text;
using DDS.PolicyAgent.Client;

namespace DDS.PolicyAgent.Tests;

/// <summary>
/// Tests for the H-7 step-2b transport factory on Windows. The
/// named-pipe end-to-end path stands up a local pipe server that
/// mimics dds-node's HTTP/1 surface and asserts an HttpClient built
/// through <see cref="DdsNodeHttpFactory"/> actually reaches it —
/// closing the loop against the Rust <c>serve_pipe</c> listener.
/// </summary>
public class DdsNodeHttpFactoryTests
{
    [Theory]
    [InlineData("pipe:dds-api", true)]
    [InlineData("Pipe:DDS-API", true)]
    [InlineData("PIPE:\\\\.\\pipe\\dds-api", true)]
    [InlineData("unix:/tmp/dds.sock", false)]
    [InlineData("http://127.0.0.1:5551", false)]
    [InlineData("", false)]
    public void IsNamedPipe_RecognisesScheme(string url, bool expected)
    {
        Assert.Equal(expected, DdsNodeHttpFactory.IsNamedPipe(url));
    }

    [Theory]
    [InlineData("unix:/tmp/dds.sock", true)]
    [InlineData("Unix:/var/run/dds.sock", true)]
    [InlineData("pipe:dds-api", false)]
    [InlineData("http://127.0.0.1:5551", false)]
    public void IsUnixSocket_RecognisesScheme(string url, bool expected)
    {
        Assert.Equal(expected, DdsNodeHttpFactory.IsUnixSocket(url));
    }

    [Fact]
    public void ParsePipeSpec_BareName()
    {
        var (server, pipe) = DdsNodeHttpFactory.ParsePipeSpec("pipe:dds-api");
        Assert.Equal(".", server);
        Assert.Equal("dds-api", pipe);
    }

    [Fact]
    public void ParsePipeSpec_StripsLocalPipePrefix()
    {
        var (server, pipe) = DdsNodeHttpFactory.ParsePipeSpec(@"pipe:\\.\pipe\dds-api");
        Assert.Equal(".", server);
        Assert.Equal("dds-api", pipe);
    }

    [Fact]
    public void ParsePipeSpec_RejectsNonPipeUrl()
    {
        Assert.Throws<ArgumentException>(() =>
            DdsNodeHttpFactory.ParsePipeSpec("http://127.0.0.1:5551"));
    }

    [Fact]
    public void ParsePipeSpec_RejectsEmpty()
    {
        Assert.Throws<ArgumentException>(() =>
            DdsNodeHttpFactory.ParsePipeSpec("pipe:"));
    }

    [Fact]
    public void ExtractSocketPath_RoundTrips()
    {
        Assert.Equal("/tmp/dds.sock", DdsNodeHttpFactory.ExtractSocketPath("unix:/tmp/dds.sock"));
    }

    [Fact]
    public void ResolveBaseAddress_LocalTransportIsHttpLocalhost()
    {
        Assert.Equal("http://localhost/", DdsNodeHttpFactory.ResolveBaseAddress("pipe:dds-api").ToString());
        Assert.Equal("http://localhost/", DdsNodeHttpFactory.ResolveBaseAddress("unix:/x").ToString());
    }

    [Fact]
    public void ResolveBaseAddress_TcpPassesThrough()
    {
        var uri = DdsNodeHttpFactory.ResolveBaseAddress("http://127.0.0.1:5551");
        Assert.Equal("127.0.0.1", uri.Host);
        Assert.Equal(5551, uri.Port);
        Assert.EndsWith("/", uri.AbsolutePath);
    }

    [Fact]
    public void BuildHandler_Tcp_NoConnectCallback()
    {
        using var handler = DdsNodeHttpFactory.BuildHandler("http://127.0.0.1:5551");
        var sh = Assert.IsType<SocketsHttpHandler>(handler);
        Assert.Null(sh.ConnectCallback);
    }

    [Fact]
    public void BuildHandler_Pipe_InstallsConnectCallback()
    {
        using var handler = DdsNodeHttpFactory.BuildHandler("pipe:dds-api");
        var sh = Assert.IsType<SocketsHttpHandler>(handler);
        Assert.NotNull(sh.ConnectCallback);
    }

    [Fact]
    public void BuildHandler_Unix_InstallsConnectCallback()
    {
        using var handler = DdsNodeHttpFactory.BuildHandler("unix:/tmp/dds.sock");
        var sh = Assert.IsType<SocketsHttpHandler>(handler);
        Assert.NotNull(sh.ConnectCallback);
    }

    /// <summary>
    /// End-to-end: stand up a local named-pipe HTTP/1 responder and
    /// confirm the factory-built HttpClient reaches it. Only runs on
    /// Windows since Unix-like CI hosts don't have
    /// <c>NamedPipeClientStream</c> semantics.
    /// </summary>
    [Fact]
    public async Task PipeHandler_E2E_ConnectsToLocalPipe()
    {
        if (!OperatingSystem.IsWindows())
        {
            // Skip silently on non-Windows hosts — the factory still
            // compiles on those targets (the agent builds net8.0/net9.0
            // cross-platform for dev), and the Windows-only path gets
            // exercised on the Windows CI runner.
            return;
        }

        var pipeName = "dds-test-" + Guid.NewGuid().ToString("N");
        using var responder = StartPipeEchoResponder(pipeName);

        using var handler = DdsNodeHttpFactory.BuildHandler("pipe:" + pipeName);
        using var http = new HttpClient(handler)
        {
            BaseAddress = DdsNodeHttpFactory.ResolveBaseAddress("pipe:" + pipeName),
        };

        var resp = await http.GetAsync("v1/ping");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("GET /v1/ping", body);

        responder.Stop();
    }

    /// <summary>
    /// Minimal named-pipe HTTP/1.1 responder: echoes the first request
    /// line as the response body. One request per connection.
    /// </summary>
    private static PipeEchoResponder StartPipeEchoResponder(string pipeName)
    {
        var cts = new CancellationTokenSource();
        var loop = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                NamedPipeServerStream server;
                try
                {
                    server = new NamedPipeServerStream(
                        pipeName,
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous);
                }
                catch (Exception) { break; }

                try
                {
                    await server.WaitForConnectionAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    server.Dispose();
                    break;
                }
                catch (Exception)
                {
                    server.Dispose();
                    continue;
                }

                _ = Task.Run(async () =>
                {
                    using var s = server;
                    var buf = new byte[4096];
                    var read = 0;
                    while (read < buf.Length)
                    {
                        var n = await s.ReadAsync(buf.AsMemory(read, buf.Length - read));
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
                    await s.WriteAsync(bytes);
                });
            }
        }, cts.Token);

        return new PipeEchoResponder(loop, cts);
    }

    private sealed class PipeEchoResponder : IDisposable
    {
        private readonly Task _loop;
        private readonly CancellationTokenSource _cts;

        public PipeEchoResponder(Task loop, CancellationTokenSource cts)
        {
            _loop = loop;
            _cts = cts;
        }

        public void Stop()
        {
            try { _cts.Cancel(); } catch { /* ignore */ }
        }

        public void Dispose()
        {
            Stop();
            try { _loop.Wait(TimeSpan.FromSeconds(1)); } catch { /* ignore */ }
            _cts.Dispose();
        }
    }
}
