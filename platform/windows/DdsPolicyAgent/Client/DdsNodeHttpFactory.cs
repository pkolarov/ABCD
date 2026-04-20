// SPDX-License-Identifier: MIT OR Apache-2.0

using System.IO.Pipes;
using System.Net.Sockets;

namespace DDS.PolicyAgent.Client;

/// <summary>
/// Transport factory for talking to <c>dds-node</c> from the Windows
/// Policy Agent.
///
/// <para>
/// <b>H-7 step-2b (security review)</b>. On Windows the target
/// transport is a named pipe. The Rust node's pipe listener calls
/// <c>GetNamedPipeClientProcessId</c> + <c>OpenProcessToken</c> +
/// <c>GetTokenInformation(TokenUser)</c> on every accepted connection,
/// extracts the caller's primary user SID, and admits admin endpoints
/// only when the SID matches <c>LocalSystem</c> (<c>S-1-5-18</c>) or
/// an explicitly-configured SID allowlist. Routing the agent through
/// the pipe means policy-agent calls are now peer-cred-authenticated
/// end to end — replacing the old implicit "localhost-only + OS
/// process isolation" assumption (H-7 pre-fix).
/// </para>
///
/// <para>
/// URL scheme dispatch:
/// </para>
/// <list type="bullet">
/// <item><description><c>pipe:&lt;name&gt;</c> — Windows named pipe.
/// <c>&lt;name&gt;</c> is either a bare name (<c>dds-api</c>, resolved
/// as <c>\\.\pipe\dds-api</c>) or a full path
/// (<c>\\.\pipe\dds-api</c>, passthrough). A
/// <see cref="SocketsHttpHandler.ConnectCallback"/> opens a
/// <see cref="NamedPipeClientStream"/> per HTTP connection.
/// </description></item>
/// <item><description><c>unix:/path</c> — Unix domain socket.
/// Supported for cross-platform dev builds of this agent on macOS /
/// Linux (it never ships that way, but keeping the code paths
/// symmetrical avoids a `#if WINDOWS` forest).
/// </description></item>
/// <item><description>anything else — legacy TCP loopback. Retained
/// for backwards compatibility during the transport cutover.
/// </description></item>
/// </list>
///
/// <para>
/// <see cref="HttpClient"/> still needs an <c>http://</c>-shaped
/// <see cref="HttpClient.BaseAddress"/>. For both named-pipe and UDS
/// transports we use <c>http://localhost/</c> as a cosmetic
/// placeholder; the authority is only used for the <c>Host</c>
/// header.
/// </para>
/// </summary>
public static class DdsNodeHttpFactory
{
    public const string PipeScheme = "pipe:";
    public const string UnixScheme = "unix:";

    public static bool IsNamedPipe(string? baseUrl)
        => !string.IsNullOrEmpty(baseUrl)
           && baseUrl.StartsWith(PipeScheme, StringComparison.OrdinalIgnoreCase);

    public static bool IsUnixSocket(string? baseUrl)
        => !string.IsNullOrEmpty(baseUrl)
           && baseUrl.StartsWith(UnixScheme, StringComparison.OrdinalIgnoreCase);

    public static bool IsLocalTransport(string? baseUrl)
        => IsNamedPipe(baseUrl) || IsUnixSocket(baseUrl);

    /// <summary>
    /// Parses a <c>pipe:</c> spec into a (server, pipe) pair suitable
    /// for <see cref="NamedPipeClientStream"/>. The server is always
    /// <c>"."</c> (this machine); the pipe name is the trailing
    /// component of the spec, with any <c>\\.\pipe\</c> prefix
    /// stripped.
    /// </summary>
    public static (string server, string pipeName) ParsePipeSpec(string baseUrl)
    {
        if (!IsNamedPipe(baseUrl))
            throw new ArgumentException($"not a pipe: URL: {baseUrl}", nameof(baseUrl));
        var spec = baseUrl.Substring(PipeScheme.Length);
        if (string.IsNullOrEmpty(spec))
            throw new ArgumentException("empty named-pipe spec", nameof(baseUrl));
        // Strip leading `\\.\pipe\` if present so we're left with just
        // the pipe name component. NamedPipeClientStream takes the pipe
        // name without the `\\.\pipe\` prefix.
        const string LocalPipePrefix = @"\\.\pipe\";
        if (spec.StartsWith(LocalPipePrefix, StringComparison.OrdinalIgnoreCase))
            spec = spec.Substring(LocalPipePrefix.Length);
        return (".", spec);
    }

    public static string ExtractSocketPath(string baseUrl)
    {
        if (!IsUnixSocket(baseUrl))
            throw new ArgumentException($"not a unix: URL: {baseUrl}", nameof(baseUrl));
        var path = baseUrl.Substring(UnixScheme.Length);
        if (string.IsNullOrEmpty(path))
            throw new ArgumentException("empty UDS socket path", nameof(baseUrl));
        return path;
    }

    public static Uri ResolveBaseAddress(string baseUrl)
    {
        if (IsLocalTransport(baseUrl))
            return new Uri("http://localhost/");
        return new Uri(baseUrl.TrimEnd('/') + "/");
    }

    public static HttpMessageHandler BuildHandler(string baseUrl)
    {
        if (IsNamedPipe(baseUrl))
        {
            var (server, pipeName) = ParsePipeSpec(baseUrl);
            return new SocketsHttpHandler
            {
                ConnectCallback = async (_, ct) =>
                {
                    var client = new NamedPipeClientStream(
                        server,
                        pipeName,
                        PipeDirection.InOut,
                        PipeOptions.Asynchronous);
                    try
                    {
                        // 5s timeout matches the HttpClient timeout
                        // range the agent uses; a longer wait here
                        // just layers on top of the overall request
                        // timeout.
                        await client.ConnectAsync(TimeSpan.FromSeconds(5), ct);
                    }
                    catch
                    {
                        client.Dispose();
                        throw;
                    }
                    return client;
                },
                PooledConnectionLifetime = TimeSpan.FromSeconds(30),
            };
        }

        if (IsUnixSocket(baseUrl))
        {
            var sockPath = ExtractSocketPath(baseUrl);
            return new SocketsHttpHandler
            {
                ConnectCallback = async (_, ct) =>
                {
                    var endpoint = new UnixDomainSocketEndPoint(sockPath);
                    var socket = new Socket(
                        AddressFamily.Unix,
                        SocketType.Stream,
                        ProtocolType.Unspecified);
                    try
                    {
                        await socket.ConnectAsync(endpoint, ct);
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                    return new NetworkStream(socket, ownsSocket: true);
                },
                PooledConnectionLifetime = TimeSpan.FromSeconds(30),
            };
        }

        return new SocketsHttpHandler();
    }
}
