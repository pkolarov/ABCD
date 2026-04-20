// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Net.Sockets;

namespace DDS.PolicyAgent.MacOS.Client;

/// <summary>
/// Transport factory for talking to <c>dds-node</c>.
///
/// <para>
/// <b>H-7 step-2b (security review)</b>. On Linux/macOS the target
/// transport is a Unix domain socket (UDS). The Rust node's UDS
/// listener extracts the caller's peer credentials on every accepted
/// connection (<c>getpeereid</c> / <c>SO_PEERCRED</c>) and admits
/// administrative endpoints only when the caller's UID matches the
/// service UID or the allowlist. Routing the agent through the UDS
/// means policy-agent calls are now peer-cred-authenticated end to end.
/// </para>
///
/// <para>
/// URL scheme dispatch:
/// </para>
/// <list type="bullet">
/// <item><description><c>unix:/path/to/sock</c> — UDS transport. We
/// install a <see cref="SocketsHttpHandler.ConnectCallback"/> that
/// opens the named socket per HTTP connection. <see cref="HttpClient"/>
/// still needs an <c>http://</c>-shaped <see cref="HttpClient.BaseAddress"/>
/// so we use <c>http://localhost/</c> as a placeholder. The authority
/// is only used for the <c>Host</c> header the server echoes back.
/// </description></item>
/// <item><description>anything else — the default TCP handler (today:
/// loopback <c>127.0.0.1:5551</c>). Retained for backwards compatibility
/// during the transport cutover; once all clients are on UDS / named
/// pipe the node flips <c>trust_loopback_tcp_admin</c> to
/// <c>false</c>.</description></item>
/// </list>
/// </summary>
public static class DdsNodeHttpFactory
{
    public const string UnixScheme = "unix:";

    /// <summary>
    /// Returns <c>true</c> when <paramref name="baseUrl"/> is a UDS URL.
    /// </summary>
    public static bool IsUnixSocket(string? baseUrl)
        => !string.IsNullOrEmpty(baseUrl)
           && baseUrl.StartsWith(UnixScheme, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Extracts the on-disk socket path from a UDS URL of the form
    /// <c>unix:/path</c>. Throws <see cref="ArgumentException"/> if the
    /// URL is not a UDS URL or the extracted path is empty.
    /// </summary>
    public static string ExtractSocketPath(string baseUrl)
    {
        if (!IsUnixSocket(baseUrl))
            throw new ArgumentException($"not a unix: URL: {baseUrl}", nameof(baseUrl));
        var path = baseUrl.Substring(UnixScheme.Length);
        if (string.IsNullOrEmpty(path))
            throw new ArgumentException("empty UDS socket path", nameof(baseUrl));
        return path;
    }

    /// <summary>
    /// Resolves the <see cref="HttpClient.BaseAddress"/> for a given
    /// configured base URL. For UDS URLs this is the cosmetic
    /// placeholder <c>http://localhost/</c>; for TCP URLs it is the
    /// configured URL with a trailing slash.
    /// </summary>
    public static Uri ResolveBaseAddress(string baseUrl)
    {
        if (IsUnixSocket(baseUrl))
            return new Uri("http://localhost/");
        return new Uri(baseUrl.TrimEnd('/') + "/");
    }

    /// <summary>
    /// Builds the primary <see cref="HttpMessageHandler"/>. A new
    /// instance is returned on every call — the caller (typically
    /// <see cref="Microsoft.Extensions.DependencyInjection.IHttpClientFactory"/>)
    /// owns its lifetime.
    /// </summary>
    public static HttpMessageHandler BuildHandler(string baseUrl)
    {
        if (!IsUnixSocket(baseUrl))
            return new SocketsHttpHandler();

        var sockPath = ExtractSocketPath(baseUrl);
        return new SocketsHttpHandler
        {
            // The ConnectCallback replaces the TCP connect phase. We
            // open a fresh Unix stream socket to the configured path
            // per HTTP connection; keep-alive still works inside that
            // stream and HttpClient's internal pool still reuses the
            // connection across requests.
            ConnectCallback = async (_, ct) =>
            {
                var endpoint = new UnixDomainSocketEndPoint(sockPath);
                var socket = new Socket(
                    AddressFamily.Unix,
                    SocketType.Stream,
                    ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(endpoint, ct).ConfigureAwait(false);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
                return new NetworkStream(socket, ownsSocket: true);
            },
            // Cap connection lifetime so the peer-cred-bound stream on
            // the node side doesn't sit around indefinitely if the
            // agent's effective UID ever changes (e.g. setuid in a
            // future deployment model). 30s is more than enough for
            // the agent's 60s poll cycle to reuse the connection
            // within a single poll and drop it before the next.
            PooledConnectionLifetime = TimeSpan.FromSeconds(30),
        };
    }
}
