// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Net.Sockets;

namespace DDS.PolicyAgent.Linux.Client;

public static class DdsNodeHttpFactory
{
    public const string UnixScheme = "unix:";

    public static bool IsUnixSocket(string? baseUrl)
        => !string.IsNullOrEmpty(baseUrl)
           && baseUrl.StartsWith(UnixScheme, StringComparison.OrdinalIgnoreCase);

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
        => IsUnixSocket(baseUrl)
            ? new Uri("http://localhost/")
            : new Uri(baseUrl.TrimEnd('/') + "/");

    public static HttpMessageHandler BuildHandler(string baseUrl)
    {
        if (!IsUnixSocket(baseUrl))
            return new SocketsHttpHandler();

        var sockPath = ExtractSocketPath(baseUrl);
        return new SocketsHttpHandler
        {
            ConnectCallback = async (_, ct) =>
            {
                var socket = new Socket(
                    AddressFamily.Unix,
                    SocketType.Stream,
                    ProtocolType.Unspecified);
                try
                {
                    await socket.ConnectAsync(new UnixDomainSocketEndPoint(sockPath), ct)
                        .ConfigureAwait(false);
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
}
