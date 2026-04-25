// SPDX-License-Identifier: MIT OR Apache-2.0

using DDS.PolicyAgent.MacOS.Runtime;

namespace DDS.PolicyAgent.MacOS.Tests;

internal sealed class RecordingCommandRunner : ICommandRunner
{
    private readonly Func<string, IReadOnlyList<string>, string?, CommandResult> _handler;

    public RecordingCommandRunner(
        Func<string, IReadOnlyList<string>, string?, CommandResult> handler)
        => _handler = handler;

    public List<RecordedCommand> Invocations { get; } = [];

    public CommandResult Run(
        string fileName,
        IEnumerable<string> arguments,
        string? standardInput = null,
        CancellationToken ct = default)
    {
        var args = arguments.ToArray();
        Invocations.Add(new RecordedCommand(fileName, args, standardInput));
        return _handler(fileName, args, standardInput);
    }
}

internal sealed record RecordedCommand(
    string FileName,
    IReadOnlyList<string> Arguments,
    string? StandardInput);

internal sealed class StaticHttpClientFactory : IHttpClientFactory
{
    private readonly HttpClient _client;

    public StaticHttpClientFactory(HttpClient client) => _client = client;

    public HttpClient CreateClient(string name) => _client;
}

/// <summary>
/// A-6 test double: returns a synthetic byte stream of a configurable
/// length, with optional <c>Content-Length</c> header. Lets unit
/// tests exercise the size-cap path in
/// <c>SoftwareInstaller.DownloadPackageAsync</c> without hitting the
/// network.
/// </summary>
internal sealed class FakeBytesHandler : HttpMessageHandler
{
    private readonly long _bodyLen;
    private readonly bool _emitContentLength;

    public FakeBytesHandler(long bodyLen, bool emitContentLength)
    {
        _bodyLen = bodyLen;
        _emitContentLength = emitContentLength;
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var stream = new RepeatingByteStream(_bodyLen);
        var content = new StreamContent(stream);
        if (_emitContentLength)
        {
            content.Headers.ContentLength = _bodyLen;
        }
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = content,
        };
        return Task.FromResult(response);
    }
}

/// <summary>
/// A non-seekable stream of <paramref name="length"/> arbitrary bytes
/// (0xAA). Mirrors the shape of an HTTP response body without
/// allocating the entire buffer up-front, so a test that pretends to
/// emit hundreds of MB doesn't actually exhaust memory.
/// </summary>
internal sealed class RepeatingByteStream : Stream
{
    private readonly long _length;
    private long _pos;

    public RepeatingByteStream(long length) => _length = length;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => _length;
    public override long Position
    {
        get => _pos;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        var remaining = _length - _pos;
        if (remaining <= 0) return 0;
        var n = (int)Math.Min(remaining, count);
        for (int i = 0; i < n; i++) buffer[offset + i] = 0xAA;
        _pos += n;
        return n;
    }

    public override Task<int> ReadAsync(
        byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => Task.FromResult(Read(buffer, offset, count));

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count)
        => throw new NotSupportedException();
}
