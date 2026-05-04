// SPDX-License-Identifier: MIT OR Apache-2.0

using DDS.PolicyAgent.MacOS.Client;
using DDS.PolicyAgent.MacOS.Runtime;
using DDS.PolicyAgent.MacOS.State;

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

/// <summary>
/// In-memory <see cref="IAppliedStateStore"/> for Worker-level reconciliation
/// tests. Pre-seed <see cref="ManagedItems"/> to simulate items managed in a
/// prior cycle; inspect <see cref="SetCalls"/> after running a poll cycle to
/// verify the Worker updated the tracked set correctly.
/// </summary>
internal sealed class TrackingAppliedStateStore : IAppliedStateStore
{
    private readonly Dictionary<string, HashSet<string>> _managed;

    public Dictionary<string, HashSet<string>> SetCalls { get; } = new(StringComparer.Ordinal);

    public TrackingAppliedStateStore(Dictionary<string, HashSet<string>>? initial = null)
        => _managed = initial ?? [];

    public AppliedState Load() => new();
    public void Save(AppliedState state) { }
    public bool HasChanged(string targetId, string contentHash) => true;
    public void RecordApplied(string targetId, string version, string contentHash, string status, bool isSoftware) { }

    public IReadOnlySet<string> GetManagedItems(string category)
        => _managed.TryGetValue(category, out var set) ? set : new HashSet<string>();

    public void SetManagedItems(string category, IEnumerable<string> items)
    {
        var newSet = new HashSet<string>(items, StringComparer.Ordinal);
        SetCalls[category] = newSet;
        _managed[category] = newSet;
    }
}

/// <summary>
/// Controllable <see cref="IDdsNodeClient"/> for Worker-level tests.
/// Collects all <see cref="ReportAppliedAsync"/> calls in
/// <see cref="ReceivedReports"/> for assertion.
/// </summary>
internal sealed class TestMacDdsNodeClient : IDdsNodeClient
{
    public List<ApplicableMacOsPolicy> NextPolicies { get; set; } = [];
    public List<ApplicableSoftware> NextSoftware { get; set; } = [];
    public List<AppliedReport> ReceivedReports { get; } = [];

    public Task<List<ApplicableMacOsPolicy>> GetPoliciesAsync(
        string deviceUrn, CancellationToken ct = default)
        => Task.FromResult(NextPolicies);

    public Task<List<ApplicableSoftware>> GetSoftwareAsync(
        string deviceUrn, CancellationToken ct = default)
        => Task.FromResult(NextSoftware);

    public Task ReportAppliedAsync(AppliedReport report, CancellationToken ct = default)
    {
        ReceivedReports.Add(report);
        return Task.CompletedTask;
    }
}
