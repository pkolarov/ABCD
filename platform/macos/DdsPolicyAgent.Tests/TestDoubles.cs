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
