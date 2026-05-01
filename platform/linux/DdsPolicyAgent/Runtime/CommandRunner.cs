// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Linux.Runtime;

public interface ICommandRunner
{
    Task<int> RunAsync(string fileName, string arguments, CancellationToken ct = default);
}

public sealed class ProcessCommandRunner : ICommandRunner
{
    public Task<int> RunAsync(string fileName, string arguments, CancellationToken ct = default)
        => throw new NotSupportedException("L-1 Linux agent must not run host mutation commands");
}
