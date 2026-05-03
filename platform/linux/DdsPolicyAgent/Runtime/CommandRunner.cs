// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Diagnostics;

namespace DDS.PolicyAgent.Linux.Runtime;

public interface ICommandRunner
{
    Task<CommandResult> RunAsync(string fileName, string arguments, CancellationToken ct = default);
}

public readonly record struct CommandResult(int ExitCode, string Stdout, string Stderr)
{
    public bool Success => ExitCode == 0;
}

public sealed class ProcessCommandRunner : ICommandRunner
{
    public async Task<CommandResult> RunAsync(
        string fileName, string arguments, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var proc = new Process { StartInfo = psi };
        proc.Start();

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);

        await proc.WaitForExitAsync(ct).ConfigureAwait(false);

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);

        return new CommandResult(proc.ExitCode, stdout.Trim(), stderr.Trim());
    }
}

/// Records all commands; returns exit code 0 unless a per-command override is configured.
/// For use in unit tests.
public sealed class NullCommandRunner : ICommandRunner
{
    public List<(string FileName, string Arguments)> Invocations { get; } = [];

    /// Per-command exit-code overrides keyed by executable name.
    public Dictionary<string, int> ExitCodeOverrides { get; } = new(StringComparer.Ordinal);

    public Task<CommandResult> RunAsync(
        string fileName, string arguments, CancellationToken ct = default)
    {
        Invocations.Add((fileName, arguments));
        var code = ExitCodeOverrides.TryGetValue(fileName, out var ov) ? ov : 0;
        return Task.FromResult(new CommandResult(code, string.Empty, string.Empty));
    }
}
