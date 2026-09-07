// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Diagnostics;

namespace DDS.PolicyAgent.Linux.Runtime;

public interface ICommandRunner
{
    // Arguments are passed as an explicit argv list (one element per argument),
    // NOT a single joined string. The runner forwards them via
    // ProcessStartInfo.ArgumentList, which hands each element to the child
    // process verbatim without re-parsing on whitespace. Callers must therefore
    // NOT pre-join, pre-split, or shell-quote arguments: a value containing
    // spaces or leading dashes (e.g. a user's full name) stays a single argument
    // and can never be reinterpreted as additional flags. See the macOS agent's
    // ProcessCommandRunner for the same ArgumentList-based contract.
    Task<CommandResult> RunAsync(
        string fileName, IReadOnlyList<string> arguments, CancellationToken ct = default);
}

public readonly record struct CommandResult(int ExitCode, string Stdout, string Stderr)
{
    public bool Success => ExitCode == 0;
}

public sealed class ProcessCommandRunner : ICommandRunner
{
    public async Task<CommandResult> RunAsync(
        string fileName, IReadOnlyList<string> arguments, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        // ArgumentList escapes/quotes each element for the platform and does NOT
        // re-tokenise on whitespace — unlike the single-string ProcessStartInfo
        // constructor, which splits its argument string and would let an argument
        // value inject extra flags into the command.
        foreach (var arg in arguments)
            psi.ArgumentList.Add(arg);

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

/// A single recorded runner invocation. <see cref="Argv"/> is the exact argument
/// vector the enforcer passed — assert on it when argument boundaries matter (e.g.
/// proving an attacker-controlled value stayed one element instead of splitting
/// into injected flags).
public readonly record struct RecordedCommand(string FileName, IReadOnlyList<string> Argv)
{
    /// The argv joined by single spaces. Convenience for substring/equality
    /// assertions on simple commands. LOSSY: an argument that itself contains a
    /// space is indistinguishable from two arguments here, so it must NOT be used
    /// to reason about argument-injection safety — use <see cref="Argv"/> for that.
    public string Arguments => string.Join(" ", Argv);
}

/// Records all commands; returns exit code 0 unless a per-command override is configured.
/// For use in unit tests.
public sealed class NullCommandRunner : ICommandRunner
{
    public List<RecordedCommand> Invocations { get; } = [];

    /// Per-command exit-code overrides keyed by executable name.
    public Dictionary<string, int> ExitCodeOverrides { get; } = new(StringComparer.Ordinal);

    /// Per-invocation exit-code overrides keyed by (executable, space-joined arguments).
    /// Takes precedence over <see cref="ExitCodeOverrides"/> when both match the same call.
    public Dictionary<(string FileName, string Arguments), int> InvocationExitCodeOverrides { get; } = new();

    public Task<CommandResult> RunAsync(
        string fileName, IReadOnlyList<string> arguments, CancellationToken ct = default)
    {
        // Snapshot argv so a caller reusing/mutating its list can't alter the record.
        var argv = arguments.ToArray();
        Invocations.Add(new RecordedCommand(fileName, argv));

        var joined = string.Join(" ", argv);
        var code = InvocationExitCodeOverrides.TryGetValue((fileName, joined), out var ov2) ? ov2
                 : ExitCodeOverrides.TryGetValue(fileName, out var ov) ? ov
                 : 0;
        return Task.FromResult(new CommandResult(code, string.Empty, string.Empty));
    }
}
