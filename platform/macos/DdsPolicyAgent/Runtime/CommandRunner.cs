// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.MacOS.Runtime;

public sealed record CommandResult(
    int ExitCode,
    string StandardOutput,
    string StandardError)
{
    public bool Succeeded => ExitCode == 0;
}

public interface ICommandRunner
{
    // AUDIT-2026-06-11 #13: `sensitive` marks a command whose arguments and
    // stdin may carry plaintext secrets (e.g. account passwords). When set,
    // the runner must NOT log the argument list or stdin, and failure messages
    // must redact the arguments so secrets never reach logs or off-host reports.
    CommandResult Run(
        string fileName,
        IEnumerable<string> arguments,
        string? standardInput = null,
        bool sensitive = false,
        CancellationToken ct = default);
}

public sealed class CommandExecutionException : InvalidOperationException
{
    public CommandExecutionException(string message)
        : base(message)
    {
    }
}

public sealed class ProcessCommandRunner : ICommandRunner
{
    private const int DefaultTimeoutMs = 5 * 60 * 1000; // 5 minutes

    private readonly ILogger<ProcessCommandRunner> _log;

    public ProcessCommandRunner(ILogger<ProcessCommandRunner> log) => _log = log;

    public CommandResult Run(
        string fileName,
        IEnumerable<string> arguments,
        string? standardInput = null,
        bool sensitive = false,
        CancellationToken ct = default)
    {
        using var process = new Process
        {
            StartInfo = BuildStartInfo(fileName, arguments, standardInput is not null),
        };

        // AUDIT-2026-06-11 #13: never log arguments or stdin for sensitive
        // commands — they may contain plaintext account passwords.
        if (sensitive)
            _log.LogDebug("Executing {Command} (arguments redacted)", fileName);
        else
            _log.LogDebug(
                "Executing {Command} {Arguments}",
                fileName,
                string.Join(" ", process.StartInfo.ArgumentList.ToArray()));

        process.Start();

        if (standardInput is not null)
        {
            process.StandardInput.Write(standardInput);
            process.StandardInput.Close();
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = process.StandardError.ReadToEndAsync(ct);

        bool exited = process.WaitForExit(DefaultTimeoutMs);
        if (!exited)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* best-effort */ }
            Task.WhenAll(stdoutTask, stderrTask).GetAwaiter().GetResult();
            throw new CommandExecutionException(
                $"{fileName} did not exit within {DefaultTimeoutMs / 1000} s and was killed");
        }

        var stdout = stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();

        return new CommandResult(process.ExitCode, stdout, stderr);
    }

    private static ProcessStartInfo BuildStartInfo(
        string fileName,
        IEnumerable<string> arguments,
        bool redirectStandardInput)
    {
        var info = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = redirectStandardInput,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };

        foreach (var argument in arguments)
            info.ArgumentList.Add(argument);

        return info;
    }
}

internal static class CommandRunnerExtensions
{
    public static CommandResult RunChecked(
        this ICommandRunner runner,
        string fileName,
        IEnumerable<string> arguments,
        string? standardInput = null,
        bool sensitive = false,
        CancellationToken ct = default)
    {
        var result = runner.Run(fileName, arguments, standardInput, sensitive, ct);
        if (result.Succeeded)
            return result;

        throw new CommandExecutionException(BuildFailureMessage(fileName, arguments, result, sensitive));
    }

    public static string BuildFailureMessage(
        string fileName,
        IEnumerable<string> arguments,
        CommandResult result,
        bool sensitive = false)
    {
        // AUDIT-2026-06-11 #13: redact arguments for sensitive commands so a
        // plaintext password can never reach logs or an off-host failure report.
        var command = sensitive
            ? $"{fileName} (arguments redacted)"
            : string.Join(" ", new[] { fileName }.Concat(arguments));
        var stderr = string.IsNullOrWhiteSpace(result.StandardError)
            ? "(empty)"
            : result.StandardError.Trim();
        var stdout = string.IsNullOrWhiteSpace(result.StandardOutput)
            ? "(empty)"
            : result.StandardOutput.Trim();

        return $"{command} failed with exit code {result.ExitCode}. stderr: {stderr}. stdout: {stdout}";
    }
}
