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
    CommandResult Run(
        string fileName,
        IEnumerable<string> arguments,
        string? standardInput = null,
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
    private readonly ILogger<ProcessCommandRunner> _log;

    public ProcessCommandRunner(ILogger<ProcessCommandRunner> log) => _log = log;

    public CommandResult Run(
        string fileName,
        IEnumerable<string> arguments,
        string? standardInput = null,
        CancellationToken ct = default)
    {
        using var process = new Process
        {
            StartInfo = BuildStartInfo(fileName, arguments, standardInput is not null),
        };

        var argList = process.StartInfo.ArgumentList.ToArray();
        _log.LogDebug("Executing {Command} {Arguments}", fileName, string.Join(" ", argList));

        process.Start();

        if (standardInput is not null)
        {
            process.StandardInput.Write(standardInput);
            process.StandardInput.Close();
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = process.StandardError.ReadToEndAsync(ct);
        process.WaitForExit();

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
        CancellationToken ct = default)
    {
        var result = runner.Run(fileName, arguments, standardInput, ct);
        if (result.Succeeded)
            return result;

        throw new CommandExecutionException(BuildFailureMessage(fileName, arguments, result));
    }

    public static string BuildFailureMessage(
        string fileName,
        IEnumerable<string> arguments,
        CommandResult result)
    {
        var command = string.Join(" ", new[] { fileName }.Concat(arguments));
        var stderr = string.IsNullOrWhiteSpace(result.StandardError)
            ? "(empty)"
            : result.StandardError.Trim();
        var stdout = string.IsNullOrWhiteSpace(result.StandardOutput)
            ? "(empty)"
            : result.StandardOutput.Trim();

        return $"{command} failed with exit code {result.ExitCode}. stderr: {stderr}. stdout: {stdout}";
    }
}
