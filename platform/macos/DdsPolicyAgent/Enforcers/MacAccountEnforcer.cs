// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using System.Security.Cryptography;
using DDS.PolicyAgent.MacOS.Runtime;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.MacOS.Enforcers;

public interface IMacAccountOperations
{
    bool UserExists(string username);
    void CreateUser(string username, string? fullName, string? shell, bool admin, bool hidden);
    void DeleteUser(string username);
    void DisableUser(string username);
    void EnableUser(string username);
    bool IsEnabled(string username);
    bool IsAdmin(string username);
    bool IsHidden(string username);
    string? GetShell(string username);
    void SetAdmin(string username, bool isAdmin);
    void SetHidden(string username, bool hidden);
    void SetShell(string username, string? shell);
    bool IsDirectoryBound();
}

public sealed class InMemoryMacAccountOperations : IMacAccountOperations
{
    public sealed class AccountState
    {
        public string Username { get; set; } = string.Empty;
        public string? FullName { get; set; }
        public string? Shell { get; set; }
        public bool Enabled { get; set; } = true;
        public bool Admin { get; set; }
        public bool Hidden { get; set; }
    }

    private readonly Dictionary<string, AccountState> _accounts = new(StringComparer.OrdinalIgnoreCase);
    public bool SimulateDirectoryBound { get; set; }

    public bool UserExists(string username) => _accounts.ContainsKey(username);

    public void CreateUser(string username, string? fullName, string? shell, bool admin, bool hidden)
    {
        if (_accounts.ContainsKey(username))
            throw new InvalidOperationException($"User '{username}' already exists");
        _accounts[username] = new AccountState
        {
            Username = username,
            FullName = fullName,
            Shell = shell,
            Admin = admin,
            Hidden = hidden,
        };
    }

    public void DeleteUser(string username) => _accounts.Remove(username);
    public void DisableUser(string username) { if (_accounts.TryGetValue(username, out var a)) a.Enabled = false; }
    public void EnableUser(string username) { if (_accounts.TryGetValue(username, out var a)) a.Enabled = true; }
    public bool IsEnabled(string username) => _accounts.TryGetValue(username, out var a) && a.Enabled;
    public bool IsAdmin(string username) => _accounts.TryGetValue(username, out var a) && a.Admin;
    public bool IsHidden(string username) => _accounts.TryGetValue(username, out var a) && a.Hidden;
    public string? GetShell(string username) => _accounts.TryGetValue(username, out var a) ? a.Shell : null;
    public void SetAdmin(string username, bool isAdmin) { if (_accounts.TryGetValue(username, out var a)) a.Admin = isAdmin; }
    public void SetHidden(string username, bool hidden) { if (_accounts.TryGetValue(username, out var a)) a.Hidden = hidden; }
    public void SetShell(string username, string? shell) { if (_accounts.TryGetValue(username, out var a)) a.Shell = shell; }
    public bool IsDirectoryBound() => SimulateDirectoryBound;

    public AccountState? Peek(string username)
        => _accounts.TryGetValue(username, out var a) ? a : null;
}

public sealed class HostMacAccountOperations : IMacAccountOperations
{
    private readonly ICommandRunner _runner;

    public HostMacAccountOperations(ICommandRunner runner) => _runner = runner;

    public bool UserExists(string username)
        => _runner.Run("/usr/bin/dscl", [".", "-read", UserPath(username)]).Succeeded;

    public void CreateUser(string username, string? fullName, string? shell, bool admin, bool hidden)
    {
        PrivilegeGuard.DemandRoot("local macOS account creation");

        var uid = GetNextUid();
        var home = $"/Users/{username}";
        var effectiveShell = string.IsNullOrWhiteSpace(shell) ? "/bin/zsh" : shell;
        var displayName = string.IsNullOrWhiteSpace(fullName) ? username : fullName!;

        RunDscl("-create", UserPath(username));
        RunDscl("-create", UserPath(username), "RealName", displayName);
        RunDscl("-create", UserPath(username), "UserShell", effectiveShell);
        RunDscl("-create", UserPath(username), "UniqueID", uid.ToString());
        RunDscl("-create", UserPath(username), "PrimaryGroupID", "20");
        RunDscl("-create", UserPath(username), "NFSHomeDirectory", home);
        RunDscl("-create", UserPath(username), "GeneratedUID", Guid.NewGuid().ToString().ToUpperInvariant());

        // The current policy model does not distribute a login password.
        // v1 therefore seeds a random local secret and expects a later
        // DDS login/bootstrap flow to rotate credentials as needed.
        RunDscl("-passwd", UserPath(username), GenerateBootstrapPassword());

        if (File.Exists("/usr/sbin/createhomedir"))
            _runner.RunChecked("/usr/sbin/createhomedir", ["-c", "-u", username]);

        SetAdmin(username, admin);
        SetHidden(username, hidden);
    }

    public void DeleteUser(string username)
    {
        PrivilegeGuard.DemandRoot("local macOS account deletion");
        _runner.RunChecked("/usr/sbin/sysadminctl", ["-deleteUser", username, "-keepHome"]);
    }

    public void DisableUser(string username)
    {
        PrivilegeGuard.DemandRoot("local macOS account disable");
        _runner.RunChecked("/usr/bin/pwpolicy", ["-u", username, "-disableuser"]);
    }

    public void EnableUser(string username)
    {
        PrivilegeGuard.DemandRoot("local macOS account enable");
        _runner.RunChecked("/usr/bin/pwpolicy", ["-u", username, "-enableuser"]);
    }

    public bool IsEnabled(string username)
    {
        var result = _runner.Run("/usr/bin/pwpolicy", ["-u", username, "-authentication-allowed"]);
        if (!result.Succeeded)
            return false;

        var output = $"{result.StandardOutput}\n{result.StandardError}";
        if (output.Contains("does not allow", StringComparison.OrdinalIgnoreCase))
            return false;
        if (output.Contains("allows", StringComparison.OrdinalIgnoreCase))
            return true;
        return result.Succeeded;
    }

    public bool IsAdmin(string username)
    {
        var result = _runner.Run("/usr/bin/id", ["-Gn", username]);
        if (!result.Succeeded)
            return false;

        return result.StandardOutput
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains("admin", StringComparer.OrdinalIgnoreCase);
    }

    public bool IsHidden(string username)
        => string.Equals(ReadSingleAttribute(username, "IsHidden"), "1", StringComparison.OrdinalIgnoreCase);

    public string? GetShell(string username)
        => ReadSingleAttribute(username, "UserShell");

    public void SetAdmin(string username, bool isAdmin)
    {
        PrivilegeGuard.DemandRoot("local macOS admin group mutation");
        _runner.RunChecked(
            "/usr/sbin/dseditgroup",
            ["-o", "edit", "-n", ".", isAdmin ? "-a" : "-d", username, "-t", "user", "admin"]);
    }

    public void SetHidden(string username, bool hidden)
    {
        PrivilegeGuard.DemandRoot("local macOS hidden-user mutation");
        if (hidden)
        {
            RunDscl("-create", UserPath(username), "IsHidden", "1");
        }
        else
        {
            var result = _runner.Run("/usr/bin/dscl", [".", "-delete", UserPath(username), "IsHidden"]);
            if (!result.Succeeded &&
                !result.StandardError.Contains("No such key", StringComparison.OrdinalIgnoreCase))
            {
                throw new CommandExecutionException(
                    CommandRunnerExtensions.BuildFailureMessage(
                        "/usr/bin/dscl",
                        [".", "-delete", UserPath(username), "IsHidden"],
                        result));
            }
        }
    }

    public void SetShell(string username, string? shell)
    {
        if (string.IsNullOrWhiteSpace(shell))
            return;

        PrivilegeGuard.DemandRoot("local macOS shell mutation");
        RunDscl("-create", UserPath(username), "UserShell", shell);
    }

    public bool IsDirectoryBound()
    {
        var ad = _runner.Run("/usr/sbin/dsconfigad", ["-show"]);
        if (ad.Succeeded && !string.IsNullOrWhiteSpace(ad.StandardOutput))
            return true;

        var search = _runner.Run("/usr/bin/dscl", ["/Search", "-read", "/", "CSPSearchPath"]);
        if (!search.Succeeded)
            return false;

        var output = search.StandardOutput;
        return output.Contains("/Active Directory/", StringComparison.OrdinalIgnoreCase)
            || output.Contains("/LDAPv3/", StringComparison.OrdinalIgnoreCase);
    }

    private string? ReadSingleAttribute(string username, string attribute)
    {
        var result = _runner.Run("/usr/bin/dscl", [".", "-read", UserPath(username), attribute]);
        if (!result.Succeeded)
            return null;

        foreach (var rawLine in result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (!line.StartsWith($"{attribute}:", StringComparison.OrdinalIgnoreCase))
                continue;
            return line[(attribute.Length + 1)..].Trim();
        }

        return null;
    }

    private int GetNextUid()
    {
        var result = _runner.RunChecked("/usr/bin/dscl", [".", "-list", "/Users", "UniqueID"]);
        var maxUid = 500;

        foreach (var rawLine in result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = rawLine.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length < 2 || !int.TryParse(parts[^1], out var uid))
                continue;
            if (uid > maxUid)
                maxUid = uid;
        }

        return maxUid + 1;
    }

    private void RunDscl(params string[] args)
        => _runner.RunChecked("/usr/bin/dscl", new[] { "." }.Concat(args));

    private static string UserPath(string username) => $"/Users/{username}";

    private static string GenerateBootstrapPassword()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
}

/// <summary>
/// Applies <c>MacOsSettings.local_accounts</c> directives against
/// local macOS account operations. Directory-bound hosts are refused
/// in v1 to avoid conflicting with external identity sources.
/// </summary>
public sealed class MacAccountEnforcer : IEnforcer
{
    private readonly IMacAccountOperations _ops;
    private readonly ILogger<MacAccountEnforcer> _log;

    public string Name => "Account";

    public MacAccountEnforcer(
        IMacAccountOperations ops,
        ILogger<MacAccountEnforcer> log)
    {
        _ops = ops;
        _log = log;
    }

    public Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive,
        EnforcementMode mode,
        CancellationToken ct = default)
    {
        if (directive.ValueKind != JsonValueKind.Array)
            return Task.FromResult(new EnforcementOutcome(EnforcementStatus.Skipped));

        if (_ops.IsDirectoryBound())
        {
            _log.LogWarning("Account enforcer refused: host is bound to an external directory source");
            return Task.FromResult(new EnforcementOutcome(
                EnforcementStatus.Skipped,
                "directory-bound hosts are out of scope for v1"));
        }

        var changes = new List<string>();
        string? firstError = null;
        var overallStatus = EnforcementStatus.Ok;

        foreach (var item in directive.EnumerateArray())
        {
            try
            {
                changes.Add(ApplyOne(item, mode));
            }
            catch (Exception ex)
            {
                var desc = DescribeDirective(item);
                _log.LogError(ex, "Account enforcer failed on {Directive}", desc);
                changes.Add($"FAILED: {desc} — {ex.Message}");
                firstError ??= ex.Message;
                overallStatus = EnforcementStatus.Failed;
            }
        }

        return Task.FromResult(new EnforcementOutcome(overallStatus, firstError, changes));
    }

    private string ApplyOne(JsonElement item, EnforcementMode mode)
    {
        var username = item.GetProperty("username").GetString() ?? throw new InvalidOperationException("missing username");
        var action = item.GetProperty("action").GetString() ?? throw new InvalidOperationException("missing action");
        var desc = $"{action} '{username}'";

        if (mode == EnforcementMode.Audit)
        {
            _log.LogInformation("[AUDIT] Account: would {Action}", desc);
            return $"[AUDIT] {desc}";
        }

        return action switch
        {
            "Create" => ApplyCreate(item, username),
            "Delete" => ApplyDelete(username),
            "Disable" => ApplyDisable(username),
            "Enable" => ApplyEnable(username),
            "Modify" => ApplyModify(item, username),
            _ => throw new InvalidOperationException($"unknown account action: {action}"),
        };
    }

    private string ApplyCreate(JsonElement item, string username)
    {
        var fullName = GetOptionalString(item, "full_name");
        var shell = GetOptionalString(item, "shell");
        var admin = GetOptionalBool(item, "admin") ?? false;
        var hidden = GetOptionalBool(item, "hidden") ?? false;

        if (_ops.UserExists(username))
            return ApplyModify(item, username);

        _ops.CreateUser(username, fullName, shell, admin, hidden);
        _log.LogInformation("Account: created '{User}'", username);
        return $"Create '{username}'";
    }

    private string ApplyDelete(string username)
    {
        if (!_ops.UserExists(username))
            return $"[NO-OP] Delete '{username}' (not found)";
        _ops.DeleteUser(username);
        _log.LogInformation("Account: deleted '{User}'", username);
        return $"Delete '{username}'";
    }

    private string ApplyDisable(string username)
    {
        if (!_ops.UserExists(username))
            return $"[NO-OP] Disable '{username}' (not found)";
        if (!_ops.IsEnabled(username))
            return $"[NO-OP] Disable '{username}' (already disabled)";
        _ops.DisableUser(username);
        _log.LogInformation("Account: disabled '{User}'", username);
        return $"Disable '{username}'";
    }

    private string ApplyEnable(string username)
    {
        if (!_ops.UserExists(username))
            return $"[NO-OP] Enable '{username}' (not found)";
        if (_ops.IsEnabled(username))
            return $"[NO-OP] Enable '{username}' (already enabled)";
        _ops.EnableUser(username);
        _log.LogInformation("Account: enabled '{User}'", username);
        return $"Enable '{username}'";
    }

    private string ApplyModify(JsonElement item, string username)
    {
        if (!_ops.UserExists(username))
            throw new InvalidOperationException($"user '{username}' does not exist");

        var changes = new List<string>();

        var shell = GetOptionalString(item, "shell");
        if (shell is not null && _ops.GetShell(username) != shell)
        {
            _ops.SetShell(username, shell);
            changes.Add($"shell={shell}");
        }

        var admin = GetOptionalBool(item, "admin");
        if (admin.HasValue && _ops.IsAdmin(username) != admin.Value)
        {
            _ops.SetAdmin(username, admin.Value);
            changes.Add($"admin={admin.Value}");
        }

        var hidden = GetOptionalBool(item, "hidden");
        if (hidden.HasValue && _ops.IsHidden(username) != hidden.Value)
        {
            _ops.SetHidden(username, hidden.Value);
            changes.Add($"hidden={hidden.Value}");
        }

        if (changes.Count == 0)
            return $"[NO-OP] Modify '{username}'";

        _log.LogInformation("Account: modified '{User}' ({Changes})", username, string.Join(", ", changes));
        return $"Modify '{username}' ({string.Join(", ", changes)})";
    }

    private static string? GetOptionalString(JsonElement item, string name)
        => item.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.GetString()
            : null;

    private static bool? GetOptionalBool(JsonElement item, string name)
        => item.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.GetBoolean()
            : null;

    private static string DescribeDirective(JsonElement item)
    {
        var user = item.TryGetProperty("username", out var u) ? u.GetString() : "?";
        var action = item.TryGetProperty("action", out var a) ? a.GetString() : "?";
        return $"{action} '{user}'";
    }
}
