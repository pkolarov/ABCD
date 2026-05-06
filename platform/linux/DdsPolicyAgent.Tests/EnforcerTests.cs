// SPDX-License-Identifier: MIT OR Apache-2.0
// Tests run on macOS/Linux; suppress CA1416 — this agent is Linux-only by design.
#pragma warning disable CA1416

using System.Text.Json;
using DDS.PolicyAgent.Linux.Enforcers;
using DDS.PolicyAgent.Linux.Runtime;
using Microsoft.Extensions.Logging.Abstractions;

namespace DDS.PolicyAgent.Linux.Tests;

// ============================================================
// UserEnforcer
// ============================================================

public sealed class UserEnforcerTests
{
    private static JsonElement ParseElement(string json)
        => JsonDocument.Parse(json).RootElement;

    [Theory]
    [InlineData("alice",    true)]
    [InlineData("alice123", true)]
    [InlineData("a-b_c.d", true)]
    [InlineData("",         false)]
    [InlineData("-alice",   false)]
    [InlineData("alice!",   false)]
    [InlineData("a b",      false)]
    [InlineData("toolongusernamethatexceedslimit123456789012", false)]
    public void UsernameValidation(string name, bool expected)
        => Assert.Equal(expected, UserEnforcer.IsValidUsername(name));

    [Fact]
    public async Task CreateUser_AuditOnlyLogsAndDoesNotInvokeRunner()
    {
        var runner = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var directives = new[]
        {
            ParseElement("""{"username":"alice","action":"Create","shell":"/bin/bash","groups":["sudo"]}"""),
        };

        var applied = await enforcer.ApplyAsync(directives, new HashSet<string>(), default);

        Assert.Single(applied);
        Assert.Equal("user:create:alice", applied[0]);
        // Audit mode: runner must NOT have been called with useradd
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task CreateUser_EnforceMode_CallsUseradd()
    {
        var runner = new NullCommandRunner();
        // Make `id -u` return exit 1 so the enforcer treats the user as absent.
        runner.ExitCodeOverrides["id"] = 1;
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var directives = new[]
        {
            ParseElement("""{"username":"bob","action":"Create","uid":1500,"shell":"/bin/sh"}"""),
        };

        await enforcer.ApplyAsync(directives, new HashSet<string>(), default);

        Assert.Contains(runner.Invocations, i => i.FileName == "useradd");
        var addArgs = runner.Invocations.First(i => i.FileName == "useradd").Arguments;
        Assert.Contains("bob", addArgs);
        Assert.Contains("1500", addArgs);
    }

    [Fact]
    public async Task DeleteUser_RefusedWhenNotManaged()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var directives = new[]
        {
            ParseElement("""{"username":"root","action":"Delete"}"""),
        };

        var applied = await enforcer.ApplyAsync(
            directives, new HashSet<string>(["alice"]), default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task UidBelowMinimumIsRejected()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var directives = new[]
        {
            ParseElement("""{"username":"lowuid","action":"Create","uid":500}"""),
        };

        var applied = await enforcer.ApplyAsync(directives, new HashSet<string>(), default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Theory]
    [InlineData("/bin/bash",       true)]
    [InlineData("/usr/bin/zsh",    true)]
    [InlineData("/bin/sh",         true)]
    [InlineData("/sbin/nologin",   true)]
    [InlineData("bash",            false)]  // not absolute
    [InlineData("/bin/bash -x",    false)]  // space — would inject a flag
    [InlineData("/bin/bash\t",     false)]  // tab
    [InlineData("/bin/ba$h",       false)]  // $ metacharacter
    [InlineData("/bin/ba;sh",      false)]  // ; metacharacter
    [InlineData("",                false)]
    public void ShellPathValidation(string shell, bool expected)
        => Assert.Equal(expected, UserEnforcer.IsSafeShellPath(shell));

    [Fact]
    public async Task Create_UnsafeShell_Skipped()
    {
        var runner = new NullCommandRunner();
        runner.ExitCodeOverrides["id"] = 1;
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        // Shell with a space would allow injecting "-g root" as an extra useradd flag.
        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"username":"alice","action":"Create","shell":"/bin/bash -g root"}""")],
            new HashSet<string>(), default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task Modify_UnsafeShell_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"username":"alice","action":"Modify","shell":"/bin/bash -g root"}""")],
            new HashSet<string>(), default);

        // The Modify action itself still succeeds (groups may be applied), but usermod
        // is not called with the unsafe shell flag.
        Assert.DoesNotContain(runner.Invocations, i =>
            i.FileName == "usermod" && i.Arguments.Contains("-s"));
    }

    [Theory]
    [InlineData("sudo",       true)]
    [InlineData("wheel",      true)]
    [InlineData("dds-ops",    true)]
    [InlineData("dds_ops",    true)]
    [InlineData("",           false)]
    [InlineData("-wheel",     false)]  // starts with '-' — would be parsed as a usermod flag
    [InlineData("wh eel",     false)]  // space — causes argument split
    [InlineData("wh\teel",    false)]  // tab
    [InlineData("wh;eel",     false)]  // semicolon
    [InlineData("wh$eel",     false)]  // dollar
    [InlineData("toolonggroupnamethatexceedslimit123456789012", false)]
    public void GroupNameValidation(string name, bool expected)
        => Assert.Equal(expected, UserEnforcer.IsValidGroupName(name));

    [Fact]
    public async Task Create_UnsafeGroupName_Skipped()
    {
        var runner = new NullCommandRunner();
        runner.ExitCodeOverrides["id"] = 1;
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        // Group name with a leading '-' would inject a flag into "usermod -aG".
        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"username":"alice","action":"Create","groups":["-G root"]}""")],
            new HashSet<string>(), default);

        // useradd still runs (create is valid), but the unsafe group is never passed to usermod.
        Assert.Contains(runner.Invocations, i => i.FileName == "useradd");
        Assert.DoesNotContain(runner.Invocations, i =>
            i.FileName == "usermod" && i.Arguments.Contains("-G root"));
    }

    [Fact]
    public async Task Create_MixedGroups_SafeGroupApplied_UnsafeSkipped()
    {
        var runner = new NullCommandRunner();
        runner.ExitCodeOverrides["id"] = 1;
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"username":"alice","action":"Create","groups":["sudo","-bad","wh eel"]}""")],
            new HashSet<string>(), default);

        // Only "sudo" is valid; the other two are skipped.
        Assert.Contains(runner.Invocations, i =>
            i.FileName == "usermod" && i.Arguments.Contains("sudo") && i.Arguments.Contains("alice"));
        Assert.DoesNotContain(runner.Invocations, i =>
            i.FileName == "usermod" && i.Arguments.Contains("-bad"));
        Assert.DoesNotContain(runner.Invocations, i =>
            i.FileName == "usermod" && i.Arguments.Contains("wh eel"));
    }

    [Fact]
    public async Task Disable_AuditOnly_NoRunnerCall()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"username":"alice","action":"Disable"}""")],
            new HashSet<string>(), default);

        Assert.Single(applied);
        Assert.Equal("user:disable:alice", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task Disable_EnforceMode_CallsPasswdLock()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"username":"alice","action":"Disable"}""")],
            new HashSet<string>(), default);

        Assert.Single(applied);
        Assert.Equal("user:disable:alice", applied[0]);
        Assert.Single(runner.Invocations);
        Assert.Equal("passwd", runner.Invocations[0].FileName);
        Assert.Contains("-l", runner.Invocations[0].Arguments);
        Assert.Contains("alice", runner.Invocations[0].Arguments);
    }

    [Fact]
    public async Task Enable_EnforceMode_CallsPasswdUnlock()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"username":"alice","action":"Enable"}""")],
            new HashSet<string>(), default);

        Assert.Single(applied);
        Assert.Equal("user:enable:alice", applied[0]);
        Assert.Single(runner.Invocations);
        Assert.Equal("passwd", runner.Invocations[0].FileName);
        Assert.Contains("-u", runner.Invocations[0].Arguments);
        Assert.Contains("alice", runner.Invocations[0].Arguments);
    }

    [Fact]
    public async Task Modify_HappyPath_UpdatesShell()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"username":"alice","action":"Modify","shell":"/usr/sbin/nologin"}""")],
            new HashSet<string>(), default);

        Assert.Single(applied);
        Assert.Equal("user:modify:alice", applied[0]);
        Assert.Contains(runner.Invocations, i =>
            i.FileName == "usermod" && i.Arguments.Contains("-s") && i.Arguments.Contains("alice"));
    }
}

// ============================================================
// SudoersEnforcer
// ============================================================

public sealed class SudoersEnforcerTests
{
    [Theory]
    [InlineData("dds-ops",   true)]
    [InlineData("dds_ops",   true)]
    [InlineData("../etc",    false)]
    [InlineData("dds/ops",   false)]
    [InlineData("dds.ops",   false)]
    [InlineData("",          false)]
    public void FilenameValidation(string name, bool expected)
        => Assert.Equal(expected, SudoersEnforcer.IsSafeFilename(name));

    [Fact]
    public async Task SetDropin_AuditOnlyDoesNotCallRunner()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SudoersEnforcer(runner, auditOnly: true, NullLogger.Instance);

        // Omit content_sha256 so no hash check is performed; we're testing audit routing.
        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse(
                """{"filename":"dds-ops","content":"%ops ALL=(ALL) NOPASSWD: ALL"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("sudoers:set:dds-ops", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task DeleteDropin_EmptyContentTreatedAsDelete()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SudoersEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse(
                """{"filename":"dds-ops","content":"","content_sha256":""}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("sudoers:delete:dds-ops", applied[0]);
    }

    [Fact]
    public async Task UnsafeFilenameSkipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SudoersEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse(
                """{"filename":"../etc/passwd","content":"x","content_sha256":""}""").RootElement],
            default);

        Assert.Empty(applied);
    }
}

// ============================================================
// FileEnforcer
// ============================================================

public sealed class FileEnforcerTests
{
    [Theory]
    [InlineData("/etc/dds/motd",                  true)]
    [InlineData("/etc/dds/conf.d/custom.conf",    true)]
    [InlineData("/etc/ssh/sshd_config.d/60-dds.conf", true)]
    [InlineData("/etc/sysctl.d/60-dds.conf",      true)]
    [InlineData("/etc/systemd/system/foo.service", true)]
    [InlineData("/usr/local/lib/dds/helper",      true)]
    [InlineData("relative/path",                  false)]
    [InlineData("/etc/../etc/passwd",             false)]
    [InlineData("/etc/passwd",                    false)]  // outside allowlist
    [InlineData("/etc/shadow",                    false)]  // outside allowlist
    [InlineData("/boot/grub.cfg",                 false)]  // outside allowlist
    [InlineData("/home/alice/file",               false)]  // outside allowlist
    [InlineData("/tmp/evil",                      false)]  // outside allowlist
    public void PathValidation(string path, bool expected)
        => Assert.Equal(expected, FileEnforcer.IsSafePath(path));

    [Fact]
    public async Task SetFile_AuditOnlyDoesNotWrite()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""
                {"path":"/etc/dds/motd","action":"Set",
                 "content_b64":"aGVsbG8=","content_sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}
                """).RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal("file:set:/etc/dds/motd", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task DeleteFile_RefusedWhenNotManaged()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"path":"/etc/passwd","action":"Delete"}""").RootElement],
            new HashSet<string>(["/etc/dds/motd"]),
            default);

        Assert.Empty(applied);
    }

    [Fact]
    public async Task Sha256MismatchSkipsWrite()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""
                {"path":"/etc/dds/motd","action":"Set",
                 "content_b64":"aGVsbG8=","content_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}
                """).RootElement],
            new HashSet<string>(),
            default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Theory]
    [InlineData("root",            true)]
    [InlineData("www-data",        true)]
    [InlineData("root:root",       true)]
    [InlineData("nobody:nogroup",  true)]
    [InlineData("nobody /etc/shadow", false)]  // space — would inject extra chown target
    [InlineData("root /etc/passwd",   false)]  // space injection
    [InlineData("",                false)]
    [InlineData("root:root:extra", false)]      // too many colons
    public void OwnerValidation(string owner, bool expected)
        => Assert.Equal(expected, FileEnforcer.IsSafeOwner(owner));

    [Theory]
    [InlineData("644",         true)]
    [InlineData("0644",        true)]
    [InlineData("1777",        true)]
    [InlineData("777",         true)]
    [InlineData("u+x",         false)]   // symbolic — could contain spaces
    [InlineData("644 /etc/shadow", false)]  // space injection
    [InlineData("",            false)]
    [InlineData("99",          false)]   // too short
    [InlineData("08644",       false)]   // too long
    [InlineData("888",         false)]   // non-octal digit
    public void ModeValidation(string mode, bool expected)
        => Assert.Equal(expected, FileEnforcer.IsSafeMode(mode));

    [Fact]
    public async Task UnsafeOwner_SkipsChown()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: true, NullLogger.Instance);

        // Even in audit mode the runner should not be called with a chown for an unsafe owner.
        // (audit mode returns true for ApplySetAsync but never invokes the runner.)
        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""
                {"path":"/etc/dds/motd","action":"Set",
                 "content_b64":"aGVsbG8=",
                 "content_sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                 "owner":"nobody /etc/shadow","mode":"644"}
                """).RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);  // file:set was recorded
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "chown");
    }

    [Fact]
    public async Task UnsafeMode_SkipsChmod()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""
                {"path":"/etc/dds/motd","action":"Set",
                 "content_b64":"aGVsbG8=",
                 "content_sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                 "mode":"777 /etc/shadow"}
                """).RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);  // file:set was recorded
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "chmod");
    }

    [Fact]
    public async Task EnsureDir_AuditOnly_NoRunnerCall()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"path":"/etc/dds/conf.d","action":"EnsureDir","owner":"root","mode":"0750"}""")
                .RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal("file:ensuredir:/etc/dds/conf.d", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task EnsureDir_EnforceMode_CallsChownAndChmod()
    {
        // Use a temp directory that actually exists so Directory.CreateDirectory is a no-op.
        // Inject the temp prefix into the enforcer's allowlist so the path passes IsSafePath.
        var tmpBase = Path.GetTempPath().TrimEnd('/') + "/";
        var path    = Path.Combine(Path.GetTempPath(), "dds-test-ensuredir");
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: false, NullLogger.Instance,
            allowedPrefixes: [tmpBase]);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse($$$"""{"path":"{{{path}}}","action":"EnsureDir","owner":"root:root","mode":"0755"}""")
                .RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal($"file:ensuredir:{path}", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "chown");
        Assert.Contains(runner.Invocations, i => i.FileName == "chmod");
    }

    [Fact]
    public async Task EnsureDir_EnforceMode_UnsafeOwner_SkipsChown()
    {
        var tmpBase = Path.GetTempPath().TrimEnd('/') + "/";
        var path    = Path.Combine(Path.GetTempPath(), "dds-test-ensuredir");
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: false, NullLogger.Instance,
            allowedPrefixes: [tmpBase]);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse($$$"""{"path":"{{{path}}}","action":"EnsureDir","owner":"nobody /etc/shadow","mode":"0750"}""")
                .RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "chown");
        // chmod still runs because mode is safe
        Assert.Contains(runner.Invocations, i => i.FileName == "chmod");
    }

    [Fact]
    public async Task EnsureDir_EnforceMode_UnsafeMode_SkipsChmod()
    {
        var tmpBase = Path.GetTempPath().TrimEnd('/') + "/";
        var path    = Path.Combine(Path.GetTempPath(), "dds-test-ensuredir");
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: false, NullLogger.Instance,
            allowedPrefixes: [tmpBase]);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse($$$"""{"path":"{{{path}}}","action":"EnsureDir","owner":"root","mode":"777 /etc/shadow"}""")
                .RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        // chown still runs because owner is safe
        Assert.Contains(runner.Invocations, i => i.FileName == "chown");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "chmod");
    }

    [Fact]
    public async Task SetFile_OutsideAllowlist_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""
                {"path":"/etc/passwd","action":"Set",
                 "content_b64":"aGVsbG8=","content_sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}
                """).RootElement],
            new HashSet<string>(),
            default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }
}

// ============================================================
// SystemdEnforcer
// ============================================================

public sealed class SystemdEnforcerTests
{
    [Theory]
    [InlineData("sshd.service",     true)]
    [InlineData("cron.timer",       true)]
    [InlineData("dds.target",       true)]
    [InlineData("badunit",          false)]
    [InlineData("../sshd.service",  false)]
    [InlineData("",                 false)]
    public void UnitNameValidation(string name, bool expected)
        => Assert.Equal(expected, SystemdEnforcer.IsSafeUnitName(name));

    [Theory]
    [InlineData("dds-limits", true)]
    [InlineData("dds_opts",   true)]
    [InlineData("dds.conf",   false)]
    [InlineData("",           false)]
    public void DropinStemValidation(string stem, bool expected)
        => Assert.Equal(expected, SystemdEnforcer.IsSafeDropinStem(stem));

    [Fact]
    public async Task EnableUnit_AuditOnlyNoRunner()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"sshd.service","action":"Enable"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:enable:sshd.service", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task EnableUnit_EnforceMode_CallsSystemctl()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"sshd.service","action":"Enable"}""").RootElement],
            default);

        Assert.Single(runner.Invocations);
        Assert.Equal("systemctl", runner.Invocations[0].FileName);
        Assert.Contains("enable", runner.Invocations[0].Arguments);
        Assert.Contains("sshd.service", runner.Invocations[0].Arguments);
    }

    [Fact]
    public async Task UnsafeUnitNameSkipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"badunit","action":"Start"}""").RootElement],
            default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task MaskUnit_AuditOnly_NoRunner()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"telnet.service","action":"Mask"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:mask:telnet.service", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task MaskUnit_EnforceMode_CallsSystemctl()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"telnet.service","action":"Mask"}""").RootElement],
            default);

        Assert.Single(runner.Invocations);
        Assert.Equal("systemctl", runner.Invocations[0].FileName);
        Assert.Contains("mask", runner.Invocations[0].Arguments);
        Assert.Contains("telnet.service", runner.Invocations[0].Arguments);
    }

    [Fact]
    public async Task UnmaskUnit_EnforceMode_CallsSystemctl()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"telnet.service","action":"Unmask"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:unmask:telnet.service", applied[0]);
        Assert.Single(runner.Invocations);
        Assert.Equal("systemctl", runner.Invocations[0].FileName);
        Assert.Contains("unmask", runner.Invocations[0].Arguments);
    }

    [Fact]
    public async Task DisableUnit_AuditOnly_NoRunner()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"telnet.service","action":"Disable"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:disable:telnet.service", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task DisableUnit_EnforceMode_CallsSystemctl()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"telnet.service","action":"Disable"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:disable:telnet.service", applied[0]);
        Assert.Single(runner.Invocations);
        Assert.Equal("systemctl", runner.Invocations[0].FileName);
        Assert.Contains("disable", runner.Invocations[0].Arguments);
        Assert.Contains("telnet.service", runner.Invocations[0].Arguments);
    }

    [Fact]
    public async Task StartUnit_EnforceMode_CallsSystemctl()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"ntp.service","action":"Start"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:start:ntp.service", applied[0]);
        Assert.Single(runner.Invocations);
        Assert.Equal("systemctl", runner.Invocations[0].FileName);
        Assert.Contains("start", runner.Invocations[0].Arguments);
        Assert.Contains("ntp.service", runner.Invocations[0].Arguments);
    }

    [Fact]
    public async Task StopUnit_EnforceMode_CallsSystemctl()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"ntp.service","action":"Stop"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:stop:ntp.service", applied[0]);
        Assert.Single(runner.Invocations);
        Assert.Equal("systemctl", runner.Invocations[0].FileName);
        Assert.Contains("stop", runner.Invocations[0].Arguments);
        Assert.Contains("ntp.service", runner.Invocations[0].Arguments);
    }

    [Fact]
    public async Task RestartUnit_EnforceMode_CallsSystemctl()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"sshd.service","action":"Restart"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:restart:sshd.service", applied[0]);
        Assert.Single(runner.Invocations);
        Assert.Equal("systemctl", runner.Invocations[0].FileName);
        Assert.Contains("restart", runner.Invocations[0].Arguments);
        Assert.Contains("sshd.service", runner.Invocations[0].Arguments);
    }

    [Fact]
    public async Task ConfigureDropin_AuditOnly_ReturnsDirectiveTagWithoutWrite()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""
                {"unit":"sshd.service","action":"ConfigureDropin",
                 "dropin_name":"dds-limits","dropin_content":"[Service]\nLimitNOFILE=1024\n"}
                """).RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:configuredropin:sshd.service/dds-limits", applied[0]);
        // Audit mode: no systemctl daemon-reload should be called
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ConfigureDropin_MissingDropinName_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"sshd.service","action":"ConfigureDropin","dropin_content":"[Service]\nX=1\n"}""")
                .RootElement],
            default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ConfigureDropin_UnsafeDropinStemSkipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        // dropin_name with a dot is rejected by IsSafeDropinStem
        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""
                {"unit":"sshd.service","action":"ConfigureDropin",
                 "dropin_name":"dds.conf","dropin_content":"[Service]\nX=1\n"}
                """).RootElement],
            default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ConfigureDropin_EnforceMode_WritesFileAndCallsDaemonReload()
    {
        var tmpBase  = Path.Combine(Path.GetTempPath(), "dds-systemd-" + Guid.NewGuid());
        try
        {
            var runner   = new NullCommandRunner();
            var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance,
                dropinBase: tmpBase);

            var applied = await enforcer.ApplyAsync(
                [JsonDocument.Parse("""
                    {"unit":"sshd.service","action":"ConfigureDropin",
                     "dropin_name":"dds-limits","dropin_content":"[Service]\nLimitNOFILE=1024\n"}
                    """).RootElement],
                default);

            Assert.Single(applied);
            Assert.Equal("systemd:configuredropin:sshd.service/dds-limits", applied[0]);

            // Enforce mode: daemon-reload must be called after writing the drop-in.
            Assert.Single(runner.Invocations);
            Assert.Equal("systemctl", runner.Invocations[0].FileName);
            Assert.Contains("daemon-reload", runner.Invocations[0].Arguments);

            // The drop-in file must be written at the injected base path.
            var dropinPath = Path.Combine(tmpBase, "sshd.service.d", "dds-limits.conf");
            Assert.True(File.Exists(dropinPath));
            var content = await File.ReadAllTextAsync(dropinPath);
            Assert.Contains("LimitNOFILE=1024", content);
        }
        finally
        {
            if (Directory.Exists(tmpBase))
                Directory.Delete(tmpBase, recursive: true);
        }
    }

    [Fact]
    public async Task RemoveDropin_AuditOnly_ReturnsDirectiveTag()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"sshd.service","action":"RemoveDropin","dropin_name":"dds-limits"}""")
                .RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:removedropin:sshd.service/dds-limits", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task UnmaskUnit_AuditOnly_NoRunner()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"telnet.service","action":"Unmask"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:unmask:telnet.service", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task StartUnit_AuditOnly_NoRunner()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"ntp.service","action":"Start"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:start:ntp.service", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task StopUnit_AuditOnly_NoRunner()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"ntp.service","action":"Stop"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:stop:ntp.service", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task RestartUnit_AuditOnly_NoRunner()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"sshd.service","action":"Restart"}""").RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:restart:sshd.service", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task RemoveDropin_EnforceMode_CallsDaemonReload()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"sshd.service","action":"RemoveDropin","dropin_name":"dds-limits"}""")
                .RootElement],
            default);

        Assert.Single(applied);
        Assert.Equal("systemd:removedropin:sshd.service/dds-limits", applied[0]);
        // Enforce mode: needReload=true triggers daemon-reload even when file does not exist.
        Assert.Single(runner.Invocations);
        Assert.Equal("systemctl", runner.Invocations[0].FileName);
        Assert.Contains("daemon-reload", runner.Invocations[0].Arguments);
    }

    [Fact]
    public async Task RemoveDropin_MissingDropinName_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"sshd.service","action":"RemoveDropin"}""").RootElement],
            default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task RemoveDropin_UnsafeDropinStem_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        // dropin_name with a dot is rejected by IsSafeDropinStem
        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"unit":"sshd.service","action":"RemoveDropin","dropin_name":"dds.conf"}""")
                .RootElement],
            default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }
}

// ============================================================
// PackageEnforcer
// ============================================================

public sealed class PackageEnforcerTests
{
    [Theory]
    [InlineData("ntp",       true)]
    [InlineData("g++",       true)]
    [InlineData("libssl1.0", true)]
    [InlineData("bad pkg",   false)]
    [InlineData("",          false)]
    public void PackageNameValidation(string name, bool expected)
        => Assert.Equal(expected, PackageEnforcer.IsValidPackageName(name));

    [Fact]
    public async Task InstallPackage_AuditOnlyNoRunner()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new PackageEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"ntp","action":"Install"}""").RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:install:ntp", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task RemovePackage_RefusedWhenNotManaged()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"bash","action":"Remove"}""").RootElement],
            new HashSet<string>(["ntp"]),
            default);

        Assert.Empty(applied);
    }

    [Fact]
    public async Task UnsafePackageNameSkipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"bad pkg","action":"Install"}""").RootElement],
            new HashSet<string>(),
            default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Theory]
    [InlineData("1.2.3",                                                                   true)]
    [InlineData("1:2.3.4-5",                                                               true)]
    [InlineData("2.3.1-1.fc38",                                                            true)]
    [InlineData("1.0+dfsg",                                                                true)]
    [InlineData("1.0~rc1",                                                                 true)]
    [InlineData("",                                                                        false)]  // empty
    [InlineData("1.0 --force",                                                             false)]  // space
    [InlineData("1.0;rm -rf /",                                                            false)]  // semicolon
    [InlineData("$(evil)",                                                                 false)]  // dollar
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",     false)]  // 67 chars > 64
    public void VersionValidation(string version, bool expected)
        => Assert.Equal(expected, PackageEnforcer.IsValidVersion(version));

    [Fact]
    public async Task Install_UnsafeVersion_SkippedNoRunner()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        // Version with a space would split into extra arguments; must be rejected.
        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"ntp","action":"Install","version":"1.0 --no-verify-gpg"}""").RootElement],
            new HashSet<string>(),
            default);

        // The directive tag is not emitted and no runner call is made.
        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task Install_ValidVersion_AuditOnlyNoRunner()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new PackageEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"ntp","action":"Install","version":"1:4.2.8p15+dfsg-1"}""").RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:install:ntp", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task InstallPackage_ZypperBackend_CallsZypperInstall()
    {
        var runner = new NullCommandRunner();
        // Make apt-get and dnf absent; zypper present.
        runner.InvocationExitCodeOverrides[("which", "apt-get")] = 1;
        runner.InvocationExitCodeOverrides[("which", "dnf")]     = 1;
        runner.InvocationExitCodeOverrides[("which", "zypper")]  = 0;
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"vim","action":"Install"}""").RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:install:vim", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "zypper" && i.Arguments == "install -y vim");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "apt-get");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "dnf");
    }

    [Fact]
    public async Task InstallPackage_ZypperBackend_WithVersion_UsesEqualsSeparator()
    {
        var runner = new NullCommandRunner();
        runner.InvocationExitCodeOverrides[("which", "apt-get")] = 1;
        runner.InvocationExitCodeOverrides[("which", "dnf")]     = 1;
        runner.InvocationExitCodeOverrides[("which", "zypper")]  = 0;
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"vim","action":"Install","version":"9.0.1-1"}""").RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Contains(runner.Invocations, i => i.FileName == "zypper" && i.Arguments == "install -y vim=9.0.1-1");
    }

    [Fact]
    public async Task RemovePackage_ZypperBackend_CallsZypperRemove()
    {
        var runner = new NullCommandRunner();
        runner.InvocationExitCodeOverrides[("which", "apt-get")] = 1;
        runner.InvocationExitCodeOverrides[("which", "dnf")]     = 1;
        runner.InvocationExitCodeOverrides[("which", "zypper")]  = 0;
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"vim","action":"Remove"}""").RootElement],
            new HashSet<string>(["vim"]),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:remove:vim", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "zypper" && i.Arguments == "remove -y vim");
    }

    [Fact]
    public async Task InstallPackage_AptBackend_CallsAptGet()
    {
        // Default NullCommandRunner returns exit 0 for "which apt-get", selecting the Apt backend.
        var runner   = new NullCommandRunner();
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"ntp","action":"Install"}""").RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:install:ntp", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "apt-get" && i.Arguments == "install -y ntp");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "dnf");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "zypper");
    }

    [Fact]
    public async Task RemovePackage_AptBackend_CallsAptGet()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"ntp","action":"Remove"}""").RootElement],
            new HashSet<string>(["ntp"]),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:remove:ntp", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "apt-get" && i.Arguments == "remove -y ntp");
    }

    [Fact]
    public async Task InstallPackage_AptBackend_WithVersion_UsesEqualsSeparator()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"ntp","action":"Install","version":"1:4.2.8p15-1"}""").RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:install:ntp", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "apt-get" && i.Arguments == "install -y ntp=1:4.2.8p15-1");
    }

    [Fact]
    public async Task InstallPackage_DnfBackend_CallsDnf()
    {
        var runner = new NullCommandRunner();
        runner.InvocationExitCodeOverrides[("which", "apt-get")] = 1;
        runner.InvocationExitCodeOverrides[("which", "dnf")]     = 0;
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"httpd","action":"Install"}""").RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:install:httpd", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "dnf" && i.Arguments == "install -y httpd");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "apt-get");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "zypper");
    }

    [Fact]
    public async Task RemovePackage_DnfBackend_CallsDnf()
    {
        var runner = new NullCommandRunner();
        runner.InvocationExitCodeOverrides[("which", "apt-get")] = 1;
        runner.InvocationExitCodeOverrides[("which", "dnf")]     = 0;
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"httpd","action":"Remove"}""").RootElement],
            new HashSet<string>(["httpd"]),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:remove:httpd", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "dnf" && i.Arguments == "remove -y httpd");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "apt-get");
    }

    [Fact]
    public async Task InstallPackage_DnfBackend_WithVersion_UsesEqualsSeparator()
    {
        var runner = new NullCommandRunner();
        runner.InvocationExitCodeOverrides[("which", "apt-get")] = 1;
        runner.InvocationExitCodeOverrides[("which", "dnf")]     = 0;
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"httpd","action":"Install","version":"2.4.54-1"}""").RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:install:httpd", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "dnf" && i.Arguments == "install -y httpd=2.4.54-1");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "apt-get");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "zypper");
    }

    [Fact]
    public async Task InstallPackage_RpmBackend_CallsRpm()
    {
        var runner = new NullCommandRunner();
        runner.InvocationExitCodeOverrides[("which", "apt-get")] = 1;
        runner.InvocationExitCodeOverrides[("which", "dnf")]     = 1;
        runner.InvocationExitCodeOverrides[("which", "zypper")]  = 1;
        runner.InvocationExitCodeOverrides[("which", "rpm")]     = 0;
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"bash","action":"Install"}""").RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:install:bash", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "rpm" && i.Arguments == "-i bash");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "apt-get");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "dnf");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "zypper");
    }

    [Fact]
    public async Task InstallPackage_RpmBackend_WithVersion_UsesEqualsSeparator()
    {
        var runner = new NullCommandRunner();
        runner.InvocationExitCodeOverrides[("which", "apt-get")] = 1;
        runner.InvocationExitCodeOverrides[("which", "dnf")]     = 1;
        runner.InvocationExitCodeOverrides[("which", "zypper")]  = 1;
        runner.InvocationExitCodeOverrides[("which", "rpm")]     = 0;
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"bash","action":"Install","version":"5.1.8-6.el9"}""").RootElement],
            new HashSet<string>(),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:install:bash", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "rpm" && i.Arguments == "-i bash=5.1.8-6.el9");
    }

    [Fact]
    public async Task RemovePackage_RpmBackend_CallsRpm()
    {
        var runner = new NullCommandRunner();
        runner.InvocationExitCodeOverrides[("which", "apt-get")] = 1;
        runner.InvocationExitCodeOverrides[("which", "dnf")]     = 1;
        runner.InvocationExitCodeOverrides[("which", "zypper")]  = 1;
        runner.InvocationExitCodeOverrides[("which", "rpm")]     = 0;
        var enforcer = new PackageEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [JsonDocument.Parse("""{"name":"bash","action":"Remove"}""").RootElement],
            new HashSet<string>(["bash"]),
            default);

        Assert.Single(applied);
        Assert.Equal("pkg:remove:bash", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "rpm" && i.Arguments == "-e bash");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "apt-get");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "dnf");
        Assert.DoesNotContain(runner.Invocations, i => i.FileName == "zypper");
    }
}

// ============================================================
// SysctlEnforcer
// ============================================================

public sealed class SysctlEnforcerTests
{
    private static JsonElement ParseElement(string json)
        => JsonDocument.Parse(json).RootElement;

    [Theory]
    [InlineData("net.ipv4.ip_forward",   true)]
    [InlineData("vm.swappiness",         true)]
    [InlineData("kernel.sysrq",          true)]
    [InlineData("a.b_c.d1",              true)]
    [InlineData("",                      false)]
    [InlineData("net..ipv4",             false)]  // empty segment
    [InlineData(".leading",              false)]  // leading dot
    [InlineData("trailing.",             false)]  // trailing dot
    [InlineData("net.ipv4.ip forward",   false)]  // space
    [InlineData("net.ipv4.ip-forward",   false)]  // hyphen not allowed
    public void KeyValidation(string key, bool expected)
        => Assert.Equal(expected, SysctlEnforcer.IsValidKey(key));

    [Theory]
    [InlineData("1",     true)]
    [InlineData("0",     true)]
    [InlineData("65536", true)]
    [InlineData("",      true)]   // empty string is valid (some params accept it)
    [InlineData("hello", true)]
    [InlineData("val;rm -rf /", false)]  // shell metacharacter
    [InlineData("val`cmd`",     false)]  // backtick
    [InlineData("val$PATH",     false)]  // dollar
    [InlineData("val|cmd",      false)]  // pipe
    public void ValueValidation(string value, bool expected)
        => Assert.Equal(expected, SysctlEnforcer.IsValidValue(value));

    [Fact]
    public async Task EmptyDirectivesReturnsEmpty()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SysctlEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync([], default);
        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task SetDirective_AuditOnly_NoRunnerCall()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SysctlEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"key":"net.ipv4.ip_forward","value":"1","action":"Set"}""")],
            default);

        Assert.Single(applied);
        Assert.Equal("sysctl:set:net.ipv4.ip_forward", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task SetDirective_AuditOnly_NoRunnerCall_MultipleKeys()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SysctlEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [
                ParseElement("""{"key":"vm.swappiness","value":"10","action":"Set"}"""),
                ParseElement("""{"key":"net.ipv4.ip_forward","value":"1","action":"Set"}"""),
            ],
            default);

        Assert.Equal(2, applied.Count);
        Assert.Contains("sysctl:set:vm.swappiness", applied);
        Assert.Contains("sysctl:set:net.ipv4.ip_forward", applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task DeleteDirective_ReturnsEntry()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SysctlEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"key":"net.ipv4.ip_forward","action":"Delete"}""")],
            default);

        Assert.Single(applied);
        Assert.Equal("sysctl:delete:net.ipv4.ip_forward", applied[0]);
    }

    [Fact]
    public async Task UnsafeKeySkipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SysctlEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"key":"net.ipv4.ip-forward","value":"1","action":"Set"}""")],
            default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task UnsafeValueSkipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SysctlEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"key":"net.ipv4.ip_forward","value":"1;rm -rf /","action":"Set"}""")],
            default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task MissingValueOnSetSkipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SysctlEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"key":"net.ipv4.ip_forward","action":"Set"}""")],
            default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task UnknownActionSkipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SysctlEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(
            [ParseElement("""{"key":"net.ipv4.ip_forward","value":"1","action":"Bogus"}""")],
            default);

        Assert.Empty(applied);
    }
}

// ============================================================
// SshdEnforcer
// ============================================================

public sealed class SshdEnforcerTests
{
    private static JsonElement ParseObject(string json)
        => JsonDocument.Parse(json).RootElement;

    [Theory]
    [InlineData("alice",    true)]
    [InlineData("dds-ops",  true)]
    [InlineData("dds.ops",  true)]
    [InlineData("",         false)]
    [InlineData("1alice",   false)]  // starts with digit
    [InlineData("alice!",   false)]  // illegal char
    [InlineData("toolongusernamethatexceedslimit123456789012", false)]
    public void NameValidation(string name, bool expected)
        => Assert.Equal(expected, SshdEnforcer.IsValidName(name));

    [Fact]
    public async Task NullPolicy_NoDropinPresent_ReturnsEmpty()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ApplyAsync(null, default);
        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task EmptyPolicyObject_NoDropinPresent_ReturnsEmpty()
    {
        // No recognized fields → no dropin present → no-op (same as null policy when dropin absent).
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var policy = ParseObject("{}");
        var applied = await enforcer.ApplyAsync(policy, default);
        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task AllFieldsInvalid_NoDropinPresent_ReturnsEmpty()
    {
        // All fields have invalid values → lines.Count == 0 → same cleanup path as empty object.
        // When no dropin exists (common in CI), behaves as a no-op.
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var policy = ParseObject("""{"permit_root_login":"maybe","allow_users":["bad user"]}""");
        var applied = await enforcer.ApplyAsync(policy, default);
        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task PasswordAuth_False_AuditOnly_NoRunnerCall()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var policy = ParseObject("""{"password_authentication":false}""");
        var applied = await enforcer.ApplyAsync(policy, default);

        Assert.Single(applied);
        Assert.Equal("sshd:set:PasswordAuthentication=False", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task PasswordAuth_True_RecordedCorrectly()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var policy = ParseObject("""{"password_authentication":true}""");
        var applied = await enforcer.ApplyAsync(policy, default);

        Assert.Single(applied);
        Assert.Equal("sshd:set:PasswordAuthentication=True", applied[0]);
    }

    [Fact]
    public async Task PubkeyAuth_AppliedWithSshd()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var policy = ParseObject("""{"pubkey_authentication":true}""");
        var applied = await enforcer.ApplyAsync(policy, default);

        Assert.Single(applied);
        Assert.Equal("sshd:set:PubkeyAuthentication=True", applied[0]);
    }

    [Fact]
    public async Task PermitRootLogin_ValidValue_Applied()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var policy = ParseObject("""{"permit_root_login":"prohibit-password"}""");
        var applied = await enforcer.ApplyAsync(policy, default);

        Assert.Single(applied);
        Assert.Equal("sshd:set:PermitRootLogin=prohibit-password", applied[0]);
    }

    [Fact]
    public async Task PermitRootLogin_InvalidValue_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var policy = ParseObject("""{"permit_root_login":"maybe"}""");
        var applied = await enforcer.ApplyAsync(policy, default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task AllowUsers_ValidNames_Applied()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var policy = ParseObject("""{"allow_users":["alice","bob"]}""");
        var applied = await enforcer.ApplyAsync(policy, default);

        Assert.Single(applied);
        Assert.Equal("sshd:set:AllowUsers=alice,bob", applied[0]);
    }

    [Fact]
    public async Task AllowUsers_UnsafeNameFiltered()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        // "bad user" contains a space — should be filtered, leaving empty list → no directive
        var policy = ParseObject("""{"allow_users":["bad user"]}""");
        var applied = await enforcer.ApplyAsync(policy, default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task AllowGroups_ValidNames_Applied()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var policy = ParseObject("""{"allow_groups":["sshusers","ops-team"]}""");
        var applied = await enforcer.ApplyAsync(policy, default);

        Assert.Single(applied);
        Assert.Equal("sshd:set:AllowGroups=sshusers,ops-team", applied[0]);
    }

    [Fact]
    public async Task AllowGroups_UnsafeNameFiltered()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        // "bad group!" contains '!' — should be filtered, leaving empty list → no directive
        var policy = ParseObject("""{"allow_groups":["bad group!"]}""");
        var applied = await enforcer.ApplyAsync(policy, default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task MultipleFields_AllPresentInResult()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SshdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var policy = ParseObject("""
            {
              "password_authentication": false,
              "pubkey_authentication": true,
              "permit_root_login": "prohibit-password",
              "allow_groups": ["sshusers"]
            }
            """);
        var applied = await enforcer.ApplyAsync(policy, default);

        Assert.Equal(4, applied.Count);
        Assert.Contains("sshd:set:PasswordAuthentication=False",     applied);
        Assert.Contains("sshd:set:PubkeyAuthentication=True",        applied);
        Assert.Contains("sshd:set:PermitRootLogin=prohibit-password", applied);
        Assert.Contains("sshd:set:AllowGroups=sshusers",             applied);
        Assert.Empty(runner.Invocations);
    }

    // ---- HasValidDirectives ----

    [Theory]
    [InlineData("""{"password_authentication":false}""",                     true)]
    [InlineData("""{"pubkey_authentication":true}""",                        true)]
    [InlineData("""{"permit_root_login":"no"}""",                            true)]
    [InlineData("""{"allow_users":["alice"]}""",                             true)]
    [InlineData("""{"allow_groups":["sshusers"]}""",                         true)]
    [InlineData("""{}""",                                                    false)]
    [InlineData("""{"permit_root_login":"invalid"}""",                       false)]
    [InlineData("""{"allow_users":["bad user"]}""",                          false)]
    [InlineData("""{"allow_users":[]}""",                                    false)]
    [InlineData("""{"permit_root_login":"maybe","allow_users":["bad!"]}""",  false)]
    [InlineData("""{"allow_groups":["bad group!"]}""",                       false)]
    [InlineData("""{"allow_groups":[]}""",                                   false)]
    public void HasValidDirectives_Returns_Expected(string json, bool expected)
        => Assert.Equal(expected,
               SshdEnforcer.HasValidDirectives(
                   JsonDocument.Parse(json).RootElement));
}

// ============================================================
// Reconciliation methods on enforcers
// ============================================================

public sealed class ReconcileUserEnforcerTests
{
    [Fact]
    public async Task ReconcileStaleUsers_DisablesEachUser()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleUsersAsync(["alice", "bob"], default);

        Assert.Equal(2, applied.Count);
        Assert.Contains("user:disable:alice", applied);
        Assert.Contains("user:disable:bob", applied);
        Assert.Contains(runner.Invocations, i => i.FileName == "passwd" && i.Arguments.Contains("alice"));
        Assert.Contains(runner.Invocations, i => i.FileName == "passwd" && i.Arguments.Contains("bob"));
    }

    [Fact]
    public async Task ReconcileStaleUsers_AuditOnly_NoRunnerCall()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleUsersAsync(["alice"], default);

        Assert.Single(applied);
        Assert.Equal("user:disable:alice", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleUsers_UnsafeUsername_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleUsersAsync(["bad name!"], default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleUsers_EmptyList_ReturnsEmpty()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleUsersAsync([], default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }
}

public sealed class ReconcileGroupEnforcerTests
{
    private static JsonElement ParseElement(string json)
        => JsonDocument.Parse(json).RootElement;

    [Theory]
    [InlineData("""{"username":"alice","action":"Create","groups":["sudo","staff"]}""", new[] { "alice:sudo", "alice:staff" })]
    [InlineData("""{"username":"bob","action":"Modify","groups":["docker"]}""",         new[] { "bob:docker" })]
    [InlineData("""{"username":"carol","action":"Create"}""",                           new string[0])]
    [InlineData("""{"username":"dave","action":"Create","groups":[]}""",                new string[0])]
    public void ExtractManagedGroups_ReturnsExpectedKeys(string json, string[] expected)
    {
        var d = ParseElement(json);
        var actual = UserEnforcer.ExtractManagedGroups(d).ToList();
        Assert.Equal(expected.OrderBy(x => x), actual.OrderBy(x => x));
    }

    [Fact]
    public async Task ReconcileStaleGroups_CallsGpasswdForValidKey()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleGroupsAsync(
            new HashSet<string> { "alice:sudo" }, default);

        Assert.Single(applied);
        Assert.Equal("user:leave-group:alice:sudo", applied[0]);
        Assert.Contains(runner.Invocations, i => i.FileName == "gpasswd" && i.Arguments.Contains("alice") && i.Arguments.Contains("sudo"));
    }

    [Fact]
    public async Task ReconcileStaleGroups_AuditOnly_LogsDoesNotRunGpasswd()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleGroupsAsync(
            new HashSet<string> { "alice:sudo" }, default);

        Assert.Single(applied);
        Assert.Equal("user:leave-group:alice:sudo", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleGroups_InvalidUsername_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleGroupsAsync(
            new HashSet<string> { "bad name!:sudo" }, default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleGroups_InvalidGroupName_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleGroupsAsync(
            new HashSet<string> { "alice:-badgroup" }, default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleGroups_UnparseableKey_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleGroupsAsync(
            new HashSet<string> { "nodecollonseparator" }, default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleGroups_GpasswdFailure_NotRecordedAsChange()
    {
        var runner = new NullCommandRunner();
        runner.ExitCodeOverrides["gpasswd"] = 3;
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleGroupsAsync(
            new HashSet<string> { "alice:sudo" }, default);

        // gpasswd returned non-zero (user already not a member) — not counted as a change.
        Assert.Empty(applied);
        Assert.Single(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleGroups_EmptySet_ReturnsEmpty()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new UserEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleGroupsAsync(
            new HashSet<string>(), default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }
}

public sealed class ReconcileFileEnforcerTests
{
    [Fact]
    public void ReconcileStaleFiles_ReturnsDeleteEntries()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = enforcer.ReconcileStaleFiles(["/etc/dds/old.conf"]);

        Assert.Single(applied);
        Assert.Equal("file:delete:/etc/dds/old.conf", applied[0]);
    }

    [Fact]
    public void ReconcileStaleFiles_UnsafePath_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = enforcer.ReconcileStaleFiles(["relative/path"]);

        Assert.Empty(applied);
    }

    [Fact]
    public void ReconcileStaleFiles_EmptyList_ReturnsEmpty()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new FileEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = enforcer.ReconcileStaleFiles([]);

        Assert.Empty(applied);
    }
}

public sealed class ReconcilePackageEnforcerTests
{
    [Fact]
    public async Task ReconcileStalePackages_AuditOnly_NoRunnerCall()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new PackageEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ReconcileStalePackagesAsync(["ntp"], default);

        Assert.Single(applied);
        Assert.Equal("pkg:remove:ntp", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStalePackages_UnsafeName_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new PackageEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ReconcileStalePackagesAsync(["bad pkg"], default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStalePackages_EmptyList_ReturnsEmpty()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new PackageEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ReconcileStalePackagesAsync([], default);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }
}

// ============================================================
// SysctlEnforcer — reconciliation
// ============================================================

public sealed class ReconcileSysctlEnforcerTests
{
    [Fact]
    public async Task ReconcileStaleKeys_NoDropinFile_ReturnsEmpty()
    {
        // If the drop-in file does not exist there is nothing to reconcile.
        var runner   = new NullCommandRunner();
        var enforcer = new SysctlEnforcer(runner, auditOnly: false, NullLogger.Instance);

        // /etc/sysctl.d/60-dds-managed.conf does not exist in CI → returns empty.
        var applied = await enforcer.ReconcileStaleKeysAsync(
            new HashSet<string>(), CancellationToken.None);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleKeys_AuditOnly_NoRunnerCallOnEmptyFile()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SysctlEnforcer(runner, auditOnly: true, NullLogger.Instance);

        // No drop-in file → still returns empty even in audit mode.
        var applied = await enforcer.ReconcileStaleKeysAsync(
            new HashSet<string> { "net.ipv4.ip_forward" }, CancellationToken.None);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }
}

// ============================================================
// SudoersEnforcer — reconciliation
// ============================================================

public sealed class ReconcileSudoersEnforcerTests
{
    [Fact]
    public async Task ReconcileStaleSudoers_ReturnsDeleteDirectivePerFilename()
    {
        // The enforcer returns a delete directive for each stale filename.
        // /etc/sudoers.d/ does not exist in CI so DeleteDropinAsync is a no-op.
        var runner   = new NullCommandRunner();
        var enforcer = new SudoersEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleSudoersAsync(
            new HashSet<string> { "dds-ops", "dds-readonly" }, CancellationToken.None);

        Assert.Equal(2, applied.Count);
        Assert.Contains("sudoers:delete:dds-ops", applied);
        Assert.Contains("sudoers:delete:dds-readonly", applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleSudoers_AuditOnly_ReturnsdirectivesButNoFilesystemWrite()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SudoersEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleSudoersAsync(
            new HashSet<string> { "dds-ops" }, CancellationToken.None);

        Assert.Single(applied);
        Assert.Equal("sudoers:delete:dds-ops", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleSudoers_UnsafeFilename_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SudoersEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleSudoersAsync(
            new HashSet<string> { "bad/name" }, CancellationToken.None);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleSudoers_EmptySet_ReturnsEmpty()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SudoersEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleSudoersAsync(
            new HashSet<string>(), CancellationToken.None);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }
}

// ============================================================
// ReconcileSystemdDropinEnforcerTests
// ============================================================

public sealed class ReconcileSystemdDropinEnforcerTests
{
    [Fact]
    public async Task ReconcileStaleDropins_ReturnsRemoveDirectivePerKey()
    {
        // The enforcer returns a removedropin directive for each stale key.
        // /etc/systemd/system/ does not exist in CI so File.Delete is a no-op.
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleDropinsAsync(
            new HashSet<string> { "sshd.service/hardening", "dds-agent.service/limits" },
            CancellationToken.None);

        Assert.Equal(2, applied.Count);
        Assert.Contains("systemd:removedropin:sshd.service/hardening", applied);
        Assert.Contains("systemd:removedropin:dds-agent.service/limits", applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleDropins_AuditOnly_ReturnDirectivesButNoFilesystemWrite()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: true, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleDropinsAsync(
            new HashSet<string> { "sshd.service/hardening" }, CancellationToken.None);

        Assert.Single(applied);
        Assert.Equal("systemd:removedropin:sshd.service/hardening", applied[0]);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleDropins_UnsafeKey_Skipped()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleDropinsAsync(
            new HashSet<string> { "../../etc/passwd/evil" }, CancellationToken.None);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }

    [Fact]
    public async Task ReconcileStaleDropins_EmptySet_ReturnsEmpty()
    {
        var runner   = new NullCommandRunner();
        var enforcer = new SystemdEnforcer(runner, auditOnly: false, NullLogger.Instance);

        var applied = await enforcer.ReconcileStaleDropinsAsync(
            new HashSet<string>(), CancellationToken.None);

        Assert.Empty(applied);
        Assert.Empty(runner.Invocations);
    }
}
