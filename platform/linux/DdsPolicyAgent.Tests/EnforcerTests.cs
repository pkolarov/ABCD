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

        Assert.True(runner.Invocations.Any(i => i.FileName == "useradd"),
            "Expected useradd to be invoked");
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
    [InlineData("/etc/dds/motd", true)]
    [InlineData("relative/path", false)]
    [InlineData("/etc/../etc/passwd", false)]
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
}
