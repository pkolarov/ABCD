// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DDS.PolicyAgent.MacOS.Config;
using DDS.PolicyAgent.MacOS.Enforcers;
using DDS.PolicyAgent.MacOS.Runtime;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.MacOS.Tests;

public sealed class BackendOperationTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly string? _previousAssumeRoot;

    public BackendOperationTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), $"dds-macos-backend-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tmpDir);
        _previousAssumeRoot = Environment.GetEnvironmentVariable("DDS_POLICYAGENT_ASSUME_ROOT");
        Environment.SetEnvironmentVariable("DDS_POLICYAGENT_ASSUME_ROOT", "1");
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("DDS_POLICYAGENT_ASSUME_ROOT", _previousAssumeRoot);
        try { Directory.Delete(_tmpDir, recursive: true); }
        catch { }
    }

    [Fact]
    public void HostMacPreferenceOperations_round_trips_managed_plist_values()
    {
        var cfg = Options.Create(new AgentConfig
        {
            ManagedPreferencesDir = Path.Combine(_tmpDir, "prefs"),
            UserTemplatePreferencesDir = Path.Combine(_tmpDir, "prefs-user-template"),
        });
        var ops = new HostMacPreferenceOperations(
            new ProcessCommandRunner(NullLogger<ProcessCommandRunner>.Instance),
            cfg);

        ops.SetValueJson("com.dds.test", "IdleTime", PreferenceScope.System, "600");
        var current = ops.GetValueJson("com.dds.test", "IdleTime", PreferenceScope.System);
        ops.DeleteValue("com.dds.test", "IdleTime", PreferenceScope.System);

        Assert.Equal("600", current);
        Assert.Null(ops.GetValueJson("com.dds.test", "IdleTime", PreferenceScope.System));
    }

    [Fact]
    public void HostLaunchdOperations_issues_launchctl_commands_and_persists_binding()
    {
        var launchdDir = Path.Combine(_tmpDir, "LaunchDaemons");
        Directory.CreateDirectory(launchdDir);
        var plistPath = Path.Combine(launchdDir, "com.dds.test.plist");
        File.WriteAllText(plistPath, """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key>
          <string>com.dds.test</string>
          <key>ProgramArguments</key>
          <array>
            <string>/usr/bin/true</string>
          </array>
        </dict>
        </plist>
        """);

        var realRunner = new ProcessCommandRunner(NullLogger<ProcessCommandRunner>.Instance);
        var runner = new RecordingCommandRunner((file, args, stdin) =>
        {
            if (file == "/usr/bin/plutil")
                return realRunner.Run(file, args, stdin);
            if (file == "/bin/launchctl")
                return new CommandResult(0, string.Empty, string.Empty);
            return new CommandResult(1, string.Empty, "unexpected command");
        });

        var ops = new HostLaunchdOperations(
            runner,
            Options.Create(new AgentConfig
            {
                StateDir = _tmpDir,
                LaunchDaemonPlistDir = launchdDir,
                LaunchdStateFile = Path.Combine(_tmpDir, "launchd-state.json"),
            }));

        ops.Configure("com.dds.test", plistPath, enabled: true);
        ops.Load("com.dds.test");
        ops.Kickstart("com.dds.test");
        ops.Unload("com.dds.test");

        Assert.Contains(runner.Invocations, x => x.FileName == "/bin/launchctl" && x.Arguments.SequenceEqual(["enable", "system/com.dds.test"]));
        Assert.Contains(runner.Invocations, x => x.FileName == "/bin/launchctl" && x.Arguments.SequenceEqual(["bootstrap", "system", plistPath]));
        Assert.Contains(runner.Invocations, x => x.FileName == "/bin/launchctl" && x.Arguments.SequenceEqual(["kickstart", "-k", "system/com.dds.test"]));
        Assert.Contains(runner.Invocations, x => x.FileName == "/bin/launchctl" && x.Arguments.SequenceEqual(["bootout", "system/com.dds.test"]));
        Assert.True(File.Exists(Path.Combine(_tmpDir, "launchd-state.json")));
    }

    [Fact]
    public void HostProfileOperations_installs_and_removes_profile_with_stamp_state()
    {
        var installed = new HashSet<string>(StringComparer.Ordinal);
        var realRunner = new ProcessCommandRunner(NullLogger<ProcessCommandRunner>.Instance);
        var runner = new RecordingCommandRunner((file, args, stdin) =>
        {
            if (file == "/usr/bin/profiles")
            {
                if (args.SequenceEqual(["-I", "-F", args[2], "-f"]))
                {
                    installed.Add("com.dds.test");
                    return new CommandResult(0, string.Empty, string.Empty);
                }

                if (args.Count >= 3 && args[0] == "-R" && args[1] == "-p")
                {
                    installed.Remove(args[2]);
                    return new CommandResult(0, string.Empty, string.Empty);
                }

                if (args.Count >= 3 && args[0] == "-C" && args[1] == "-o")
                {
                    var outputPath = args[2];
                    File.WriteAllText(outputPath, installed.Contains("com.dds.test")
                        ? """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                        <plist version="1.0">
                        <dict>
                          <key>_computerLevel</key>
                          <array>
                            <dict>
                              <key>ProfileIdentifier</key>
                              <string>com.dds.test</string>
                            </dict>
                          </array>
                        </dict>
                        </plist>
                        """
                        : """
                        <?xml version="1.0" encoding="UTF-8"?>
                        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                        <plist version="1.0"><dict/></plist>
                        """);
                    return new CommandResult(0, string.Empty, string.Empty);
                }
            }

            if (file == "/usr/bin/plutil")
                return realRunner.Run(file, args, stdin);

            return new CommandResult(1, string.Empty, "unexpected command");
        });

        var ops = new HostProfileOperations(
            runner,
            Options.Create(new AgentConfig
            {
                StateDir = _tmpDir,
                ProfileStateDir = Path.Combine(_tmpDir, "profiles"),
            }));

        ops.Install("com.dds.test", "DDS Test", "sha256:test", Encoding.UTF8.GetBytes("payload"));

        Assert.True(ops.IsInstalled("com.dds.test", "sha256:test"));

        ops.Remove("com.dds.test");
        Assert.False(ops.IsInstalled("com.dds.test", "sha256:test"));
    }

    [Fact]
    public async Task SoftwareInstaller_installs_local_pkg_after_hash_and_signature_checks()
    {
        var pkgPath = Path.Combine(_tmpDir, "editor.pkg");
        await File.WriteAllBytesAsync(pkgPath, Encoding.UTF8.GetBytes("pkg-bytes"));
        var sha = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(pkgPath))).ToLowerInvariant();
        var installed = false;

        var runner = new RecordingCommandRunner((file, args, _) =>
        {
            if (file == "/usr/sbin/pkgutil" &&
                args.SequenceEqual(["--pkg-info", "com.example.editor"]))
            {
                return installed
                    ? new CommandResult(0, "package-id: com.example.editor\nversion: 1.0\n", string.Empty)
                    : new CommandResult(1, string.Empty, "No receipt");
            }

            if (file == "/usr/sbin/pkgutil" && args.SequenceEqual(["--check-signature", pkgPath]))
                return new CommandResult(0, "signed", string.Empty);

            if (file == "/usr/sbin/installer" &&
                args.SequenceEqual(["-pkg", pkgPath, "-target", "/"]))
            {
                installed = true;
                return new CommandResult(0, string.Empty, string.Empty);
            }

            return new CommandResult(1, string.Empty, "unexpected command");
        });

        var installer = new SoftwareInstaller(
            NullLogger<SoftwareInstaller>.Instance,
            runner,
            Options.Create(new AgentConfig
            {
                PackageInstallTarget = "/",
                RequirePackageSignature = true,
            }),
            new StaticHttpClientFactory(new HttpClient()));

        var directive = JsonDocument.Parse($$"""
        {
          "package_id":"com.example.editor",
          "version":"1.0",
          "source":"{{pkgPath}}",
          "sha256":"sha256:{{sha}}",
          "action":"Install"
        }
        """).RootElement;

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
        Assert.Contains(runner.Invocations, x => x.FileName == "/usr/sbin/installer");
    }
}
