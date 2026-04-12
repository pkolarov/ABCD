# macOS Platform Slice

`platform/macos/` now contains a real macOS policy agent, not just a worker shell.

Current backend coverage:

- managed preferences: plist-backed via `plutil`
- local accounts: `dscl`, `pwpolicy`, `dseditgroup`, `sysadminctl`
- launchd: `launchctl` with persisted label-to-plist bindings
- configuration profiles: `profiles` plus local payload-hash stamps
- software install/update: `/usr/sbin/installer` and `pkgutil` with SHA-256 verification

Current limits:

- generic `.pkg` uninstall is still not implemented safely
- profile, account, and package operations are real host mutations and should be tested on a disposable machine
- the agent must run as `root` for account/profile/software/launchd mutation
- inline pre/post package scripts stay disabled by default

## Two-Machine E2E

For an actual DDS mesh validation across two Macs, use the dedicated harness in [platform/macos/e2e/README.md](/Users/peter/ABCD/platform/macos/e2e/README.md).

That path is broader than the single-host smoke flow here. It validates:

- node-to-node libp2p peering
- live publish of a macOS policy plus software assignment into the mesh
- local agent application on both machines
- local summary collection on both machines
- one merged pass/fail comparison step

## Safe First E2E

Start with a staging config that redirects preferences, launchd plist paths, and package cache into `/tmp`, then exercise only:

1. `PreferenceEnforcer`
2. `LaunchdEnforcer`
3. `SoftwareInstaller` with a local throwaway signed test pkg or `RequirePackageSignature=false`

Leave profiles and local accounts for a second pass on a disposable host.

Sample config: [appsettings.e2e.sample.json](/Users/peter/ABCD/platform/macos/appsettings.e2e.sample.json)

You can also override the same values through environment variables:

```bash
export DdsPolicyAgent__DeviceUrn='urn:dds:device:macos-e2e'
export DdsPolicyAgent__NodeBaseUrl='http://127.0.0.1:5551'
export DdsPolicyAgent__StateDir='/tmp/dds-macos-e2e/state'
export DdsPolicyAgent__ManagedPreferencesDir='/tmp/dds-macos-e2e/managed-prefs'
export DdsPolicyAgent__UserTemplatePreferencesDir='/tmp/dds-macos-e2e/user-template-prefs'
export DdsPolicyAgent__LaunchDaemonPlistDir='/tmp/dds-macos-e2e/LaunchDaemons'
export DdsPolicyAgent__LaunchAgentPlistDir='/tmp/dds-macos-e2e/LaunchAgents'
export DdsPolicyAgent__LaunchdStateFile='/tmp/dds-macos-e2e/state/launchd-state.json'
export DdsPolicyAgent__PackageCacheDir='/tmp/dds-macos-e2e/packages'
export DdsPolicyAgent__ProfileStateDir='/tmp/dds-macos-e2e/profiles'
export DdsPolicyAgent__RequirePackageSignature='false'
```

Create those directories before running the agent:

```bash
mkdir -p \
  /tmp/dds-macos-e2e/state \
  /tmp/dds-macos-e2e/managed-prefs \
  /tmp/dds-macos-e2e/user-template-prefs \
  /tmp/dds-macos-e2e/LaunchDaemons \
  /tmp/dds-macos-e2e/LaunchAgents \
  /tmp/dds-macos-e2e/packages \
  /tmp/dds-macos-e2e/profiles
```

## Manual Run

Build the node and agent:

```bash
cargo build -p dds-node
dotnet build platform/macos/DdsPolicyAgent/DdsPolicyAgent.MacOS.csproj -c Debug
```

Run the local node with the macOS HTTP API enabled, seed a test device plus one macOS policy/software assignment, then start the agent as root:

```bash
sudo dotnet run --project platform/macos/DdsPolicyAgent/DdsPolicyAgent.MacOS.csproj
```

What to verify first:

- [appsettings.json](/Users/peter/ABCD/platform/macos/DdsPolicyAgent/appsettings.json) values are being picked up
- [AppliedStateStore](/Users/peter/ABCD/platform/macos/DdsPolicyAgent/State/AppliedStateStore.cs) is recording hashes in the configured `StateDir`
- managed plist files appear under the configured preferences root
- `launchctl bootstrap` / `kickstart` only touch the staged plist paths you assigned
- package hashes are verified before `installer` runs

Recommended validation order:

1. preferences only
2. preferences + launchd
3. software install/update
4. profiles on a disposable host
5. local account lifecycle on a disposable host
