# Two-Machine macOS E2E Runbook

This is the operator guide for running the DDS macOS end-to-end test on two real Macs.

The test proves this full path:

1. two `dds-node` instances join the same DDS domain over libp2p
2. each Mac enrolls its local managed device into its local node
3. one temporary publisher injects a macOS policy document and a software assignment into the live mesh
4. both macOS policy agents poll, evaluate, and apply the same intended state
5. both Macs collect machine-readable evidence
6. one comparison step checks whether both machines converged on the same result

The default fixture validates these macOS behaviors:

- managed preference write
- `launchd` configure, load, and kickstart
- package install and version reporting using a throwaway marker package

The default fixture does not exercise local-account mutation or configuration-profile installation. Those paths are more invasive and belong in a disposable-host follow-up run.

## What Success Looks Like

The run is considered successful when all of the following are true:

- both nodes report at least one connected peer
- both machines report `all_passed: true` in their local summary
- both machines applied the same DDS policy version
- both machines applied the same software package version
- both machines observed the same managed preference value
- the comparison command exits with code `0`

The final output artifact is:

- `/tmp/dds-macos-e2e/comparison.json`

## Test Layout

Use these names consistently through the run:

- machine A: `mac-a`
- machine B: `mac-b`

Shared staging root on each machine:

- `/tmp/dds-macos-e2e`

Important local artifacts created during the run:

- `peer-id.txt`
- `bootstrap-peer.txt`
- `domain/domain.toml`
- `domain/admission-<machine>.cbor`
- `dds.toml`
- `packages/com.dds.e2e.marker.pkg`
- `manifest.json`
- `summary-<machine>.json`
- `comparison.json`

## Prerequisites

Before starting, make sure all of these are true on both Macs:

- this repository is checked out at the same commit
- Rust toolchain is installed
- .NET SDK is installed
- the operator has `sudo`
- the two Macs can reach each other on the chosen libp2p port
- `ssh` and `scp` between the two Macs work, or you have another reliable file-copy method

Build the required binaries on both Macs from the repo root:

```bash
cargo build -p dds-node --bin dds-node --bin dds-macos-e2e
dotnet build platform/macos/DdsPolicyAgent/DdsPolicyAgent.MacOS.csproj -c Debug
```

If either build fails, stop here. Do not attempt the e2e run with mixed or partial binaries.

## Files And Scripts Used By This Run

Scripts under `platform/macos/e2e/`:

- `init-machine.sh`
- `write-node-config.sh`
- `build-marker-package.sh`
- `enroll-device.sh`
- `start-node.sh`
- `start-agent.sh`
- `publish-fixture.sh`
- `collect-summary.sh`
- `compare-summaries.sh`
- `cleanup-machine.sh`

Rust helper binary:

- `target/debug/dds-macos-e2e`

## Step 1: Initialize Machine A

Run on machine A:

```bash
platform/macos/e2e/init-machine.sh \
  --machine-id mac-a \
  --advertise-ip 192.168.1.10 \
  --listen-port 4001
```

Check these files exist on machine A:

```bash
ls -l /tmp/dds-macos-e2e/peer-id.txt
ls -l /tmp/dds-macos-e2e/bootstrap-peer.txt
ls -l /tmp/dds-macos-e2e/LaunchDaemons/com.dds.e2e.marker.plist
cat /tmp/dds-macos-e2e/bootstrap-peer.txt
```

Record the printed bootstrap multiaddr. You will need it later.

## Step 2: Initialize Machine B

Run on machine B:

```bash
platform/macos/e2e/init-machine.sh \
  --machine-id mac-b \
  --advertise-ip 192.168.1.11 \
  --listen-port 4001
```

Check these files exist on machine B:

```bash
ls -l /tmp/dds-macos-e2e/peer-id.txt
ls -l /tmp/dds-macos-e2e/bootstrap-peer.txt
ls -l /tmp/dds-macos-e2e/LaunchDaemons/com.dds.e2e.marker.plist
cat /tmp/dds-macos-e2e/bootstrap-peer.txt
```

## Step 3: Create The DDS Domain On Machine A

Run on machine A:

```bash
target/debug/dds-node init-domain \
  --name macos-e2e.local \
  --dir /tmp/dds-macos-e2e/domain
```

Confirm the domain artifacts exist:

```bash
ls -l /tmp/dds-macos-e2e/domain/domain.toml
ls -l /tmp/dds-macos-e2e/domain/domain_key.bin
```

## Step 4: Admit Both Node Identities

First admit machine A from machine A:

```bash
target/debug/dds-node admit \
  --domain-key /tmp/dds-macos-e2e/domain/domain_key.bin \
  --domain /tmp/dds-macos-e2e/domain/domain.toml \
  --peer-id "$(cat /tmp/dds-macos-e2e/peer-id.txt)" \
  --out /tmp/dds-macos-e2e/domain/admission-mac-a.cbor
```

Then copy machine B's `peer-id.txt` to machine A or read it over `ssh`, and admit machine B:

```bash
target/debug/dds-node admit \
  --domain-key /tmp/dds-macos-e2e/domain/domain_key.bin \
  --domain /tmp/dds-macos-e2e/domain/domain.toml \
  --peer-id "$(ssh mac-b 'cat /tmp/dds-macos-e2e/peer-id.txt')" \
  --out /tmp/dds-macos-e2e/domain/admission-mac-b.cbor
```

At this point machine A should have:

- `/tmp/dds-macos-e2e/domain/domain.toml`
- `/tmp/dds-macos-e2e/domain/domain_key.bin`
- `/tmp/dds-macos-e2e/domain/admission-mac-a.cbor`
- `/tmp/dds-macos-e2e/domain/admission-mac-b.cbor`

## Step 5: Copy Domain Files To Machine B

From machine A, copy the domain file and machine B's admission file:

```bash
scp /tmp/dds-macos-e2e/domain/domain.toml \
    mac-b:/tmp/dds-macos-e2e/domain.toml

scp /tmp/dds-macos-e2e/domain/admission-mac-b.cbor \
    mac-b:/tmp/dds-macos-e2e/admission-mac-b.cbor
```

Machine A can continue using:

- `/tmp/dds-macos-e2e/domain/domain.toml`
- `/tmp/dds-macos-e2e/domain/admission-mac-a.cbor`

Machine B will use:

- `/tmp/dds-macos-e2e/domain.toml`
- `/tmp/dds-macos-e2e/admission-mac-b.cbor`

## Step 6: Write Node Config On Machine A

Run on machine A:

```bash
platform/macos/e2e/write-node-config.sh \
  --domain-file /tmp/dds-macos-e2e/domain/domain.toml \
  --admission-file /tmp/dds-macos-e2e/domain/admission-mac-a.cbor \
  --listen-port 4001 \
  --api-port 5551 \
  --bootstrap-peer "$(ssh mac-b 'cat /tmp/dds-macos-e2e/bootstrap-peer.txt')"
```

Confirm the node config was written:

```bash
ls -l /tmp/dds-macos-e2e/dds.toml
```

## Step 7: Write Node Config On Machine B

Run on machine B:

```bash
platform/macos/e2e/write-node-config.sh \
  --domain-file /tmp/dds-macos-e2e/domain.toml \
  --admission-file /tmp/dds-macos-e2e/admission-mac-b.cbor \
  --listen-port 4001 \
  --api-port 5551 \
  --bootstrap-peer "$(ssh mac-a 'cat /tmp/dds-macos-e2e/bootstrap-peer.txt')"
```

Confirm the node config was written:

```bash
ls -l /tmp/dds-macos-e2e/dds.toml
```

Using both bootstrap directions is not strictly required, but it simplifies diagnosis if peer discovery is unstable.

## Step 8: Build The Marker Package Once

Run only on machine A:

```bash
platform/macos/e2e/build-marker-package.sh --version 2026.04.12.1
```

Confirm the package artifacts exist:

```bash
ls -l /tmp/dds-macos-e2e/packages/com.dds.e2e.marker.pkg
cat /tmp/dds-macos-e2e/packages/com.dds.e2e.marker.version
cat /tmp/dds-macos-e2e/packages/com.dds.e2e.marker.sha256
```

Important: use the exact same package file on both machines. Do not rebuild it independently on machine B.

## Step 9: Copy The Package To Machine B

From machine A:

```bash
scp /tmp/dds-macos-e2e/packages/com.dds.e2e.marker.pkg \
    mac-b:/tmp/dds-macos-e2e/packages/com.dds.e2e.marker.pkg

scp /tmp/dds-macos-e2e/packages/com.dds.e2e.marker.version \
    mac-b:/tmp/dds-macos-e2e/packages/com.dds.e2e.marker.version

scp /tmp/dds-macos-e2e/packages/com.dds.e2e.marker.sha256 \
    mac-b:/tmp/dds-macos-e2e/packages/com.dds.e2e.marker.sha256
```

On machine B, verify the files arrived:

```bash
ls -l /tmp/dds-macos-e2e/packages/com.dds.e2e.marker.pkg
cat /tmp/dds-macos-e2e/packages/com.dds.e2e.marker.version
cat /tmp/dds-macos-e2e/packages/com.dds.e2e.marker.sha256
```

## Step 10: Start Both DDS Nodes

Run on machine A:

```bash
platform/macos/e2e/start-node.sh
```

Run on machine B:

```bash
platform/macos/e2e/start-node.sh
```

Each script should wait for the local HTTP API and then return. If it exits early, inspect the node log under `/tmp/dds-macos-e2e/`.

## Step 11: Enroll Machine A And Start Its Agent

Run on machine A:

```bash
platform/macos/e2e/enroll-device.sh \
  --machine-id mac-a \
  --node-url http://127.0.0.1:5551
```

Confirm the enrollment outputs:

```bash
ls -l /tmp/dds-macos-e2e/device-urn.txt
ls -l /tmp/dds-macos-e2e/enroll-device.json
ls -l /tmp/dds-macos-e2e/agent.env
cat /tmp/dds-macos-e2e/device-urn.txt
```

Then start the macOS agent on machine A:

```bash
platform/macos/e2e/start-agent.sh
```

## Step 12: Enroll Machine B And Start Its Agent

Run on machine B:

```bash
platform/macos/e2e/enroll-device.sh \
  --machine-id mac-b \
  --node-url http://127.0.0.1:5551
```

Confirm the enrollment outputs:

```bash
ls -l /tmp/dds-macos-e2e/device-urn.txt
ls -l /tmp/dds-macos-e2e/enroll-device.json
ls -l /tmp/dds-macos-e2e/agent.env
cat /tmp/dds-macos-e2e/device-urn.txt
```

Then start the macOS agent on machine B:

```bash
platform/macos/e2e/start-agent.sh
```

## Step 13: Publish The DDS Fixture

Run only on machine A:

```bash
platform/macos/e2e/publish-fixture.sh \
  --domain-key /tmp/dds-macos-e2e/domain/domain_key.bin \
  --domain-file /tmp/dds-macos-e2e/domain/domain.toml \
  --bootstrap-peer "$(cat /tmp/dds-macos-e2e/bootstrap-peer.txt)"
```

This writes:

- `/tmp/dds-macos-e2e/manifest.json`

Confirm it exists:

```bash
ls -l /tmp/dds-macos-e2e/manifest.json
cat /tmp/dds-macos-e2e/manifest.json
```

## Step 14: Wait For Agent Polling

Wait for at least one or two policy polling intervals after publishing. If you changed the agent polling interval in config, wait long enough for both machines to fetch and apply.

If you want to inspect intermediate state before collecting summaries, look at:

- `/tmp/dds-macos-e2e/applied-state.json`
- `/tmp/dds-macos-e2e/launchd-state.json`

## Step 15: Collect Machine A Summary

Run on machine A:

```bash
platform/macos/e2e/collect-summary.sh --node-url http://127.0.0.1:5551
```

Expected artifact:

- `/tmp/dds-macos-e2e/summary-mac-a.json`

Inspect it:

```bash
cat /tmp/dds-macos-e2e/summary-mac-a.json
```

## Step 16: Collect Machine B Summary

Run on machine B:

```bash
platform/macos/e2e/collect-summary.sh --node-url http://127.0.0.1:5551
```

Expected artifact:

- `/tmp/dds-macos-e2e/summary-mac-b.json`

Inspect it:

```bash
cat /tmp/dds-macos-e2e/summary-mac-b.json
```

## Step 17: Copy Machine B Summary Back To Machine A

From machine B or machine A:

```bash
scp /tmp/dds-macos-e2e/summary-mac-b.json \
    mac-a:/tmp/dds-macos-e2e/summary-mac-b.json
```

Verify on machine A:

```bash
ls -l /tmp/dds-macos-e2e/summary-mac-a.json
ls -l /tmp/dds-macos-e2e/summary-mac-b.json
```

## Step 18: Compare Both Summaries

Run on machine A:

```bash
platform/macos/e2e/compare-summaries.sh \
  --summary-a /tmp/dds-macos-e2e/summary-mac-a.json \
  --summary-b /tmp/dds-macos-e2e/summary-mac-b.json \
  --out /tmp/dds-macos-e2e/comparison.json
```

Inspect the result:

```bash
cat /tmp/dds-macos-e2e/comparison.json
echo $?
```

Interpretation:

- exit code `0`: the two-machine e2e passed
- exit code nonzero: one or more convergence or evidence checks failed

## Step 19: Cleanup

Run on both machines:

```bash
platform/macos/e2e/cleanup-machine.sh
```

This attempts to:

- stop the background node and agent processes
- boot out the test `launchd` job
- forget the marker package receipt
- remove the `/tmp/dds-macos-e2e` run root

## Fast Failure Checks

If the run does not converge, check these in order:

- both nodes started and respond on `http://127.0.0.1:5551/v1/status`
- each machine has the correct `dds.toml`
- each machine was admitted into the same DDS domain
- machine A published the fixture after both agents were started
- both machines have the same `.pkg` file and SHA-256 sidecar
- the comparison used the latest `summary-mac-a.json` and `summary-mac-b.json`

Useful commands:

```bash
curl -s http://127.0.0.1:5551/v1/status | jq
cat /tmp/dds-macos-e2e/applied-state.json
cat /tmp/dds-macos-e2e/launchd-state.json
pkgutil --pkg-info com.dds.e2e.marker
plutil -p /tmp/dds-macos-e2e/preferences/com.dds.e2e.plist
```

## Safety Notes

- run this only on machines where a temporary test package and temporary `launchd` job are acceptable
- do not expand this default harness to local-account or profile mutation on a daily-use Mac without a disposable test plan
- do not reuse old `/tmp/dds-macos-e2e` artifacts across runs; clean up before re-running if there is any doubt
