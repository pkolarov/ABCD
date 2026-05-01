# Linux Platform Implementation Plan

`platform/linux/` is the planning home for the Linux platform slice. The goal is
to add a DDS-managed Linux endpoint that can enroll into a DDS domain, receive
signed policy intent from `dds-node`, apply supported local state
deterministically, and report applied state or drift without depending on Active
Directory.

This plan intentionally starts with policy and account management. Login-path
integration through PAM or SSSD is deferred until local policy application,
host safety, and reporting are proven.

## Target Scope

Initial supported distributions:

- Ubuntu 24.04 LTS
- Debian 12
- Fedora 40 or newer

Initial host roles:

- single-user or shared workstation
- server enrolled as a managed DDS device
- greenfield DDS-managed endpoint, not an AD or LDAP domain member

Out of scope for the first implementation:

- replacing Kerberos, LDAP, or SSSD as a domain identity provider
- joining existing AD domains
- managing SELinux policy modules beyond service/package labels needed by DDS
- destructive user-home migration

## Architecture

Use the same high-level shape as the Windows and macOS platform agents:

1. `dds-node` exposes Linux-specific agent endpoints:
   - `GET /v1/linux/policies?device_urn=...`
   - `GET /v1/linux/software?device_urn=...`
   - `POST /v1/linux/applied`
2. A Linux policy agent runs as a systemd service with least-privilege local
   helpers for operations that require root.
3. The agent verifies signed policy envelopes, computes intended state, applies
   idempotent enforcers, records local applied-state hashes, and reports drift.
4. Production deployments use a Unix domain socket for the node API:
   `unix:/var/run/dds/api.sock`, guarded by `SO_PEERCRED` and filesystem
   permissions.

Preferred implementation language for the first agent is C#/.NET, matching the
existing Windows and macOS policy agents. If Linux-specific privilege separation
or packaging makes that awkward, evaluate a Rust agent before implementation
starts and record the decision here.

## Policy Surfaces

Phase 1 policy coverage:

- local users and groups:
  - create, update, disable, and remove DDS-managed local users
  - manage supplementary group membership
  - refuse to manage system users below a configured UID threshold
- sudoers:
  - write DDS-managed files under `/etc/sudoers.d/`
  - validate with `visudo -cf` before activation
- files and directories:
  - ensure ownership, mode, and static content for DDS-owned paths
  - refuse broad recursive mutation by default
- systemd units:
  - install DDS-managed drop-ins under `/etc/systemd/system/*.d/`
  - run `systemctl daemon-reload` only when content changes
  - support enable, disable, start, stop, and restart actions
- packages:
  - install and remove packages through apt, dnf, or rpm backends
  - require repository allowlists and package signature verification

Phase 2 policy coverage:

- PAM configuration templates with validation and rollback
- SSHD configuration fragments with `sshd -t` validation
- firewalld or nftables profile management
- auditd rule management
- compliance collection for policy state, package inventory, and local users

## Safety Model

The Linux agent must be fail-closed for trust and fail-safe for host mutation.

Required safeguards:

- verify every policy envelope before parsing platform directives
- apply only DDS-owned resources unless a directive explicitly names a safe
  takeover path
- persist per-resource content hashes and last applied reasons
- detect local drift before modifying a resource
- support audit-only mode for all enforcers
- dry-run validation for sudoers, systemd, PAM, SSHD, and firewall changes
- use atomic writes followed by rename for managed files
- leave unmanaged host state untouched
- refuse destructive account or package actions unless the resource is marked
  DDS-managed in local state

## Packaging

Initial packaging targets:

- Debian package for Ubuntu and Debian
- RPM package for Fedora-family systems

Installed paths:

- `/usr/local/bin/dds-node` or distribution package path for the node binary
- `/usr/local/lib/dds/DdsPolicyAgent.Linux/` for the agent payload
- `/etc/dds/node.toml` for node configuration
- `/etc/dds/policy-agent.json` for agent configuration
- `/var/lib/dds/` for node and agent state
- `/var/log/dds/` for file logs when journald forwarding is not enough
- `/run/dds/api.sock` or `/var/run/dds/api.sock` for the node API socket

systemd units:

- `dds-node.service`
- `dds-policy-agent.service`

## Testing Plan

Unit tests:

- envelope verification and malformed payload rejection
- applied-state migration and hash matching
- each enforcer in audit and enforce mode
- package backend command planning
- UID/GID guardrails and DDS-managed ownership checks

Integration tests:

- containerized Ubuntu, Debian, and Fedora smoke tests
- sudoers validation failure leaves previous state intact
- systemd drop-in change triggers daemon reload once
- package allowlist blocks unexpected package names and repositories
- local drift is reported before correction

E2E tests:

- one Linux node enrolls as a DDS device
- policy agent fetches Linux policy over a Unix socket
- local user, sudoers, file, systemd, and package directives apply
- agent posts applied-state reports
- repeated runs are idempotent

## Implementation Phases

### L-0: Design Freeze

- Define `LinuxPolicyDocument` and report schemas.
- Decide whether the Linux agent stays C#/.NET or moves to Rust.
- Define supported distributions and package manager abstraction boundaries.
- Add `/v1/linux/*` HTTP and CLI query stubs.

Exit gate: schema examples, endpoint contract, and implementation-language ADR
are reviewed.

### L-1: Agent Skeleton

- Create the first Linux policy agent project:
  - `platform/linux/DdsPolicyAgent/DdsPolicyAgent.Linux.csproj`
  - `platform/linux/DdsPolicyAgent/Program.cs`
  - `platform/linux/DdsPolicyAgent/Worker.cs`
  - `platform/linux/DdsPolicyAgent/appsettings.json`
  - `platform/linux/DdsPolicyAgent.Tests/DdsPolicyAgent.Linux.Tests.csproj`
- Keep the project shape close to the macOS policy agent:
  - .NET worker service targeting `net9.0`
  - nullable reference types and implicit usings enabled
  - `Microsoft.Extensions.Hosting` and `Microsoft.Extensions.Http`
  - `BouncyCastle.Cryptography` for Ed25519 envelope verification
  - `InternalsVisibleTo` for the Linux test project
- Add the initial source layout:

```text
platform/linux/
  DdsPolicyAgent/
    Client/
      DdsNodeClient.cs
      DdsNodeHttpFactory.cs
      SignedPolicyEnvelope.cs
    Config/
      AgentConfig.cs
    State/
      AppliedStateStore.cs
    Runtime/
      CommandRunner.cs
      PrivilegeGuard.cs
    Program.cs
    Worker.cs
    appsettings.json
  DdsPolicyAgent.Tests/
    DdsNodeHttpFactoryTests.cs
    EnvelopeVerifierTests.cs
    AppliedStateStoreTests.cs
    WorkerTests.cs
```

L-1 should create only no-op enforcer boundaries. Do not implement users,
sudoers, systemd, packages, PAM, SSHD, firewall, or file mutation yet. The goal
is to prove the agent lifecycle and trust path before host mutation exists.

The skeleton worker behavior:

1. Load `DdsPolicyAgent` configuration.
2. Fail closed when `DeviceUrn` or `PinnedNodePubkeyB64` is missing.
3. Build an HTTP client for either loopback TCP or `unix:/...` node transport.
4. Fetch `GET /v1/linux/policies?device_urn=...`.
5. Verify and unwrap the signed Linux policy envelope.
6. Parse the response into an `ApplicableLinuxPolicy` list.
7. Record content hashes in local applied state.
8. Report `POST /v1/linux/applied` with:
   - `kind = "policy"`
   - `status = "ok"` for valid empty Linux policy bundles
   - `status = "skipped"` for policy bundles without a `linux` object
   - `directives = []`
9. Repeat at `PollIntervalSeconds`.

Initial `AgentConfig` fields:

- `DeviceUrn`
- `NodeBaseUrl`, defaulting to `unix:/run/dds/api.sock`
- `PollIntervalSeconds`, defaulting to `60`
- `StateDir`, defaulting to `/var/lib/dds/policy-agent`
- `PinnedNodePubkeyB64`
- `EnvelopeMaxClockSkewSeconds`, defaulting to `300`
- `AuditOnly`, defaulting to `true`

The initial applied-state file lives at:

```text
/var/lib/dds/policy-agent/applied-state.json
```

For local development, `appsettings.json` should keep mutations contained under
`./dds-linux-agent-state` and allow `http://127.0.0.1:5551` as the node URL.
Production packaging can switch the default back to the Unix socket.

Add development systemd units under `platform/linux/packaging/systemd/`:

- `dds-node.service`
- `dds-policy-agent.service`

The policy-agent unit should run as root for L-1 only because later enforcers
will need privileged host operations. Add a note in the unit comments that L-1
does not mutate host state, and that L-2 must revisit privilege separation
before real enforcers land.

Add node and CLI stubs needed by the skeleton:

- `GET /v1/linux/policies`
- `GET /v1/linux/software`
- `POST /v1/linux/applied`
- `dds platform linux policies --device-urn ...`
- `dds platform linux software --device-urn ...`
- `dds platform linux applied --from-file report.json`

For L-1, Linux software can return an empty signed response and the agent does
not need to poll it yet. Add the endpoint now so L-3 can extend behavior without
changing the public API shape.

Tests for L-1:

- `DdsNodeHttpFactoryTests`:
  - resolves `unix:/run/dds/api.sock` to a placeholder HTTP base address
  - extracts socket paths correctly
  - rejects empty `unix:` URLs
  - preserves loopback HTTP URLs
- `EnvelopeVerifierTests`:
  - accepts a valid Linux policy envelope
  - rejects malformed base64 signatures
  - rejects wrong envelope kind
  - rejects wrong audience or device URN
- `AppliedStateStoreTests`:
  - creates the state directory
  - writes `applied-state.json` atomically
  - treats `ok` and `skipped` as terminal unchanged states
  - retries failed statuses on the next poll
- `WorkerTests`:
  - fails closed without `DeviceUrn`
  - fails closed without pinned node key
  - reports `skipped` for non-Linux policy bundles
  - reports `ok` for an empty Linux policy bundle
  - does not call any host mutation API

L-1 implementation order:

1. Add Linux schemas and `/v1/linux/*` routes in `dds-node`.
2. Add `dds platform linux ...` CLI commands.
3. Copy the proven client, envelope, UDS transport, config, and state-store
   patterns into the Linux agent namespace.
4. Implement the no-op worker and empty Linux policy dispatch.
5. Add the systemd unit drafts and development config.
6. Add the L-1 tests.
7. Run `dotnet test` for the Linux agent tests and targeted Rust tests for the
   new node/CLI route plumbing.

Exit gate: on a clean Linux VM or container with systemd, the agent starts,
fetches a signed Linux policy envelope through the configured node transport,
verifies it, writes applied state, posts an empty applied report, and repeats
idempotently without mutating host state.

### L-2: Core Enforcers

- Implement users/groups, sudoers, managed files, and systemd enforcers.
- Add dry-run validation and rollback behavior.
- Add unit and container integration tests.

Exit gate: all Phase 1 non-package policy surfaces apply idempotently on Ubuntu,
Debian, and Fedora test hosts.

### L-3: Package Management

- Implement apt and dnf/rpm backends.
- Enforce repository and package allowlists.
- Capture package inventory and install/remove outcomes in applied reports.

Exit gate: package directives apply in disposable containers or VMs with
signature verification enabled.

### L-4: Installer and E2E

- Build `.deb` and `.rpm` packages.
- Install node and agent systemd units.
- Add a Linux E2E runbook and smoke script under `platform/linux/e2e/`.
- Validate Unix socket transport, enrollment, policy application, drift report,
  and idempotent re-run.

Exit gate: fresh Linux VM can install DDS, enroll, apply policy, report state,
and uninstall without leaving DDS-managed state behind.

### L-5: Login-Adjacent Spike

- Evaluate PAM-only, SSSD-adjacent, and DDS-native login helper options.
- Document offline authentication, recovery, and lockout semantics.
- Prototype only after policy-agent safety and reporting are complete.

Exit gate: ADR chooses the Linux login integration direction or explicitly
defers it.

## Open Questions

- Should Linux policy documents share most of the macOS account/software schema,
  or should Linux get a separate schema from the start?
- Should the Linux agent be privileged as a single root service, or split into an
  unprivileged reconciler plus root helper?
- Which package signing trust model is acceptable for local repositories and
  offline installs?
- How should DDS behave on hosts already joined to AD, LDAP, FreeIPA, or
  enterprise SSSD realms?
- Should first release support SELinux-enforcing Fedora hosts, or start with
  explicit SELinux limitations?
