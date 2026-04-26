# DDS AD Drop-in Replacement Gap Map and Roadmap

**Status:** Draft planning document  
**Date:** 2026-04-25  
**Audience:** maintainers, platform engineers, security reviewers, product owners  

---

## 1. Purpose

This document maps the work required before DDS can credibly claim to be a
drop-in replacement for Microsoft Active Directory Domain Services (AD DS).

DDS already targets many AD-like jobs: identity, groups, policy, revocation,
offline authorization, endpoint policy agents, and Windows/macOS integration.
That is not the same as being a drop-in replacement. A drop-in claim means that
existing Windows clients, legacy LDAP/Kerberos applications, administrative
workflows, migration paths, and security expectations can move with minimal
changes.

The roadmap is intentionally stricter than the current DDS marketing language.
It protects the project from overclaiming while preserving the core DDS
differentiator: local, cryptographically verifiable operation during network
partition.

---

## 2. Definition of "Drop-in Replacement"

DDS should not use one unqualified "AD replacement" claim. Use the ladder below.

| Claim Level | Claim | Meaning | DDS Status |
|---|---|---|---|
| L0 | Decentralized directory layer | DDS provides signed identities, groups, policy, local sessions, and P2P sync for DDS-aware clients. | Current direction |
| L1 | AD coexistence layer | DDS can safely run on AD/hybrid Windows machines without taking ownership of AD accounts, GPO, or Entra sign-in. | v1 spec exists |
| L2 | AD-adjacent migration platform | DDS can import/sync AD objects and provide LDAP-compatible read/bind for selected legacy apps. | Not built |
| L3 | DDS-managed endpoint replacement | DDS can manage greenfield Windows/macOS/Linux endpoints without AD, using DDS-native agents and login flows. | Partial |
| L4 | AD DS protocol-compatible replacement | Existing Windows domain join/logon, Kerberos, LDAP, DNS SRV discovery, GPO processing, and common admin flows work without AD DS. | Not built |
| L5 | Enterprise AD replacement | L4 plus migration tooling, trusts/coexistence, admin delegation, backup/restore, monitoring, security evidence, and scale validation. | Not built |

**Recommendation:** do not claim "drop-in replacement" until L4 is validated on
a published interoperability matrix. For now, the honest claim is closer to L0
plus an L1 coexistence track.

---

## 3. Current DDS Baseline

Current strengths from the repo:

| Area | Current DDS Capability |
|---|---|
| Identity model | Vouchsafe IDs derived from public keys; signed attestations and vouches |
| Auth | FIDO2/WebAuthn enrollment and assertion-backed session issuance |
| Directory state | Signed tokens, trust graph, CRDT-style convergence, redb/memory storage |
| Network | libp2p transport, gossipsub, Kademlia, mDNS, delta sync |
| Crypto | Ed25519 and hybrid Ed25519 + ML-DSA-65 signatures |
| Endpoint agents | Windows Policy Agent, Windows Credential Provider/Auth Bridge, macOS Policy Agent |
| AD coexistence | Locked v1 spec: AD/hybrid hosts run audit-only policy and only allow prior-enrolled vault-backed AD sign-in |
| FFI | C ABI plus language bindings |
| Testing | Rust, .NET, C++, Python, Windows host, MSI, and E2E coverage tracked in `STATUS.md` |

Current blockers to treat as roadmap input, not footnotes:

| Blocker | Why it matters for replacement claims |
|---|---|
| Open security findings A-2, A-3, A-4 | Local Windows transport/config and secret handling must be hardened before enterprise endpoint trust |
| Open security findings B-1, B-2, B-3 | Sync validation, purpose grants, and policy application correctness affect trust graph integrity |
| Open findings B-4, B-5, B-6 | Deterministic policy versions, challenge cleanup, and software staging affect operational reliability |
| Deferred M-13 | FIDO Metadata Service / attestation trust is required for high-assurance authenticator policy |
| Deferred M-15 | Node-bound FIDO2 hmac-secret design affects credential portability and stolen-bundle risk |
| Deferred M-18 | Windows service account split affects least privilege and host-hardening posture |
| No AD protocol surface | DDS has no LDAP server, Kerberos KDC, Netlogon, SAMR/LSA, DRSR, SYSVOL, or domain join implementation |
| No migration path | No AD import/sync, GPO conversion, SID/SIDHistory handling, or password migration strategy |

---

## 4. Detailed Gap Map

### 4.1 Security and Trust Foundation

| Requirement for Drop-in Claim | Current DDS State | Gap | Priority | Acceptance Criteria |
|---|---|---|---|---|
| No known High findings in trust graph, sync, auth, endpoint enforcement | 2026-04-25 review lists new High findings B-1, B-2, B-3; STATUS also tracks A-2 | Trust graph and endpoint state can be corrupted or skipped in edge cases | P0 | Independent review shows zero open Critical/High; regression tests cover each attack path |
| Durable store cannot persist rejected trust graph data | B-1 says sync stores before graph acceptance | Persistence can differ from in-memory validation after restart | P0 | Graph acceptance is the first durable gate; store insert is put-if-absent or exact-byte idempotent |
| Purpose grants only valid while target attestation is active | B-2 says purpose checks can rely on revoked/expired attestations | Delegation can survive invalid target state | P0 | Shared structural validator across token create, validate, ingest; purpose lookup requires active target |
| Policy/software failures retry instead of being marked applied | B-3 says failed enforcement can be skipped forever | Endpoint drift can become invisible | P0 | Applied state records success only for success; failure status participates in change detection |
| Deterministic policy/software version selection | B-4 open | Multiple active versions can race or flap | P0 | Serve side returns one active version per logical ID or rejects ambiguous state |
| Local admin endpoint transport is mandatory-hardened | UDS/named-pipe paths exist; A-2 says Windows bridge config still wires TCP | Secure path may be unreachable in normal Windows config | P0 | MSI and registry config default to named pipe; loopback admin trust disabled in production profile |
| Response MAC cannot fail open in production | A-3 open | Bridge can accept unsigned local responses when no secret configured | P0 | Production profile fails closed without HMAC secret; tests cover missing/invalid MAC |
| Windows secret/log handling is clean | A-4 open | Logs expose derived key material prefix and password length; ProgramData DACL incomplete | P0 | No key/password-derived material in logs; directory/file DACL is explicit and verified |
| Authenticator trust policy | A-1 mostly landed; M-13 deferred | No chain validation against FIDO MDS trust anchors | P1 | MDS-based allow/deny policy with offline cache, tests, and admin docs |
| Node and domain key rotation | Threat model calls out no node key rotation | Compromise response is re-provisioning-heavy | P1 | `rotate-identity` flow; admission renewal; audit trail; rollback plan |
| Admission certificate revocation | Threat model lists no admission cert revocation | Compromised node remains admitted until broad rotation | P1 | Domain-signed admission revocation list gossiped and enforced before traffic ingest |
| External audit and fuzzing | Current review is source-validated but internal/local | AD replacement claim needs stronger evidence | P1 | Third-party review, libFuzzer/AFL for token/CBOR/LDAP parsers, Windows IPC fuzz tests |

### 4.2 Directory Object Model

| Requirement for Drop-in Claim | Current DDS State | Gap | Priority | Acceptance Criteria |
|---|---|---|---|---|
| Stable user object model | `UserAuthAttestation` is minimal | Missing UPN, sAMAccountName-like aliases, mail, manager, account flags, expiry, lockout, mutable attributes | P1 | Versioned `UserDocument` with immutable ID, aliases, lifecycle state, and attribute map |
| Stable computer object model | Device enrollment exists | Missing AD-like computer account lifecycle, machine secret, OS attributes, trust state, delegation metadata | P1 | `ComputerDocument` covers join, disable, rotate secret, retire, owner OU, attributes |
| First-class groups | Vouch/revoke supports membership | Missing group object metadata, scope, type, nesting, owners, distribution vs security semantics | P1 | `GroupDocument` plus nested membership evaluator and cycle/size limits |
| Organizational units | Not built; design docs discuss proposal | No canonical hierarchy, inheritance, delegation, or move semantics | P1 | `OrgUnitDocument`, move/tombstone semantics, policy inheritance evaluator |
| Extensible schema | Domain documents are typed | No LDAP/AD schema facade, object classes, attribute syntax, constraints | P2 | `SchemaDocument` and compatibility mappings for common AD/LDAP attributes |
| ACL/delegated administration | Purpose vouches exist | No AD-like object ACL model or administrative delegation UI/API | P2 | Object-level permissions for create/update/delete/member changes; explainable authorization trace |
| Delete/rename/tombstone behavior | Revoke/burn exist | No object tombstones, rename history, conflict rules for mutable directory objects | P2 | Tombstone model with retention, restore, and conflict tests |
| SID/RID/objectGUID equivalents | Vouchsafe URNs are primary | Windows compatibility needs SIDs/RIDs/GUIDs and stable binary IDs | P2 | Deterministic or allocated SID/RID strategy with collision protection and migration mapping |
| Attribute indexes/search | Local stores hold tokens | LDAP compatibility needs indexed search over attributes and group expansion | P2 | Query engine with bounded latency and index rebuild/verification |

### 4.3 LDAP / LDAPS Compatibility

| Requirement for Drop-in Claim | Current DDS State | Gap | Priority | Acceptance Criteria |
|---|---|---|---|---|
| LDAP read/search facade | Not built | Legacy apps cannot query DDS as LDAP | P2 | `dds-ldap-proxy` supports bind, search, compare, base/one/subtree, common filters |
| LDAPS and StartTLS | Not built | LDAP credentials and data need standard transport security | P2 | TLS config, cert rotation, client validation, StartTLS and ldaps:// test matrix |
| Simple bind and service accounts | FIDO2 sessions exist | Legacy apps often bind with service account/password | P2 | Service account credentials with rotation, lockout, audit, and scoped LDAP read rights |
| SASL/GSSAPI | Not built | Kerberos-backed LDAP clients need GSSAPI bind | P3 | GSSAPI bind works against DDS KDC tickets |
| Common LDAP controls | Not built | Apps expect paged results, server-side sort, VLV sometimes, DirSync for sync tools | P2/P3 | Paged results and sort first; explicit compatibility list for unsupported controls |
| Modify/add/delete operations | Not built | Admin tools and sync tools need writes | P3 | Controlled write path maps LDAP ops to signed DDS documents with authorization and audit |
| AD schema compatibility subset | Not built | Apps expect `user`, `group`, `computer`, `organizationalUnit`, `memberOf`, etc. | P2 | Published schema subset with integration tests against common LDAP clients |
| Operational attributes | Not built | Apps expect objectGUID, objectSid, whenChanged, memberOf, userAccountControl-like fields | P2 | Computed attributes stable and indexed |

### 4.4 Kerberos, Password, and SSO Semantics

| Requirement for Drop-in Claim | Current DDS State | Gap | Priority | Acceptance Criteria |
|---|---|---|---|---|
| Kerberos KDC | DDS sessions are signed tokens; not Kerberos | Windows and many apps need AS/TGS flows and service tickets | P3 | KDC issues TGT/TGS for DDS principals; MIT/Windows clients can authenticate to test services |
| SPN model | Proposed only | Service identity and ticket target semantics missing | P3 | `ServicePrincipalDocument` with uniqueness, ownership, key version, delegation rules |
| Password/key material model | FIDO2 and local vault; no central passwords by design | Kerberos and LDAP bind require password-derived keys or alternate provisioning | P3 | Explicit strategy: password-based, passwordless Kerberos bridge, or recredentialing workflow |
| Account lockout/password policy | Windows password enforcer exists for local policy | No domain-wide lockout, expiry, history, fine-grained policy for DDS principals | P3 | Domain password/credential policy documents, online/offline conflict rules, audit |
| PAC/group claims | Not built | Windows authorization commonly relies on PAC with SIDs/groups | P3 | Ticket authorization data contains stable user/group/device claims; service validation tests |
| Delegation/constrained delegation | Not built | Enterprise apps need service-to-service identity delegation | P4 | Explicit support or published non-support; tests for constrained delegation if supported |
| NTLM compatibility decision | Not built | Legacy Windows stacks may still fall back to NTLM | P4 | Decision record: support, block with migration guidance, or proxy through Samba/AD during migration |

### 4.5 Windows Domain Compatibility

| Requirement for Drop-in Claim | Current DDS State | Gap | Priority | Acceptance Criteria |
|---|---|---|---|---|
| Windows domain join | Not built | Windows clients cannot join a DDS domain using native join flow | P4 | Windows 10/11 can join DDS test domain without AD DS |
| Domain controller discovery | libp2p discovery exists; no AD DNS SRV | Windows clients locate DCs via DNS SRV and site-aware logic | P4 | `_ldap._tcp`, `_kerberos._tcp`, site SRV records resolve correctly |
| Machine account secure channel | Not built | Windows domain members require machine trust and secret rotation | P4 | Machine account create/rotate/disable works; secure channel tests pass |
| Netlogon/SAMR/LSA minimum surface | Not built | Windows logon/domain management use MS-RPC services | P4 | Minimal protocol subset supports join, logon, password change, group lookup |
| Standard Windows logon path | DDS CP/Auth Bridge exists | Drop-in means no DDS-specific enrollment-only logon path for domain users | P4 | Standard domain credential and/or smartcard/passkey flow works against DDS domain |
| Cached logon behavior | Current AD coexistence relies on Windows cached domain logon | DDS domain must define offline cached semantics | P4 | Offline Windows logon works after first successful online DDS-domain logon |
| RSAT/Admin Center compatibility | Not built | Admins expect existing tools or equivalent | P5 | Either RSAT subset works via protocol facade or DDS admin UI covers same workflows |

### 4.6 Group Policy and Endpoint Management

| Requirement for Drop-in Claim | Current DDS State | Gap | Priority | Acceptance Criteria |
|---|---|---|---|---|
| DDS-native policy | WindowsPolicyDocument and agents exist | Coverage is narrower than GPO and has open enforcement bugs | P1/P2 | Policies are deterministic, retry failures, and cover documented security baselines |
| GPO compatibility | DDS policy is not GPO | Windows native clients expect SYSVOL, GPT.INI, CSEs, ADMX/ADML, security filtering | P4/P5 | `gpupdate`, RSOP, security templates, registry policy, scripts, software install test matrix |
| SYSVOL/NETLOGON shares | Not built | GPO delivery depends on SMB shares | P5 | Read-only or managed SYSVOL equivalent, versioning, integrity verification |
| Security filtering and WMI filters | Not built | GPO targeting semantics missing | P5 | DDS evaluator supports user/group/device/security filter semantics and explainable result |
| Loopback processing and precedence | Not built | Real GPO behavior is precedence-heavy | P5 | Inheritance/block/enforce/link-order/loopback compatibility tests |
| ADMX settings breadth | Registry allowlist exists | Need policy catalog and typed settings coverage | P5 | Import ADMX or generate DDS policy schema; broad Windows baseline coverage |
| macOS/Linux parity | macOS agent exists; Linux policy is design-level | AD replacement alternatives often manage cross-OS fleets | P3 | Greenfield endpoint story for Windows/macOS/Linux with compliance reporting |

### 4.7 DNS, PKI, Trusts, and Enterprise Services

| Requirement for Drop-in Claim | Current DDS State | Gap | Priority | Acceptance Criteria |
|---|---|---|---|---|
| Authoritative DNS for domain | Kademlia/DDS docs mention discovery | AD-compatible DNS zones and SRV records absent | P4 | DNS service can serve AD-compatible records and DDS records with signed source state |
| Certificate services | FIDO2 cert parsing exists; no CA service | AD CS/smartcard/cert templates not present | P4/P5 | CA profile, certificate templates, enrollment, revocation, audit, optional smartcard logon |
| Cross-domain/forest trust | Cross-org vouches are conceptual | No AD trust semantics, SID filtering, transitive trust, name suffix routing | P5 | Trust model decision and tests for at least one-way trust/migration scenario |
| Sites and subnets | mDNS/topic partitioning only | No AD-like site-aware DC selection and replication topology | P5 | Site documents, subnet mapping, DC locator behavior, sync policy |
| Replication admin model | P2P sync exists | No AD DRSR compatibility, lingering object handling, replication health UI | P5 | DDS-native replication health is enough for DDS; protocol compatibility decision recorded |

### 4.8 Cloud IAM / AD Alternative Features

These are not strictly AD DS requirements, but they are required if the claim is
"replace AD plus modern IAM alternatives."

| Requirement | Current DDS State | Gap | Priority | Acceptance Criteria |
|---|---|---|---|---|
| OIDC/SAML IdP | Not built | SaaS SSO missing | P3 | DDS identity can issue OIDC/SAML assertions with MFA claims and key rotation |
| SCIM provisioning | Not built | SaaS lifecycle management missing | P3 | SCIM 2.0 server/client for users/groups with conflict handling |
| Conditional access | DDS policy engine exists | No modern risk/device/app/location policy plane | P4 | Policy model can evaluate device posture, network, authenticator, app, and risk signals |
| HRIS lifecycle connectors | Not built | Joiner/mover/leaver automation missing | P4 | At least CSV/SCIM/Workday-style connector pattern; approvals and audit |
| PAM/JIT admin | Vouch delegation exists | No temporary elevation workflow comparable to PIM/PAM | P4 | Time-bound admin grants, approval, break-glass, audit, automatic expiry |
| Device compliance inventory | Agents report some applied state | No full compliance/posture dashboard | P4 | Endpoint inventory, posture, drift, and remediation reporting |

### 4.9 Operations, Migration, and Productization

| Requirement for Drop-in Claim | Current DDS State | Gap | Priority | Acceptance Criteria |
|---|---|---|---|---|
| AD import | Not built | Cannot migrate users/groups/OUs/GPOs | P2 | Read-only importer maps AD objects to DDS documents with dry-run and diff |
| AD sync/coexistence | v1 endpoint coexistence spec exists | No directory-level sync or cutover model | P3 | One-way and staged two-way sync design with conflict ownership rules |
| Password migration | No central passwords by design | AD password hashes generally cannot be safely exported; users must recredential or trust AD during transition | P3 | Recredential workflow, delegated auth bridge, or temporary AD trust path |
| GPO migration | DDS policy docs exist | No GPO/ADMX conversion | P4 | Converter for common registry/security/software policies with unsupported-item report |
| SIDHistory / ACL migration | Not built | File/share/app ACL continuity breaks | P4/P5 | SID mapping and migration guidance; test with SMB/file ACLs if Windows domain compatibility is pursued |
| Backup/restore | redb store exists | No full domain backup, restore, point-in-time recovery, disaster exercise | P2 | Signed backup format, restore validation, key escrow guidance, drill docs |
| Monitoring/SIEM | Audit chain mechanism exists; **emission unwired in production (Z-3)** | Need operational dashboards, alerts, SIEM export | P2 | JSON/syslog/OpenTelemetry export; health checks; audit query tooling — **implementation plan tracked in [observability-plan.md](observability-plan.md)** (Phase A wires audit emission and closes Z-3; Phases B–F deliver SIEM export, Prometheus `/metrics`, Alertmanager rules, reference Grafana dashboards, and `dds-cli` ops surface — no custom web UI on the critical path) |
| Upgrade/rollback | Crate tests exist | No compatibility contract for token/schema/protocol upgrades | P2 | Version negotiation, migration tests, downgrade refusal where unsafe |
| Scale/performance | Load tests exist | AD replacement needs published capacity envelopes | P3 | Benchmarks for 10k/100k users, group expansion, LDAP query, policy eval, sync convergence |
| Admin UX | CLI exists | AD admins need discoverable workflows | P3 | Admin UI/API for common identity, group, policy, audit, device tasks |

---

## 5. Roadmap

### Phase 0: Claim Control and Security Closure

**Goal:** make DDS safe to pilot as DDS, not as AD replacement.

Work:

1. Close A-2, A-3, A-4.
2. Close B-1 through B-6.
3. Land production hardening for M-13, M-15, and M-18 or explicitly scope them
   out of the pilot threat model.
4. Add regression tests for every closed finding.
5. Update public docs to avoid unqualified "drop-in AD replacement" wording.
6. Publish a security posture page with supported deployment modes:
   development, pilot, production-hardened.

Exit gate:

| Gate | Required Evidence |
|---|---|
| P0-G1 | Zero open Critical/High findings in current review ledger |
| P0-G2 | Windows production install defaults to named pipe plus response MAC |
| P0-G3 | Sync and trust graph persistence have adversarial tests |
| P0-G4 | Policy/software failure retry behavior is tested on Windows and macOS |
| P0-G5 | Docs use claim ladder terminology |

### Phase 1: DDS Directory Core

**Goal:** build the canonical directory model that all protocol facades will use.

Work:

1. Add versioned `UserDocument`, `ComputerDocument`, `GroupDocument`,
   `OrgUnitDocument`, `ServicePrincipalDocument`, `DnsRecordDocument`, and
   `SchemaDocument`.
2. Define object lifecycle: create, update, rename, move, disable, tombstone,
   restore, burn.
3. Add stable aliases and compatibility IDs: UPN-like name, short name,
   object GUID, SID/RID strategy.
4. Implement nested group expansion with cycle limits and deterministic order.
5. Add object-level authorization and delegated administration.
6. Add indexed search over active directory state.

Exit gate:

| Gate | Required Evidence |
|---|---|
| P1-G1 | 10k-user synthetic directory can be indexed and queried locally |
| P1-G2 | Object conflict rules are deterministic under partition/rejoin tests |
| P1-G3 | Group expansion has property tests for nesting, cycles, revocation, expiry |
| P1-G4 | Authorization trace explains why a mutation was accepted or denied |

### Phase 2: LDAP/LDAPS Compatibility Layer

**Goal:** support common legacy app read/search/bind workloads.

Work:

1. Create `dds-ldap-proxy` crate/binary.
2. Support LDAP bind, search, compare, unbind, StartTLS, LDAPS.
3. Map DDS documents to an AD/LDAP-compatible schema subset.
4. Implement paged results, server-side sort, and common search filters.
5. Add scoped service accounts and audit for LDAP reads/binds.
6. Add read-only mode first; add controlled write mode after authorization is
   proven.

Exit gate:

| Gate | Required Evidence |
|---|---|
| P2-G1 | `ldapsearch` and common LDAP libraries work unchanged |
| P2-G2 | At least five representative apps can bind/search against DDS |
| P2-G3 | LDAPS/StartTLS config passes negative and rotation tests |
| P2-G4 | Unsupported LDAP controls return explicit errors, not silent bad data |

Claim unlocked: L2 for selected LDAP workloads, with a compatibility matrix.

### Phase 3: DDS-Managed Endpoint Replacement

**Goal:** make DDS viable for greenfield fleets that do not require native AD
domain join.

Work:

1. Finish Windows AD coexistence v1.
2. Expand Windows policy coverage and deterministic software/policy handling.
3. Finish macOS policy/login-adjacent workflows within supported platform
   boundaries.
4. Add Linux policy/account/PAM/SSSD-adjacent integration if Linux is in claim
   scope.
5. Build admin UX for users, groups, devices, policy, and audit.
6. Add compliance reporting and SIEM export.

Exit gate:

| Gate | Required Evidence |
|---|---|
| P3-G1 | Greenfield Windows endpoint can be enrolled, sign in, receive policy, install software, and report drift without AD |
| P3-G2 | AD/hybrid Windows host remains audit-only and safe under transition tests |
| P3-G3 | macOS and Linux support statements are explicit and tested |
| P3-G4 | Operators can recover a lost node, rotate keys, and restore from backup |

Claim unlocked: L3 for DDS-managed endpoints. Still not AD DS drop-in.

### Phase 4: Kerberos and Windows Domain Compatibility Spike

**Goal:** decide whether DDS will pursue native AD DS protocol compatibility or
use a Samba/materialized compatibility facade.

Strategic options:

| Option | Description | Pros | Cons |
|---|---|---|---|
| Native DDS protocol implementation | Implement Kerberos KDC, DNS SRV, Netlogon, SAMR/LSA, domain join, and related Windows protocol surfaces directly | Preserves DDS purity and full control | Very large protocol/security burden |
| Samba compatibility facade | Run Samba AD DC as the Windows protocol surface and materialize DDS state into/from Samba | Fastest route to Windows compatibility; reuses mature protocol implementation | Adds DC-like infrastructure; Samba AD DC uses its own integrated LDAP/KDC stack, so DDS is not the direct backing store |
| Coexistence-only | Do not pursue Windows domain drop-in; keep DDS as overlay and greenfield endpoint manager | Realistic and safer | Cannot claim drop-in AD DS replacement |

Work:

1. Write an ADR choosing one option.
2. If native: implement minimum Kerberos KDC and SPN model first.
3. If Samba facade: prototype one-way DDS -> Samba materializer for users,
   groups, OUs, DNS, and GPO metadata.
4. Build Windows client test harness for domain join/logon/gpupdate.

Exit gate:

| Gate | Required Evidence |
|---|---|
| P4-G1 | ADR approved with security and operational tradeoffs |
| P4-G2 | Windows 10/11 compatibility harness runs in CI or scheduled lab |
| P4-G3 | Kerberos service-ticket flow works for at least one non-Windows service |
| P4-G4 | Password/credential model is explicit and reviewed |

### Phase 5: AD DS Protocol-Compatible Domain Pilot

**Goal:** make a small Windows lab domain work without Microsoft AD DS.

Work:

1. Domain join for Windows clients.
2. DNS SRV/DC locator behavior.
3. Machine account secure channel and rotation.
4. Kerberos TGT/TGS with group claims.
5. LDAP read/search for Windows and admin tooling.
6. Password change/reset and lockout.
7. Minimal GPO: registry policy, security policy, scripts, software install.
8. Offline cached logon semantics.

Exit gate:

| Gate | Required Evidence |
|---|---|
| P5-G1 | Windows client joins DDS-backed domain using native UI/CLI |
| P5-G2 | Domain user logs on online and offline |
| P5-G3 | Kerberos auth works to SMB/HTTP test services |
| P5-G4 | `gpupdate` applies a documented GPO subset |
| P5-G5 | Password reset/change/lockout tests pass |
| P5-G6 | LDAP admin reads show expected users/groups/computers/OUs |

Claim unlocked: limited L4 lab claim, not enterprise claim.

### Phase 6: Migration and Coexistence Tooling

**Goal:** make AD-to-DDS migration possible without a flag day.

Work:

1. AD read-only importer with dry-run diff.
2. Directory-level coexistence bridge: AD authoritative, DDS shadow; then staged
   DDS authoritative domains.
3. User recredentialing flow for passwords/FIDO2.
4. Group, OU, DNS, and GPO migration tools.
5. SID/SIDHistory strategy and ACL migration guidance.
6. Rollback plan and disaster drills.

Exit gate:

| Gate | Required Evidence |
|---|---|
| P6-G1 | Import of a representative AD lab produces deterministic DDS state |
| P6-G2 | Migration report flags unsupported attributes, GPOs, and protocols |
| P6-G3 | Pilot users can migrate credentials without admin password exposure |
| P6-G4 | Rollback tested from DDS pilot back to AD |

### Phase 7: Enterprise Replacement Evidence

**Goal:** support a qualified enterprise replacement claim.

Work:

1. Multi-site and partition/rejoin tests at target scale.
2. Backup/restore, key escrow, rotation, and disaster recovery runbooks.
3. Monitoring, health, SIEM, and audit retention.
4. External penetration test and protocol security review.
5. Interoperability matrix for Windows versions, applications, LDAP controls,
   Kerberos clients, and GPO areas.
6. Documentation for unsupported AD features.

Exit gate:

| Gate | Required Evidence |
|---|---|
| P7-G1 | Published compatibility matrix with pass/fail status |
| P7-G2 | External security report has no open Critical/High issues |
| P7-G3 | Scale tests meet documented SLOs |
| P7-G4 | Operator docs cover install, upgrade, backup, restore, incident response, migration, and rollback |

Claim unlocked: L5, only for the compatibility subset that passed.

---

## 6. Minimum Interoperability Matrix

Before any drop-in claim, DDS needs a public matrix like this:

| Surface | Minimum Tests |
|---|---|
| Windows clients | Windows 10/11 Pro and Enterprise join, online logon, offline logon, password change, lockout, group refresh |
| Kerberos | MIT client, Windows client, HTTP service, SMB service, key rotation, clock skew |
| LDAP | simple bind, LDAPS, StartTLS, paged search, nested group search, common filters, service account bind |
| GPO | registry policy, security policy, scripts, software install, security filtering, inheritance/precedence |
| DNS | SRV records, A/AAAA/CNAME, dynamic or managed updates, site-aware lookup if supported |
| Admin | create/disable/delete user, group membership, OU move, delegated admin, audit query |
| Migration | AD import, unsupported feature report, user recredentialing, rollback |
| Security | malicious peer, local unprivileged process, stolen node files, replay, duplicate JTI, failed policy retry |
| Operations | backup/restore, upgrade/rollback, monitoring alerts, SIEM export, disaster recovery |

---

## 7. Backlog Seeds

Use these as initial epics.

| Epic | Owner Area | First Deliverable |
|---|---|---|
| E1 Security closure | Core/security/platform | P0 findings closed with regression tests |
| E2 Directory object core | `dds-domain`, `dds-core`, `dds-store` | Versioned user/group/ou/computer documents and indexes |
| E3 LDAP proxy | New `dds-ldap-proxy` crate | Read-only LDAP search/bind over DDS state |
| E4 Admin authorization | `dds-core` policy/trust | Object-level ACL/delegation evaluator |
| E5 Windows production hardening | Windows native + agent | Named pipe config default, DACLs, response MAC fail-closed |
| E6 Policy determinism | `dds-node`, agents | Single active policy/software version resolution and retry semantics |
| E7 Kerberos spike | New service/prototype | KDC feasibility prototype or Samba facade ADR |
| E8 Migration tools | CLI + connector | AD read-only import and diff report |
| E9 Ops | Node/CLI/docs | backup/restore, health, SIEM export |
| E10 Compatibility lab | CI/platform | automated Windows domain/LDAP/Kerberos/GPO matrix |

---

## 8. Non-Negotiable Claim Rules

1. Do not call DDS a drop-in AD DS replacement until native Windows domain
   join/logon, LDAP, Kerberos, DNS SRV discovery, and a documented GPO subset
   pass the compatibility matrix.
2. Do not let post-quantum signatures substitute for protocol security review.
   Modern crypto helps, but most AD replacement risk is in authorization,
   migration, local privilege boundaries, and legacy protocol behavior.
3. If DDS chooses not to support NTLM, DRSR, full RSAT, AD CS, or full GPO
   parity, document that clearly and scope the claim.
4. Keep DDS-native endpoint management as a separate, valid product path. It can
   succeed earlier than AD DS drop-in compatibility.
5. Treat migration and rollback as core features, not professional-services
   afterthoughts.

---

## 9. References

Local DDS references:

- `README.md`
- `STATUS.md`
- `Claude_sec_review.md`
- `docs/windows-ad-coexistence-spec.md`
- `docs/DDS-Design-Document.md`
- `docs/DDS-Developer-Guide.md`
- `docs/DDS-Admin-Guide.md`

External compatibility baseline:

- Microsoft AD DS overview: <https://learn.microsoft.com/en-us/windows/win32/ad/about-active-directory-domain-services>
- Microsoft AD protocols overview: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adod/5ff67bf4-c145-48cb-89cd-4f5482d94664>
- Microsoft Kerberos overview: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
- Microsoft Entra Domain Services overview: <https://learn.microsoft.com/en-us/entra/identity/domain-services/overview>
- Microsoft Entra authentication overview: <https://learn.microsoft.com/en-us/entra/identity/authentication/overview-authentication>
- Microsoft Entra Conditional Access overview: <https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview>
- Samba AD DC setup: <https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller>
- Samba security documentation: <https://wiki.samba.org/index.php/Samba_Security_Documentation>
- FreeIPA overview: <https://www.freeipa.org/page/About>
- FreeIPA trusts: <https://www.freeipa.org/page/Trusts>
- 389 Directory Server features: <https://www.port389.org/docs/389ds/FAQ/features.html>
- OpenLDAP security: <https://www.openldap.org/doc/admin26/security.html>
- OpenLDAP access control: <https://www.openldap.org/doc/admin26/access-control.html>
- OpenLDAP replication: <https://www.openldap.org/doc/admin26/replication.html>
- Okta Universal Directory: <https://developer.okta.com/docs/concepts/universal-directory/>
- Okta AD integration features: <https://help.okta.com/oie/en-us/content/topics/directory/ad-feature-support.htm>
- JumpCloud Cloud LDAP: <https://jumpcloud.com/platform/ldap>
