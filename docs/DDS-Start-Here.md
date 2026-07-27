# DDS: Start Here

A plain-language guide to running a DDS domain day to day. Read this
before [DDS-Admin-Guide.md](DDS-Admin-Guide.md), which is a 4000-line
reference you should look things up in, not read front to back.

**Who this is for:** whoever installs DDS and then has to add people,
approve them, remove them, and let them log in.

---

## 1. Four things exist

| Thing | What it is | How many |
|---|---|---|
| **Domain** | The organisation. Has one signing key that proves "this belongs to us". | 1 |
| **Node** | One machine running `dds-node`. Nodes gossip with each other so they all end up knowing the same facts. | 1 per machine |
| **Admin** | A *person* holding a security key, who is allowed to approve things. | 1 or more |
| **User** | A person with a security key, who can log in to machines. | many |

Everything DDS knows is a small signed statement ("token") that spreads
to every node by gossip. Nobody is a central server. There is no
database to back up other than each node's own copy.

Two statements matter most:

- **"This key belongs to Alice."** Created when Alice enrols. Proves
  identity, grants nothing.
- **"I, an admin, approve Alice for X."** Called a **vouch**. This is
  what actually grants access. No vouch = no access.

---

## 2. Which machine can do what — and why

This is the part that confuses everyone, including the person who wrote
the tooling. It comes down to **two independent questions**:

**Q1: Does this machine hold an admin's signing key?**
Approving anything means *signing* a statement, and a security key can't
sign arbitrary statements — it only proves you're present. So each admin
also has an Ed25519 signing key on disk, minted by `admin-setup`. Your
security-key touch is what unlocks permission to use it.

Today that key is encrypted with the node's own identity key, so it is
undecryptable on any other machine. Two consequences worth separating:

- *Needing* a software signing key is unavoidable — FIDO2 can't do this.
- *Being stuck on one machine* is a current implementation choice, not a
  law of the design. Moving it to OS-backed storage (Keychain / DPAPI /
  TPM) with a portable export path is tracked as `TODO(security)` / M-22.

> Consequence for now: *the machine where you ran admin-setup is the only
> machine that admin can approve things from.* To approve from your laptop
> too, that laptop needs its **own** admin — recipe 7, which is one guided
> flow.

**Q2: Does the *target* machine trust that admin?**
Each node has a list of admins it trusts (`trusted_roots`). A vouch
signed by an admin the node doesn't trust is ignored — silently, from the
user's point of view. Trust arrives one of two ways:

- written into that node's config, or
- an existing trusted admin signs "this other person is also an admin"
  (a `dds:admin` vouch), which gossips, and every node then promotes them
  automatically.

**The short version:**

| I want to… | I need… |
|---|---|
| Enrol a new person's key | any node. No admin needed. |
| Approve / remove / promote someone | a machine holding **your** admin signing key |
| Have that approval respected everywhere | every node to trust your admin (config, or a `dds:admin` vouch) |
| Publish policy (e.g. create Windows accounts) | an admin, **and** that node granted `dds:policy-publisher-<platform>` |

---

## 3. Your tools

**Windows** — use the GUI. `DdsConsole.ps1` (Start menu → DDS Console)
covers essentially everything: approve, onboard, offboard, make/remove
admin, create accounts, publish policy.

**macOS / Linux** — menu-driven scripts, all needing `sudo`:

| Command | Does |
|---|---|
| `dds-domain` | bootstrap a domain, admit another node, show status, decommission |
| `dds-user` | enrol / approve / promote / demote / offboard people |
| `dds-account` | create-modify-delete local OS accounts via policy |
| `dds-verify-replication` | health check; is this node in sync? |

Handy one-liner when you need a device's URN (for policy scoping, or to
check what actually joined):

```bash
sudo dds --node-url "unix:/Library/Application Support/DDS/dds.sock" platform devices
```

Underneath: `dds-fido2` does security-key ceremonies, `dds` (dds-cli) is
the raw API client. Reach for those when a wizard can't express what you
want.

---

## 4. Recipes

### 1. Start a brand-new domain
```
macOS/Linux:  sudo dds-bootstrap-domain   then   sudo dds-enroll-admin
Windows:      Bootstrap-DdsDomain.ps1     then   DDS Console → Admin Setup
```
Creates the domain, this node, and your first admin. Keep
`domain_key.bin` safe — it is the root of everything and cannot be
regenerated.

### 2. Add a second machine
On the first machine, copy out `provision.dds`. On the new machine:
```
sudo dds-node provision /path/to/provision.dds
```
One file, one command, one security-key touch.

> Make the bundle **after** creating your first admin. A bundle created
> before that seeds new nodes with an empty trust list, and gossip never
> fixes it — you'd have to edit config by hand. The scripts regenerate
> the bundle automatically after admin setup for exactly this reason.

**What joining gives you, and what it doesn't.** Everything in the trust
graph replicates, so the new machine immediately knows every user, every
approval, who the admins are, and every published policy. Nobody has to
re-enrol anyone.

It does **not** create OS accounts. Those exist only where a policy says
so, and whether your existing policies reach the new machine depends
entirely on how they were scoped:

| Policy scoped by | Reaches a newly joined machine? |
|---|---|
| nothing (all dimensions empty) | yes — an empty scope matches every device |
| `device_tags` | yes, if the machine self-attests that tag |
| `org_units` | yes, if it self-attests that org unit |
| `identity_urns` (specific machines) | **no — and silently** |

Joining self-attests a tag for you: `auto-provisioned` via `dds-node
provision`, `joined-node` via the Windows enrol script, `bootstrap-node`
on the machine that started the domain. So scoping a policy by tag or org
unit is what makes it apply to machines that don't exist yet. Scoping by
`identity_urns` is a deliberate choice to target *only* the machines you
name — useful, but it will never grow.

Then one more platform split, once a policy does match:

- **macOS / Linux** — the account is created on the next policy poll, no
  logon needed, with a locally generated password.
- **Windows** — the account is created at that person's **first logon** on
  that machine. No admin action, but somebody has to log in once per
  machine before the account exists (see rule 5 below).

### 3. Add a person
```
sudo dds-user     → "Enrol a new person"
```
They touch **their own** key. This creates their identity and grants
nothing.

### 4. Let them log in
```
sudo dds-user     → "Approve a person for session login"
```
**You** touch **your admin** key. This is the vouch. Until it exists and
has reached the machine they're logging in to, they cannot log in.

### 5. Remove someone
```
sudo dds-user     → "Offboard a person entirely"
```
Revokes every vouch **you** issued for them. If another admin also
vouched for them, that admin must revoke theirs too — DDS will tell you
who. One admin cannot undo another's approvals.

This blocks their logon everywhere. It does **not** remove their OS
accounts — that is a separate job, recipe 10.

### 6. Promote / demote an admin
```
sudo dds-user     → "Promote a person to admin" / "Demote an admin"
```
Promotion gossips, and every node starts trusting them. Note they still
need their **own** signing key on whatever machine they'll approve from
(back to Q1).

### 7. Let a second machine approve things
```
On that machine:  sudo dds-user  → "Make THIS machine able to approve things"
```
One flow. It works out where you already are and only asks for what's
missing: mints a local admin signing key (your key touch), then prints the
exact cross-vouch command to run on a machine that already has a trusted
admin, and offers to wait until the promotion arrives.

Two things it will tell you about rather than hide:
- On a node that joined via a provision bundle, the anti-escalation gate
  (`admin_setup` requires an empty trusted-root list) is already closed.
  The flow offers to briefly clear the list and put it back — a real edit
  to `dds.toml`, backed up first, and it asks before doing it.
- Step 2 needs the *other* admin's security key, not yours. Nobody can
  self-promote.

### 8. Give someone a Windows account that doesn't exist yet
DDS can create the local Windows account at their first logon.
Requirements, all of them:
- the person is enrolled and approved (recipes 3 + 4)
- an admin published a "claim" policy naming them and that machine
- the machine is **Workgroup-joined** (not AD/Entra — unsupported today)

Easiest path is the Windows console's account wizard. From macOS/Linux
it's `dds-account`, which handles authorising the node to publish first.

---

### 9. A domain where new machines get accounts by themselves
The full worked example. Do the first three steps **once**; after that,
adding a machine is one command and the accounts follow.

**1. Start the domain and become an admin** (recipes 1 and 2's prep).
```
sudo dds-bootstrap-domain
sudo dds-enroll-admin
```

**2. Enrol and approve your people** — once each, ever, for the whole
domain. Not per machine.
```
sudo dds-user   → "Enrol a new person"              (they touch their key)
sudo dds-user   → "Approve a person for session login"   (you touch yours)
```
Note each person's subject URN; step 3 needs it.

**3. Publish an account policy scoped by TAG, not by machine.** This is
the step that decides whether the domain grows by itself.
```
sudo dds-account   → "Create/modify/... a local account"
   Device tags:   joined-node, auto-provisioned
   Org units:     (blank)
   Device URNs:   (skip — answer "n" to the pick-list)
```
Or publish the file directly — a complete, tested example lives at
[`platform/windows/examples/account-claim-by-tag.json`](../platform/windows/examples/account-claim-by-tag.json):
```
sudo dds --node-url "unix:/Library/Application Support/DDS/dds.sock" \
     policy publish-windows --from-file account-claim-by-tag.json
```
The key line is the scope:
```json
"scope": {
  "device_tags": ["joined-node", "auto-provisioned"],
  "org_units": [],
  "identity_urns": []
}
```
Those two tags are self-attested by the join itself — `joined-node` by
the Windows enrol script, `auto-provisioned` by `dds-node provision`. So
the policy matches every machine that ever joins, including ones that
don't exist yet. Put device URNs in `identity_urns` and you get the
opposite: only those machines, forever, silently.

For macOS/Linux accounts the shape is the same with a `macos`/`linux`
block instead — see the `examples/account-create.json` in each platform's
packaging directory.

**4. Now add machines.** Each one, forever, is:
```
sudo dds-node provision /path/to/provision.dds
```

**What happens on its own from here:** the new machine learns every user
and every approval by gossip within ~60s, matches the tag-scoped policy
because it tagged itself at join, and then:
- **macOS/Linux** — creates the accounts on the next policy poll. Nobody
  has to log in first.
- **Windows** — creates each account at that person's first logon on that
  machine. No admin action, but somebody must sign in once per machine.

**To add a person later**, do step 2 and add one directive to the step-3
policy with a bumped `version`. No machine is touched.

---

### 10. Delete the OS accounts of someone you offboarded
Offboarding (recipe 5) revokes their vouches, so **they can no longer log
in anywhere** — session issuance fails with "subject has no granted
purposes".

It does **not** touch their OS accounts. The policy agent never consults
vouches; account lifecycle is driven only by policy directives. So after
offboarding, on every machine they ever signed into:

- the local account still exists, enabled
- their profile and files are still there
- the sealed credential vault is still on disk

They can't get in via DDS, and they never knew the password — it is
generated on the machine and never displayed. But it is a real local
account that a local administrator could reset.

**To actually remove the accounts**, publish a policy directive with
`"action": "Delete"` (or `"Disable"` to keep the profile) for that
username, scoped the same way the Create was, and bump the version:
```
sudo dds-account   → choose Delete, same scope as the create policy
```
Then confirm it applied, rather than assuming — a version that didn't
increase publishes cleanly and is ignored.

> Treat "offboard" and "delete the account" as two separate jobs. Doing
> only the first leaves a dormant local account on every machine.

---

## 5. When something doesn't work

| Message | Means | Fix |
|---|---|---|
| "subject has no granted purposes" | enrolled but never approved | recipe 4 |
| "no claimable windows account for subject" | no matching claim policy for this exact machine, or it hasn't replicated yet | check the device matches the policy's scope; wait ~60s |
| "identity is not a trusted root" | you're approving from a machine whose admin nobody trusts | recipe 7 |
| "Authenticator did not return hmac-secret output" | the key was registered by something that didn't request `hmac-secret`; it can't unseal the Windows vault | re-register the person (a fresh credential on the same key) |
| "Timeout waiting for user interaction" | key wasn't touched, or a fingerprint wasn't recognised | hold an enrolled finger flat on the sensor; unplug/replug if it never lights |
| Tile appears but logon fails | tiles don't check approval; the approval check happens after the touch | recipe 4 |
| Peer connected but not "admitted" | admission handshake incomplete | `dds-verify-replication`; a watchdog restarts the node if it persists |

Health check on any node: `sudo dds-verify-replication`.
`connected_peers` and `admitted_peers` should match.

---

## 6. Rules that surprise people

1. **A vouch is what grants access, not enrolment.** Enrolling only says
   who someone is.
2. **Admin power is tied to a machine, not just a person.** Their signing
   key lives on one box and cannot be moved (today — see §2 Q1). Fix it
   per machine with recipe 7.
3. **An admin can only revoke their own approvals.**
4. **Security keys must be registered with `hmac-secret` for Windows
   logon**, and that can only be set when the credential is created —
   never added later. Use the supplied tools and this is automatic.
5. **Windows passwords never travel.** Each machine generates and stores
   its own, sealed to the user's key. So the same person needs a first
   logon on each machine.
6. **A policy scoped to specific machines never covers new ones.** Joining
   a machine replicates every user and approval to it automatically, but
   accounts come from policy, and an `identity_urns` scope only ever
   matches the machines you listed. Scope by tag or org unit for anything
   meant to apply going forward.
7. **Offboarding does not delete accounts.** Revoking vouches blocks
   logon; the OS account, profile and vault stay on every machine the
   person used. Account lifecycle is policy-only — recipe 10.
8. **Policy versions must increase.** Republishing at the same or lower
   version is accepted and then silently ignored by every device. The
   wizards look up the current version for you.
9. **Windows account creation needs Workgroup**, not domain-joined.
10. **Nothing is instant.** Changes gossip in seconds normally, up to ~60s
   worst case.

---

## 7. Honest note on complexity

Some of the above is irreducible: if approvals are cryptographic
signatures and signing keys can't be copied, then "which machine am I
at" genuinely matters. That is the price of having no central server to
compromise.

But some of it is just rough edges, and worth knowing they're rough
rather than assuming you misunderstood:

- **Admin signing keys are stuck on one machine.** A design choice, not a
  requirement — see §2 Q1 and M-22.
- **macOS/Linux have menu scripts where Windows has a real console.**
  Same capabilities, worse ergonomics.
- **Failures often surface one layer away from the cause** — a logon
  rejected for a missing approval, a policy published successfully and
  then ignored for a version number. The error table above exists
  because those messages don't say what to do.
- **Nothing enforces policy version ordering server-side.** The wizards
  look the current version up and warn you, but that's tooling papering
  over a missing server check.

Two rough edges called out in earlier drafts of this guide are now fixed:
setting up a second approving machine is one guided flow (recipe 7), and
device URNs are picked from a list rather than copied by hand
(`dds platform devices`, and the pick-list in `dds-account`).

If a task feels harder than it should, it may well be. Worth reporting
rather than working around.
