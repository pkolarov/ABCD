#!/usr/bin/env bash
# DDS User — enroll, approve, promote, demote, or offboard a person.
#
# Linux port of platform/macos/packaging/dds-user.sh.
#   sudo dds-user
#
# Thin menu wrapper around `dds-fido2` (the FIDO2 ceremony tool) and
# `dds-cli` (the CLI). Every action that grants or revokes trust requires
# an admin's FIDO2 touch (and PIN, for User Verification) — that's the
# real security boundary; this script just shapes the prompts.
set -euo pipefail

DATA_DIR="/var/lib/dds"
API_SOCK="${DATA_DIR}/dds.sock"
NODE_URL="unix:${API_SOCK}"
FIDO2_CLI="/usr/bin/dds-fido2"
DDS_CLI="/usr/bin/dds-cli"

if [[ $EUID -ne 0 ]]; then
  echo "Error: run with sudo" >&2
  exit 1
fi

curl -sf --unix-socket "${API_SOCK}" "http://localhost/v1/status" > /dev/null 2>&1 || {
  echo "Error: dds-node not running (run dds-domain to bootstrap first)" >&2
  exit 1
}

list_enrolled_users() {
  echo ""
  echo "Enrolled users:"
  "${DDS_CLI}" --node-url "${NODE_URL}" cp enrolled-users 2>/dev/null || echo "  (could not list — check dds-node is running)"
  echo ""
}

prompt_subject_urn() {
  list_enrolled_users
  printf "Subject URN (paste from the list above): "
  read -r SUBJECT_URN
  [[ -n "${SUBJECT_URN}" ]] || { echo "URN required" >&2; exit 1; }
}

DDS_TOML="${DATA_DIR}/dds.toml"
NODE_DATA="${DATA_DIR}/node"

api() { curl -sf --unix-socket "${API_SOCK}" "$@"; }

# Does this machine hold the on-disk Ed25519 signing key for `$1`?
#
# Approving anything means *signing* it with an admin's Ed25519 key, and
# `admin_setup` seals that key under a wrap key derived from the node's
# own identity — so it is undecryptable on any other machine. The key
# file is named SHA256(urn), which can't be reversed, so this is a
# forward hash-and-test rather than a directory listing.
holds_admin_key_for() {
  local urn="$1" hash
  hash="$(printf '%s' "${urn}" | sha256sum | awk '{print $1}')"
  [[ -f "${NODE_DATA}/admin_keys/${hash}.key" ]]
}

# Prints the URN of a trusted root whose signing key lives here, if any.
local_trusted_admin_urn() {
  local roots urn
  roots="$(api http://localhost/v1/admin/roots 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for r in d.get('roots', []):
    print(r.get('urn', ''))
" 2>/dev/null || true)"
  while IFS= read -r urn; do
    [[ -n "${urn}" ]] || continue
    if holds_admin_key_for "${urn}"; then
      printf '%s' "${urn}"
      return 0
    fi
  done <<< "${roots}"
  return 1
}

# The URN admin-setup minted here, whether or not the domain trusts it.
stored_admin_urn() {
  "${FIDO2_CLI}" list-admins --json 2>/dev/null | python3 -c "
import json, sys
try:
    admins = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for a in admins:
    if a.get('urn'):
        print(a['urn'])
        break
" 2>/dev/null || true
}

# Poll /v1/admin/roots until `$1` shows up as a trusted root.
wait_for_promotion() {
  local urn="$1" i
  echo ""
  echo "Waiting for the vouch to reach this node (Ctrl-C to stop; it will"
  echo "still take effect whenever it arrives)..."
  for i in $(seq 1 60); do
    if api http://localhost/v1/admin/roots 2>/dev/null | grep -qF "${urn}"; then
      echo ""
      echo "Promoted. This machine can now approve, promote, and offboard."
      return 0
    fi
    printf "."
    sleep 2
  done
  echo ""
  echo "Not promoted after 2 minutes. Check that the vouch was actually"
  echo "issued, and that this node has admitted peers:"
  echo "  sudo dds-verify-replication"
  return 1
}

print_crossvouch_instructions() {
  local urn="$1"
  echo ""
  echo "------------------------------------------------------------"
  echo "STEP 2 — on a machine that ALREADY has a trusted admin, run"
  echo "one of these to make the whole domain trust this machine's"
  echo "admin. It needs THAT admin's FIDO2 key, not yours:"
  echo ""
  echo "  Windows:      dds-enroll-user.exe --vouch \\"
  echo "                  --subject-urn ${urn} \\"
  echo "                  --purpose dds:admin"
  echo ""
  echo "  macOS/Linux:  sudo dds-user  → 'Promote a person to admin'"
  echo "                (paste ${urn})"
  echo "------------------------------------------------------------"
}

# Follow-up to the two-machines-two-steps wart called out in
# docs/DDS-Start-Here.md §7: one flow that figures out where you are and
# only asks for what's actually missing.
make_this_machine_approver() {
  echo ""
  echo "=== Make THIS machine able to approve things ==="
  echo ""

  # Already done?
  local existing
  if existing="$(local_trusted_admin_urn)"; then
    echo "This machine can already approve. Nothing to do."
    echo "  admin URN: ${existing}"
    echo "  (its signing key is here, and the domain trusts it)"
    return 0
  fi

  # Half done — local admin exists but the domain hasn't promoted it.
  local pending
  pending="$(stored_admin_urn)"
  if [[ -n "${pending}" ]] && holds_admin_key_for "${pending}"; then
    echo "An admin was already set up here, but the domain does not trust"
    echo "it yet — so its signatures are currently ignored everywhere."
    echo "  admin URN: ${pending}"
    print_crossvouch_instructions "${pending}"
    printf "Poll until it's promoted? [Y/n]: "
    read -r RESP
    RESP="${RESP:-Y}"
    [[ "${RESP}" =~ ^[Yy] ]] && wait_for_promotion "${pending}"
    return 0
  fi

  echo "This machine has no admin signing key, so it cannot sign approvals."
  echo "Step 1 mints one here; step 2 gets the domain to trust it."
  echo ""

  # The C-2 gate: admin_setup refuses while trusted_roots is non-empty.
  # Any node that joined via a provision bundle has a seeded root, so
  # this branch is the normal case for a second machine, not an edge case.
  local cur_roots restore_after=0 saved_roots="" ts
  ts="$(date +%Y%m%d-%H%M%S)"
  cur_roots="$(api http://localhost/v1/status | python3 -c 'import sys,json; print(json.load(sys.stdin)["trusted_roots"])' 2>/dev/null || echo "?")"
  echo "  trusted roots on this node: ${cur_roots}"

  if [[ "${cur_roots}" != "0" ]]; then
    echo ""
    echo "  admin-setup requires this node's trusted-root list to be EMPTY"
    echo "  (the C-2 anti-escalation gate: it exists so a local process"
    echo "  can't self-enroll as a second admin). This node already trusts"
    echo "  ${cur_roots} admin(s), so the gate is closed."
    echo ""
    echo "  This wizard can briefly clear the list, run admin-setup, then"
    echo "  put the existing admins back so this node trusts BOTH. During"
    echo "  that window (a few seconds) this node trusts no admin and"
    echo "  ignores incoming vouches. It needs root, which you already"
    echo "  have, so it grants nothing you couldn't do by hand — but it is"
    echo "  a real edit to ${DDS_TOML}, backed up first."
    echo ""
    printf "  Proceed? [y/N]: "
    read -r RESP
    [[ "${RESP}" =~ ^[Yy] ]] || { echo "  Nothing changed."; return 0; }

    saved_roots="$(grep -E '^trusted_roots' "${DDS_TOML}" || true)"
    [[ -n "${saved_roots}" ]] || { echo "  Error: no trusted_roots line in ${DDS_TOML}" >&2; return 1; }
    cp "${DDS_TOML}" "${DDS_TOML}.bak-${ts}"
    echo "  backed up: ${DDS_TOML}.bak-${ts}"

    python3 - "${DDS_TOML}" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(r'(?m)^trusted_roots\s*=.*$', 'trusted_roots = []', s, count=1)
# bootstrap_admin_urn is never demoted, so it must go too or the gate
# stays effectively closed.
s = re.sub(r'(?m)^bootstrap_admin_urn\s*=.*\n', '', s, count=1)
open(p, 'w').write(s)
PY
    systemctl restart dds-node
    printf "  waiting for node..."
    for _ in $(seq 1 30); do
      api http://localhost/v1/status >/dev/null 2>&1 && { echo " ready"; break; }
      printf "."; sleep 1
    done
    restore_after=1
  fi

  # The sentinel is the deliberate out-of-band operator gesture C-2 wants.
  # `provision` does not create one — joining a domain isn't bootstrapping.
  local sentinel="${NODE_DATA}/.bootstrap"
  [[ -e "${sentinel}" ]] || { echo "  creating C-2 sentinel: ${sentinel}"; touch "${sentinel}"; }

  echo ""
  echo "--- STEP 1: mint an admin identity on this machine ---"
  printf "Label for this admin [%s-admin]: " "$(hostname -s)"
  read -r LABEL
  LABEL="${LABEL:-$(hostname -s)-admin}"
  echo ""
  echo ">>> TOUCH YOUR FIDO2 KEY (biometric, or enter its PIN if asked) <<<"
  echo ""

  local setup_log="/tmp/dds-admin-setup-${ts}.log" rc=0
  set +e
  "${FIDO2_CLI}" admin-setup --node-url "${NODE_URL}" --label "${LABEL}" 2>&1 | tee "${setup_log}"
  rc=${PIPESTATUS[0]}
  set -e

  # Restore the previously-trusted admins either way — a failed setup
  # must not leave this node trusting nobody.
  if [[ "${restore_after}" -eq 1 ]]; then
    echo ""
    echo "--- restoring previously-trusted admins ---"
    python3 - "${DDS_TOML}" "${saved_roots}" <<'PY'
import re, sys
p, saved = sys.argv[1], sys.argv[2]
prev = re.findall(r'"([^"]+)"', saved)
s = open(p).read()
m = re.search(r'(?m)^trusted_roots\s*=\s*\[(.*)\]\s*$', s)
cur = [x.strip().strip('"') for x in (m.group(1) or '').split(',') if x.strip()] if m else []
for u in prev:
    if u not in cur:
        cur.append(u)
s = re.sub(r'(?m)^trusted_roots\s*=.*$',
           'trusted_roots = [' + ', '.join('"%s"' % u for u in cur) + ']', s, count=1)
open(p, 'w').write(s)
print("  trusted_roots now: %s" % cur)
PY
    if ! "${DDS_CLI}" debug config "${DDS_TOML}" >"/tmp/dds-cfgchk-${ts}.out" 2>&1; then
      echo "  config INVALID after restore — reverting to the backup" >&2
      sed -n 1,12p "/tmp/dds-cfgchk-${ts}.out" >&2
      cp "${DDS_TOML}.bak-${ts}" "${DDS_TOML}"
    fi
    systemctl restart dds-node
    printf "  waiting for node..."
    for _ in $(seq 1 30); do
      api http://localhost/v1/status >/dev/null 2>&1 && { echo " ready"; break; }
      printf "."; sleep 1
    done
  fi

  if [[ "${rc}" -ne 0 ]]; then
    echo ""
    echo "admin-setup failed (exit ${rc}). Log: ${setup_log}" >&2
    [[ -f "${DDS_TOML}.bak-${ts}" ]] && echo "Config backup: ${DDS_TOML}.bak-${ts}" >&2
    return 1
  fi

  local new_urn
  new_urn="$(awk '/^  urn:/ { print $2 }' "${setup_log}" | tail -n 1)"
  echo ""
  echo "STEP 1 done — admin minted on this machine."
  echo "  admin URN: ${new_urn}"

  if [[ -z "${new_urn}" ]]; then
    echo "  (could not read the URN back from ${setup_log} — check it by hand,"
    echo "   then run 'List admin credentials stored on this box')" >&2
    return 1
  fi

  print_crossvouch_instructions "${new_urn}"
  printf "Poll until it's promoted? [Y/n]: "
  read -r RESP
  RESP="${RESP:-Y}"
  [[ "${RESP}" =~ ^[Yy] ]] && wait_for_promotion "${new_urn}"
  return 0
}

echo ""
echo "=== DDS User ==="
echo ""
echo "1) Enroll a new person (register their FIDO2 key)"
echo "2) Approve a person for session login"
echo "3) Promote a person to admin"
echo "4) Demote an admin (remove admin, keep session access)"
echo "5) Offboard a person entirely (revoke all access)"
echo "6) List enrolled users"
echo "7) List admin credentials stored on this box"
echo "8) Make THIS machine able to approve things"
echo "9) Exit"
echo ""
printf "Choice [1-9]: "
read -r CHOICE

case "${CHOICE}" in
  1)
    echo ""
    echo "This registers a brand-new person's FIDO2 key. No admin touch"
    echo "needed for this step — the person touches their OWN key once."
    echo ""
    printf "Username/label (e.g., jsmith): "
    read -r LABEL
    [[ -n "${LABEL}" ]] || { echo "Label required" >&2; exit 1; }
    printf "Display name (e.g., Jane Smith): "
    read -r DISPLAY_NAME
    [[ -n "${DISPLAY_NAME}" ]] || { echo "Display name required" >&2; exit 1; }
    "${FIDO2_CLI}" new-user --node-url "${NODE_URL}" --label "${LABEL}" --display-name "${DISPLAY_NAME}"
    echo ""
    echo "Enrolled. To let them log in, run this wizard again and choose"
    echo "'Approve a person for session login'."
    ;;
  2)
    echo ""
    echo "This requires YOUR admin FIDO2 key (touch + PIN)."
    prompt_subject_urn
    "${FIDO2_CLI}" vouch --node-url "${NODE_URL}" --subject-urn "${SUBJECT_URN}" --purpose "dds:session"
    ;;
  3)
    echo ""
    echo "This requires YOUR admin FIDO2 key (touch + PIN)."
    prompt_subject_urn
    "${FIDO2_CLI}" vouch --node-url "${NODE_URL}" --subject-urn "${SUBJECT_URN}" --purpose "dds:admin"
    echo ""
    echo "Note: this vouch grants the dds:admin capability server-side. To"
    echo "actually approve things, the new admin needs a signing key on the"
    echo "machine they'll work from — on that machine, run:"
    echo "    sudo dds-user  → 'Make THIS machine able to approve things'"
    ;;
  4)
    echo ""
    echo "This demotes a sub-admin (revokes ONLY the dds:admin vouch — they"
    echo "keep session access if they were separately approved for it)."
    echo "Requires YOUR admin FIDO2 key (touch + PIN)."
    prompt_subject_urn
    "${FIDO2_CLI}" revoke-vouch --node-url "${NODE_URL}" --subject-urn "${SUBJECT_URN}" --purpose "dds:admin"
    ;;
  5)
    echo ""
    echo "This revokes EVERY vouch you (this admin) issued for the subject"
    echo "— full offboarding. Requires YOUR admin FIDO2 key (touch + PIN)."
    prompt_subject_urn
    printf "Type OFFBOARD to confirm revoking all access for %s: " "${SUBJECT_URN}"
    read -r CONFIRM
    [[ "${CONFIRM}" == "OFFBOARD" ]] || { echo "Aborted."; exit 0; }
    "${FIDO2_CLI}" revoke-vouch --node-url "${NODE_URL}" --subject-urn "${SUBJECT_URN}"
    ;;
  6)
    list_enrolled_users
    ;;
  7)
    "${FIDO2_CLI}" list-admins
    ;;
  8)
    make_this_machine_approver
    ;;
  9)
    exit 0
    ;;
  *)
    echo "Unknown choice." >&2
    exit 1
    ;;
esac
