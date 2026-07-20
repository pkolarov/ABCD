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
echo "8) Exit"
echo ""
printf "Choice [1-8]: "
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
    echo "Note: the new admin still needs their OWN admin-setup-equivalent"
    echo "credential registered on any box they'll run 'dds-user'/'dds-account'"
    echo "from themselves — this vouch only grants the dds:admin capability"
    echo "server-side; it doesn't provision a local credential store entry"
    echo "on machines other than the one an admin already used."
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
    exit 0
    ;;
  *)
    echo "Unknown choice." >&2
    exit 1
    ;;
esac
