#!/bin/sh
# DDS macOS — LaunchDaemon entrypoint wrapper.
#
# Tries to unseal DDS_NODE_PASSPHRASE from the System Keychain, then
# execs `dds-node run`. Falls through cleanly when no sealed
# passphrase is configured — node keys then stay plaintext at rest,
# relying on filesystem permissions.
#
# Invoked from the LaunchDaemon plist's ProgramArguments (replacing
# the previous direct `/usr/local/bin/dds-node run` line).

set -eu

CONFIG="${DDS_NODE_CONFIG:-/Library/Application Support/DDS/dds.toml}"

if pass="$(/usr/local/sbin/dds-keychain-unseal 2>/dev/null)" && [ -n "$pass" ]; then
    export DDS_NODE_PASSPHRASE="$pass"
fi

exec /usr/local/bin/dds-node run "$CONFIG"
