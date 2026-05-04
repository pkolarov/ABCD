# Alpine UTM L-1 Smoke

This runbook validates the current Linux L-1 target on an Alpine VM in UTM:

- `dds-node` starts under OpenRC
- node identity persists across restart
- the local API socket appears at `/var/lib/dds/dds.sock`
- the VM can act as a DDS anchor peer
- the no-op Linux policy agent can run under OpenRC

It does not validate host policy enforcement.

## VM Setup

Install Alpine with OpenSSH enabled, then install baseline tools:

```sh
apk update
apk add ca-certificates curl jq openssh bash tar
update-ca-certificates
```

For a build-inside-VM smoke, add the compiler toolchain:

```sh
apk add build-base rust cargo git pkgconf openssl-dev
```

If building artifacts on the host and copying them in, use `uname -m` in the VM
to pick the target:

- `aarch64` -> `linux-musl-arm64`
- `x86_64` -> `linux-musl-x64`

## Publish Artifacts

From the repository root on a machine with the .NET SDK:

```sh
dotnet publish platform/linux/DdsPolicyAgent/DdsPolicyAgent.Linux.csproj \
  -c Release \
  -r linux-musl-arm64 \
  --self-contained true \
  /p:UseAppHost=true \
  -o ./artifacts/linux-musl-arm64/DdsPolicyAgent.Linux
```

Use `linux-musl-x64` instead when the VM is `x86_64`.

For `dds-node`, either build inside Alpine:

```sh
cargo build -p dds-node -p dds-cli --release
```

or cross-compile/copy a Linux musl build from the host.

## Install Files

On the Alpine VM:

```sh
install -d -m 0755 /etc/dds
install -d -m 0700 /var/lib/dds/node
install -d -m 0700 /var/lib/dds/policy-agent
install -d -m 0750 /var/log/dds
install -d -m 0755 /usr/local/lib/dds/DdsPolicyAgent.Linux
```

Install the node binary:

```sh
install -m 0755 target/release/dds-node /usr/local/bin/dds-node
install -m 0755 target/release/dds-cli /usr/local/bin/dds-cli
```

Install the policy agent payload:

```sh
cp -R artifacts/linux-musl-arm64/DdsPolicyAgent.Linux/* \
  /usr/local/lib/dds/DdsPolicyAgent.Linux/
chmod 0755 /usr/local/lib/dds/DdsPolicyAgent.Linux/DdsPolicyAgent.Linux
```

Install OpenRC scripts:

```sh
install -m 0755 platform/linux/packaging/openrc/dds-node /etc/init.d/dds-node
install -m 0755 platform/linux/packaging/openrc/dds-policy-agent /etc/init.d/dds-policy-agent
install -d -m 0755 /etc/conf.d
install -m 0644 platform/linux/packaging/openrc/conf.d/dds-node /etc/conf.d/dds-node
install -m 0644 platform/linux/packaging/openrc/conf.d/dds-policy-agent /etc/conf.d/dds-policy-agent
```

If using the self-contained policy-agent publish, edit
`/etc/conf.d/dds-policy-agent`:

```sh
DDS_POLICY_AGENT_COMMAND="/usr/local/lib/dds/DdsPolicyAgent.Linux/DdsPolicyAgent.Linux"
DDS_POLICY_AGENT_ARGS=""
```

## Configure Anchor Node

Copy the anchor template:

```sh
cp platform/linux/packaging/config/node.anchor.toml /var/lib/dds/dds.toml
```

Replace the `__...__` placeholders with real bootstrap/domain values and place
the admission certificate at:

```text
/var/lib/dds/node/admission.cbor
```

The L-1 identity check depends on `/var/lib/dds/node/node_key.bin` surviving
restart. Do not delete it during repair; deleting it creates a different peer.

## Start Services

```sh
rc-update add dds-node default
rc-service dds-node start
rc-service dds-node status
```

Check the socket and logs:

```sh
ls -l /var/lib/dds/dds.sock
tail -n 100 /var/log/dds/dds-node.log
tail -n 100 /var/log/dds/dds-node.err
```

Confirm readiness through the Unix socket:

```sh
curl --unix-socket /var/lib/dds/dds.sock http://localhost/readyz
curl --unix-socket /var/lib/dds/dds.sock http://localhost/v1/status | jq
curl --unix-socket /var/lib/dds/dds.sock http://localhost/v1/node/info | jq
```

Record the peer ID and advertised `/ip4/.../tcp/4001/p2p/...` multiaddr from the
status output or logs. Use that as `bootstrap_peers` for a second node.

## Start No-Op Policy Agent

Write `/etc/dds/policy-agent.json` from
`platform/linux/packaging/config/policy-agent.json`, replacing:

- `__DEVICE_URN__`
- `__NODE_PUBKEY_B64__` from `/v1/node/info`

Then start the agent:

```sh
rc-update add dds-policy-agent default
rc-service dds-policy-agent start
rc-service dds-policy-agent status
tail -n 100 /var/log/dds/dds-policy-agent.log
```

Expected L-1 result:

- no host mutation
- `/var/lib/dds/policy-agent/applied-state.json` is created after a policy is
  available
- logs show poll attempts against `unix:/var/lib/dds/dds.sock`

## Restart Identity Check

Capture the peer ID:

```sh
curl --unix-socket /var/lib/dds/dds.sock http://localhost/v1/status | jq '.peer_id'
```

Restart and compare:

```sh
rc-service dds-node restart
curl --unix-socket /var/lib/dds/dds.sock http://localhost/v1/status | jq '.peer_id'
```

The value must remain unchanged.
