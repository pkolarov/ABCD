# Ubuntu L-1 Package Smoke

This runbook prepares an Ubuntu VM to build and install the Linux L-1 DDS
runtime package. It targets Ubuntu 24.04 LTS first.

The L-1 goal is:

- build `dds-node` and `dds-cli`
- publish the no-op Linux policy agent
- build a `.deb`
- install the package
- start `dds-node` with a provisioned `/var/lib/dds/dds.toml`
- confirm `/var/lib/dds/dds.sock`, `/readyz`, `/v1/status`, and peer ID stability

Policy enforcement is still out of scope.

## VM Packages

On the Ubuntu VM:

```sh
sudo platform/linux/packaging/debian/install-build-deps-ubuntu.sh
```

If the repository is not already present on the VM, install the same packages
manually, then clone or copy the repository:

```sh
sudo apt-get update
sudo apt-get install -y \
  build-essential ca-certificates cargo curl dpkg-dev git jq libssl-dev pkg-config rustc
```

Install the .NET SDK on the build machine before publishing the agent. The
runtime package defaults to a self-contained publish, so the target machine does
not need a .NET runtime.

## Choose Architecture

On the Ubuntu VM:

```sh
dpkg --print-architecture
uname -m
```

Use:

- Debian `arm64` + .NET RID `linux-arm64` for ARM64 UTM/Apple Silicon guests
- Debian `amd64` + .NET RID `linux-x64` for x86_64 guests

Set variables for the rest of the runbook:

```sh
export DDS_DEB_ARCH="$(dpkg --print-architecture)"
case "$DDS_DEB_ARCH" in
  arm64) export DDS_DOTNET_RID=linux-arm64 ;;
  amd64) export DDS_DOTNET_RID=linux-x64 ;;
  *) echo "unsupported arch: $DDS_DEB_ARCH" >&2; exit 1 ;;
esac
```

## Build Artifacts

From the repository root:

```sh
cargo build -p dds-node -p dds-cli --release

dotnet publish platform/linux/DdsPolicyAgent/DdsPolicyAgent.Linux.csproj \
  -c Release \
  -r "$DDS_DOTNET_RID" \
  --self-contained true \
  /p:UseAppHost=true \
  -o "artifacts/ubuntu-$DDS_DEB_ARCH/DdsPolicyAgent.Linux"
```

## Build Package

```sh
platform/linux/packaging/debian/build-deb.sh \
  --version 0.1.0 \
  --arch "$DDS_DEB_ARCH" \
  --node target/release/dds-node \
  --cli target/release/dds-cli \
  --agent-dir "artifacts/ubuntu-$DDS_DEB_ARCH/DdsPolicyAgent.Linux"
```

The package is written to:

```text
platform/linux/packaging/debian/dist/dds-linux_0.1.0_${DDS_DEB_ARCH}.deb
```

## Install Package

```sh
sudo apt install "./platform/linux/packaging/debian/dist/dds-linux_0.1.0_${DDS_DEB_ARCH}.deb"
```

The package installs files and creates state directories. It does not enable or
start services until the node is provisioned.

## Configure Anchor

```sh
sudo cp /usr/share/doc/dds-linux/examples/node.anchor.toml /var/lib/dds/dds.toml
sudo editor /var/lib/dds/dds.toml
sudo install -m 0600 admission.cbor /var/lib/dds/node/admission.cbor
```

Replace all `__...__` placeholders in `/var/lib/dds/dds.toml`.

## Start Node

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now dds-node.service
sudo systemctl status dds-node.service
```

Check the local API:

```sh
sudo ls -l /var/lib/dds/dds.sock
curl --unix-socket /var/lib/dds/dds.sock http://localhost/readyz
curl --unix-socket /var/lib/dds/dds.sock http://localhost/v1/status | jq
curl --unix-socket /var/lib/dds/dds.sock http://localhost/v1/node/info | jq
```

Capture the peer ID:

```sh
curl --unix-socket /var/lib/dds/dds.sock http://localhost/v1/status | jq '.peer_id'
```

Restart and confirm it stays unchanged:

```sh
sudo systemctl restart dds-node.service
curl --unix-socket /var/lib/dds/dds.sock http://localhost/v1/status | jq '.peer_id'
```

Do not delete `/var/lib/dds/node/node_key.bin` during routine repair. Removing
it creates a new peer identity.

## Start No-Op Policy Agent

```sh
sudo cp /usr/share/doc/dds-linux/examples/policy-agent.json /etc/dds/policy-agent.json
sudo editor /etc/dds/policy-agent.json
sudo systemctl enable --now dds-policy-agent.service
sudo systemctl status dds-policy-agent.service
```

Set `PinnedNodePubkeyB64` from `/v1/node/info` and `DeviceUrn` from the enrolled
device identity. The expected L-1 result is polling/reporting only; no host
state should be mutated.

Logs:

```sh
journalctl -u dds-node.service -n 100 --no-pager
journalctl -u dds-policy-agent.service -n 100 --no-pager
```
