# Debian L-1 Package Smoke

This runbook validates the Debian package path for the Linux L-1 runtime.

## Build Inputs

Build Linux binaries on Debian, Ubuntu, or a compatible builder:

```sh
cargo build -p dds-node -p dds-cli --release
dotnet publish platform/linux/DdsPolicyAgent/DdsPolicyAgent.Linux.csproj \
  -c Release \
  -r linux-arm64 \
  --self-contained true \
  /p:UseAppHost=true \
  -o artifacts/debian-arm64/DdsPolicyAgent.Linux
```

Use `linux-x64` and Debian architecture `amd64` for x86_64 hosts.

## Build Package

```sh
platform/linux/packaging/debian/build-deb.sh \
  --version 0.1.0 \
  --arch arm64 \
  --node target/release/dds-node \
  --cli target/release/dds-cli \
  --agent-dir artifacts/debian-arm64/DdsPolicyAgent.Linux
```

The output lands under `platform/linux/packaging/debian/dist/`.

## Install

```sh
sudo apt install ./platform/linux/packaging/debian/dist/dds-linux_0.1.0_arm64.deb
```

The package creates state directories but does not start services. Configure the
node first:

```sh
sudo cp /usr/share/doc/dds-linux/examples/node.anchor.toml /var/lib/dds/dds.toml
sudo editor /var/lib/dds/dds.toml
sudo install -m 0600 admission.cbor /var/lib/dds/node/admission.cbor
```

Start the anchor:

```sh
sudo systemctl enable --now dds-node.service
sudo systemctl status dds-node.service
```

Check the local API:

```sh
curl --unix-socket /var/lib/dds/dds.sock http://localhost/readyz
curl --unix-socket /var/lib/dds/dds.sock http://localhost/v1/status
curl --unix-socket /var/lib/dds/dds.sock http://localhost/v1/node/info
```

Configure and start the no-op policy agent:

```sh
sudo cp /usr/share/doc/dds-linux/examples/policy-agent.json /etc/dds/policy-agent.json
sudo editor /etc/dds/policy-agent.json
sudo systemctl enable --now dds-policy-agent.service
sudo systemctl status dds-policy-agent.service
```

Restart `dds-node` and confirm the peer ID in `/v1/status` stays unchanged.
