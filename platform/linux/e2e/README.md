# Linux Anchor Smoke Runbook

This L-1 smoke proves Linux can run `dds-node` with stable identity and serve as
a network anchor. It does not validate Linux policy enforcement.

## Build

```bash
cargo build -p dds-node -p dds-cli
dotnet build platform/linux/DdsPolicyAgent/DdsPolicyAgent.Linux.csproj -c Debug
```

## Anchor

1. Install or stage `dds-node` at `/usr/local/bin/dds-node`.
2. Install `platform/linux/packaging/systemd/dds-node.service`.
3. Write `/etc/dds/node.toml` from
   `platform/linux/packaging/config/node.anchor.toml`.
4. Bootstrap the domain and place the admission certificate at
   `/var/lib/dds/node/admission.cbor`.
5. Start the node:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dds-node.service
sudo systemctl status dds-node.service
```

6. Record the node peer ID and advertised `/ip4/.../tcp/4001/p2p/...`
   multiaddr from `/v1/status` or node logs.

## Member

1. Write `/etc/dds/node.toml` from
   `platform/linux/packaging/config/node.member.toml`.
2. Replace `bootstrap_peers` with the anchor multiaddr.
3. Install the member admission certificate at
   `/var/lib/dds/node/admission.cbor`.
4. Start `dds-node.service`.

## Checks

- `GET /readyz` is ready on both nodes.
- `GET /v1/status` shows at least one connected peer.
- Restarting the anchor keeps the same peer ID.
- `/run/dds/api.sock` exists while `dds-node.service` is running.
- The Linux policy agent can fetch `/v1/linux/policies` through
  `unix:/run/dds/api.sock` and post an empty applied report.
