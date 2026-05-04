#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Build a Debian package for the DDS Linux L-1 runtime.

Required:
  --node PATH        Path to built dds-node binary
  --cli PATH         Path to built dds-cli binary
  --agent-dir PATH   Path to published DdsPolicyAgent.Linux directory

Optional:
  --version VERSION  Package version (default: 0.1.0)
  --arch ARCH        Debian architecture, e.g. arm64 or amd64
                    (default: dpkg --print-architecture)
  --out DIR          Output directory (default: platform/linux/packaging/debian/dist)
  --framework-dependent
                    Package a framework-dependent .NET agent and add a
                    dotnet-runtime-9.0 dependency. Default assumes a
                    self-contained agent publish.

Example:
  dotnet publish platform/linux/DdsPolicyAgent/DdsPolicyAgent.Linux.csproj \
    -c Release -r linux-arm64 --self-contained true /p:UseAppHost=true \
    -o artifacts/debian-arm64/DdsPolicyAgent.Linux

  platform/linux/packaging/debian/build-deb.sh \
    --arch arm64 \
    --node target/release/dds-node \
    --cli target/release/dds-cli \
    --agent-dir artifacts/debian-arm64/DdsPolicyAgent.Linux
USAGE
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../../../.." && pwd)"

version="0.1.0"
arch=""
out_dir="$script_dir/dist"
node_bin=""
cli_bin=""
agent_dir=""
framework_dependent=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:?missing --version value}"
      shift 2
      ;;
    --arch)
      arch="${2:?missing --arch value}"
      shift 2
      ;;
    --out)
      out_dir="${2:?missing --out value}"
      shift 2
      ;;
    --node)
      node_bin="${2:?missing --node value}"
      shift 2
      ;;
    --cli)
      cli_bin="${2:?missing --cli value}"
      shift 2
      ;;
    --agent-dir)
      agent_dir="${2:?missing --agent-dir value}"
      shift 2
      ;;
    --framework-dependent)
      framework_dependent=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$arch" ]]; then
  arch="$(dpkg --print-architecture)"
fi

if [[ -z "$node_bin" || -z "$cli_bin" || -z "$agent_dir" ]]; then
  usage >&2
  exit 2
fi

node_bin="$(cd "$(dirname "$node_bin")" && pwd)/$(basename "$node_bin")"
cli_bin="$(cd "$(dirname "$cli_bin")" && pwd)/$(basename "$cli_bin")"
agent_dir="$(cd "$agent_dir" && pwd)"
out_dir="$(mkdir -p "$out_dir" && cd "$out_dir" && pwd)"

[[ -x "$node_bin" ]] || { echo "dds-node is missing or not executable: $node_bin" >&2; exit 1; }
[[ -x "$cli_bin" ]] || { echo "dds-cli is missing or not executable: $cli_bin" >&2; exit 1; }
[[ -d "$agent_dir" ]] || { echo "agent directory is missing: $agent_dir" >&2; exit 1; }

pkg="dds-linux"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
root="$work/${pkg}_${version}_${arch}"
debian="$root/DEBIAN"

install -d -m 0755 "$debian"
install -d -m 0755 "$root/usr/bin"
install -d -m 0755 "$root/usr/local/sbin"
install -d -m 0755 "$root/usr/local/lib/dds/DdsPolicyAgent.Linux"
install -d -m 0755 "$root/lib/systemd/system"
install -d -m 0755 "$root/etc/dds"
install -d -m 0755 "$root/usr/share/doc/dds-linux/examples"

install -m 0755 "$node_bin" "$root/usr/bin/dds-node"
install -m 0755 "$cli_bin" "$root/usr/bin/dds-cli"
install -m 0755 "$repo_root/platform/linux/packaging/scripts/dds-tpm-seal.sh" \
  "$root/usr/local/sbin/dds-tpm-seal"
install -m 0755 "$repo_root/platform/linux/packaging/scripts/dds-tpm-unseal.sh" \
  "$root/usr/local/sbin/dds-tpm-unseal"
cp -R "$agent_dir"/. "$root/usr/local/lib/dds/DdsPolicyAgent.Linux/"
find "$root/usr/local/lib/dds/DdsPolicyAgent.Linux" -type d -exec chmod 0755 {} +
find "$root/usr/local/lib/dds/DdsPolicyAgent.Linux" -type f -exec chmod 0644 {} +
if [[ -f "$root/usr/local/lib/dds/DdsPolicyAgent.Linux/DdsPolicyAgent.Linux" ]]; then
  chmod 0755 "$root/usr/local/lib/dds/DdsPolicyAgent.Linux/DdsPolicyAgent.Linux"
fi

install -m 0644 "$repo_root/platform/linux/packaging/systemd/dds-node.service" \
  "$root/lib/systemd/system/dds-node.service"
install -m 0644 "$repo_root/platform/linux/packaging/systemd/dds-policy-agent.service" \
  "$root/lib/systemd/system/dds-policy-agent.service"
sed -i 's#ExecStart=/usr/local/bin/dds-node run /var/lib/dds/dds.toml#ExecStart=/usr/bin/dds-node run /var/lib/dds/dds.toml#' \
  "$root/lib/systemd/system/dds-node.service"
if [[ "$framework_dependent" -eq 0 ]]; then
  sed -i 's#ExecStart=/usr/bin/dotnet /usr/local/lib/dds/DdsPolicyAgent.Linux/DdsPolicyAgent.Linux.dll#ExecStart=/usr/local/lib/dds/DdsPolicyAgent.Linux/DdsPolicyAgent.Linux#' \
    "$root/lib/systemd/system/dds-policy-agent.service"
fi

install -m 0644 "$repo_root/platform/linux/packaging/config/node.anchor.toml" \
  "$root/usr/share/doc/dds-linux/examples/node.anchor.toml"
install -m 0644 "$repo_root/platform/linux/packaging/config/node.member.toml" \
  "$root/usr/share/doc/dds-linux/examples/node.member.toml"
install -m 0644 "$repo_root/platform/linux/packaging/config/policy-agent.json" \
  "$root/usr/share/doc/dds-linux/examples/policy-agent.json"
install -m 0644 "$repo_root/platform/linux/packaging/debian/README.Debian" \
  "$root/usr/share/doc/dds-linux/README.Debian"

depends="systemd, ca-certificates"
if [[ "$framework_dependent" -eq 1 ]]; then
  depends="$depends, dotnet-runtime-9.0"
fi

installed_size="$(du -ks "$root" | awk '{print $1}')"
cat > "$debian/control" <<CONTROL
Package: dds-linux
Version: $version
Section: admin
Priority: optional
Architecture: $arch
Maintainer: DDS Maintainers <maintainers@example.invalid>
Depends: $depends
Installed-Size: $installed_size
Description: DDS Linux node and no-op policy agent
 L-1 Linux runtime package for DDS. Installs dds-node, dds-cli, the
 no-op Linux policy agent, systemd units, and example configuration.
 Services are not enabled or started automatically because domain
 bootstrap values and admission certificates must be provisioned first.
CONTROL

cat > "$debian/postinst" <<'POSTINST'
#!/bin/sh
set -e

install -d -m 0755 -o root -g root /etc/dds
install -d -m 0700 -o root -g root /var/lib/dds/node
install -d -m 0700 -o root -g root /var/lib/dds/policy-agent
install -d -m 0750 -o root -g root /var/log/dds

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

cat <<'NOTE'
dds-linux installed.

Before starting services:
  1. Copy /usr/share/doc/dds-linux/examples/node.anchor.toml or node.member.toml
     to /var/lib/dds/dds.toml and replace placeholders.
  2. Place the admission certificate at /var/lib/dds/node/admission.cbor.
  3. Copy /usr/share/doc/dds-linux/examples/policy-agent.json to
     /etc/dds/policy-agent.json and replace placeholders.
  4. Start with: systemctl enable --now dds-node
NOTE

exit 0
POSTINST

cat > "$debian/prerm" <<'PRERM'
#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop dds-policy-agent.service >/dev/null 2>&1 || true
    systemctl stop dds-node.service >/dev/null 2>&1 || true
  fi
fi

exit 0
PRERM

cat > "$debian/postrm" <<'POSTRM'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

if [ "$1" = "purge" ]; then
  rm -rf /var/lib/dds/policy-agent
  # Preserve /var/lib/dds/node by default because it contains node identity.
  # Operators who intentionally replace the node can remove it manually.
fi

exit 0
POSTRM

chmod 0755 "$debian/postinst" "$debian/prerm" "$debian/postrm"

dpkg-deb --build --root-owner-group "$root" "$out_dir/${pkg}_${version}_${arch}.deb"
echo "$out_dir/${pkg}_${version}_${arch}.deb"
