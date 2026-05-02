#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "run as root, e.g. sudo $0" >&2
  exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential \
  ca-certificates \
  cargo \
  curl \
  dpkg-dev \
  git \
  jq \
  libssl-dev \
  pkg-config \
  rustc

cat <<'NOTE'
Ubuntu L-1 build prerequisites installed.

You still need the .NET SDK on the build machine to publish
DdsPolicyAgent.Linux. The resulting package uses a self-contained agent by
default, so target machines do not need the .NET runtime unless you build with
--framework-dependent.
NOTE
