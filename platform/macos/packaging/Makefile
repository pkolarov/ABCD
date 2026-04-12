#!/usr/bin/make -f
# DDS Platform for macOS — Build & Package
#
# Usage:
#   make pkg                 # Build everything and produce .pkg
#   make rust-binaries       # Build dds-node + dds CLI
#   make dotnet-agent        # Publish self-contained DdsPolicyAgent
#   make clean               # Remove build artifacts
#
# Variables:
#   ARCH          — Target architecture (default: current machine)
#   VERSION       — Package version (default: 0.1.0)
#   BUILD_MODE    — release or debug (default: release)
#   SIGNING_IDENTITY — Apple Developer ID for productsign (optional)

SHELL := /bin/zsh
.DEFAULT_GOAL := pkg

# ---- Configuration ----
ARCH          ?= $(shell uname -m)
VERSION       ?= 0.1.0
BUILD_MODE    ?= release
REPO_ROOT     := $(shell cd ../../.. && pwd)
PKG_DIR       := $(CURDIR)
BUILD_DIR     := $(CURDIR)/build
PAYLOAD_DIR   := $(BUILD_DIR)/pkg-root
SCRIPTS_DIR   := $(CURDIR)/scripts
AGENT_PROJ    := $(REPO_ROOT)/platform/macos/DdsPolicyAgent/DdsPolicyAgent.MacOS.csproj

# Map architecture names
ifeq ($(ARCH),arm64)
  RUST_TARGET := aarch64-apple-darwin
  DOTNET_RID  := osx-arm64
else ifeq ($(ARCH),aarch64)
  RUST_TARGET := aarch64-apple-darwin
  DOTNET_RID  := osx-arm64
else
  RUST_TARGET := x86_64-apple-darwin
  DOTNET_RID  := osx-x64
endif

CARGO_FLAGS := --$(BUILD_MODE)
ifeq ($(BUILD_MODE),debug)
  CARGO_FLAGS :=
  CARGO_OUT   := $(REPO_ROOT)/target/debug
else
  CARGO_OUT   := $(REPO_ROOT)/target/release
endif

PKG_NAME := DDS-Platform-macOS-$(VERSION)-$(ARCH).pkg

# ---- Targets ----

.PHONY: pkg rust-binaries dotnet-agent pkg-payload component-pkg product-pkg sign clean

pkg: product-pkg
	@echo ""
	@echo "=== Package built: $(BUILD_DIR)/$(PKG_NAME) ==="
	@echo ""

rust-binaries:
	@echo "[1/4] Building Rust binaries ($(BUILD_MODE), $(RUST_TARGET))..."
	cd "$(REPO_ROOT)" && cargo build $(CARGO_FLAGS) -p dds-node -p dds-cli -p dds-fido2-test
	@echo "  dds-node: $(CARGO_OUT)/dds-node"
	@echo "  dds:      $(CARGO_OUT)/dds"

dotnet-agent:
	@echo "[2/4] Publishing .NET agent (self-contained, $(DOTNET_RID))..."
	dotnet publish "$(AGENT_PROJ)" \
		-c Release \
		-r "$(DOTNET_RID)" \
		--self-contained true \
		-p:PublishSingleFile=true \
		-p:PublishTrimmed=false \
		-p:UseAppHost=true \
		-o "$(BUILD_DIR)/agent"
	@echo "  Agent binary: $(BUILD_DIR)/agent/DdsPolicyAgent.MacOS"

pkg-payload: rust-binaries dotnet-agent
	@echo "[3/4] Assembling package payload..."
	rm -rf "$(PAYLOAD_DIR)"
	mkdir -p "$(PAYLOAD_DIR)/usr/local/bin"
	mkdir -p "$(PAYLOAD_DIR)/usr/local/lib/dds"
	mkdir -p "$(PAYLOAD_DIR)/Library/LaunchDaemons"
	mkdir -p "$(PAYLOAD_DIR)/Library/Application Support/DDS"

	# Rust binaries
	cp "$(CARGO_OUT)/dds-node" "$(PAYLOAD_DIR)/usr/local/bin/"
	cp "$(CARGO_OUT)/dds" "$(PAYLOAD_DIR)/usr/local/bin/"
	cp "$(CARGO_OUT)/dds-fido2-test" "$(PAYLOAD_DIR)/usr/local/bin/"

	# Bootstrap + admin scripts
	cp "$(PKG_DIR)/dds-bootstrap-domain.sh" "$(PAYLOAD_DIR)/usr/local/bin/dds-bootstrap-domain"
	cp "$(PKG_DIR)/dds-enroll-admin.sh" "$(PAYLOAD_DIR)/usr/local/bin/dds-enroll-admin"
	cp "$(PKG_DIR)/dds-admit-node.sh" "$(PAYLOAD_DIR)/usr/local/bin/dds-admit-node"
	chmod +x "$(PAYLOAD_DIR)/usr/local/bin/dds-bootstrap-domain"
	chmod +x "$(PAYLOAD_DIR)/usr/local/bin/dds-enroll-admin"
	chmod +x "$(PAYLOAD_DIR)/usr/local/bin/dds-admit-node"

	# .NET agent (self-contained single binary)
	cp "$(BUILD_DIR)/agent/DdsPolicyAgent.MacOS" "$(PAYLOAD_DIR)/usr/local/lib/dds/"
	cp "$(PKG_DIR)/appsettings.production.json" "$(PAYLOAD_DIR)/usr/local/lib/dds/appsettings.json"

	# LaunchDaemons (disabled by default)
	cp "$(PKG_DIR)/com.dds.node.plist" "$(PAYLOAD_DIR)/Library/LaunchDaemons/"
	cp "$(PKG_DIR)/com.dds.policyagent.plist" "$(PAYLOAD_DIR)/Library/LaunchDaemons/"

	# Config template
	cp "$(PKG_DIR)/dds.toml.template" "$(PAYLOAD_DIR)/Library/Application Support/DDS/"

	@echo "  Payload assembled at $(PAYLOAD_DIR)"

component-pkg: pkg-payload
	@echo "[4/4] Building component .pkg..."
	mkdir -p "$(BUILD_DIR)"
	pkgbuild \
		--root "$(PAYLOAD_DIR)" \
		--identifier "com.dds.platform" \
		--version "$(VERSION)" \
		--scripts "$(SCRIPTS_DIR)" \
		--install-location "/" \
		"$(BUILD_DIR)/dds-platform-component.pkg"

product-pkg: component-pkg
	productbuild \
		--distribution "$(PKG_DIR)/distribution.xml" \
		--package-path "$(BUILD_DIR)" \
		--version "$(VERSION)" \
		"$(BUILD_DIR)/$(PKG_NAME)"

sign: product-pkg
ifdef SIGNING_IDENTITY
	productsign \
		--sign "$(SIGNING_IDENTITY)" \
		"$(BUILD_DIR)/$(PKG_NAME)" \
		"$(BUILD_DIR)/$(PKG_NAME:.pkg=-signed.pkg)"
	mv "$(BUILD_DIR)/$(PKG_NAME:.pkg=-signed.pkg)" "$(BUILD_DIR)/$(PKG_NAME)"
	@echo "  Signed: $(BUILD_DIR)/$(PKG_NAME)"
else
	@echo "  SIGNING_IDENTITY not set — skipping signature"
endif

clean:
	rm -rf "$(BUILD_DIR)"
	@echo "  Cleaned build directory"
