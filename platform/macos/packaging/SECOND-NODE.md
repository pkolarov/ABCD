# Adding a Second Node to a DDS Domain

After bootstrapping the first node (macOS) with `dds-bootstrap-domain`,
follow these steps to add a second node (macOS or Windows).

## On the first (macOS) node

### 1. Get this node's multiaddr

```bash
cat "/Library/Application Support/DDS/bootstrap.env"
# Note the MULTIADDR line, e.g.:
# MULTIADDR=/ip4/192.168.1.10/tcp/4001/p2p/12D3KooWXXXXXX
```

### 2. Generate a node key on the second machine

**macOS:**
```bash
sudo dds-node gen-node-key --data-dir "/Library/Application Support/DDS/node-data"
# Note the peer_id output
```

**Windows (in admin cmd):**
```cmd
dds-node.exe gen-node-key --data-dir "C:\ProgramData\DDS\node-data"
REM Note the peer_id output
```

### 3. Admit the second node (on the first macOS node)

```bash
sudo dds-admit-node
# Enter the second node's Peer ID when prompted
# Enter domain key passphrase
```

This creates an admission certificate file.

### 4. Copy files to the second machine

Copy these from the first node to the second:
- `domain.toml` — from `/Library/Application Support/DDS/node-data/`
- `admission-<peer>.cbor` — from `/Library/Application Support/DDS/`

## On the second node

### macOS

```bash
# Copy files
sudo cp domain.toml "/Library/Application Support/DDS/node-data/"
sudo cp admission-XXXX.cbor "/Library/Application Support/DDS/node-data/admission.cbor"

# Edit dds.toml — set bootstrap_peers to point to the first node
sudo nano "/Library/Application Support/DDS/dds.toml"
# Set: bootstrap_peers = ["/ip4/192.168.1.10/tcp/4001/p2p/12D3KooWXXXXXX"]

# Start node
sudo launchctl enable system/com.dds.node
sudo launchctl bootstrap system /Library/LaunchDaemons/com.dds.node.plist
```

### Windows

1. **Place files:**
   ```
   C:\ProgramData\DDS\node-data\domain.toml
   C:\ProgramData\DDS\node-data\admission.cbor
   ```

2. **Edit node config** (`C:\ProgramData\DDS\dds.toml`):
   ```toml
   data_dir = "C:\\ProgramData\\DDS\\node-data"
   org_hash = "acme"  # same as first node
   trusted_roots = []  # will be populated via gossip

   [network]
   listen_addr = "/ip4/0.0.0.0/tcp/4001"
   bootstrap_peers = ["/ip4/192.168.1.10/tcp/4001/p2p/12D3KooWXXXXXX"]
   mdns_enabled = true
   api_addr = "127.0.0.1:5551"

   [domain]
   name = "acme.corp"
   id = "dds-dom:XXXX"
   pubkey = "XXXX"
   admission_path = "C:\\ProgramData\\DDS\\node-data\\admission.cbor"
   ```

3. **Start the DdsNode service:**
   ```cmd
   net start DdsNode
   ```

4. **Enroll this Windows machine:**
   ```cmd
   curl -X POST http://127.0.0.1:5551/v1/enroll/device ^
     -H "Content-Type: application/json" ^
     -d "{\"label\":\"win11-pc\",\"device_id\":\"DDS-WIN-PC\",\"hostname\":\"WIN11-PC\",\"os\":\"Windows 11\",\"os_version\":\"24H2\",\"tags\":[\"windows\"]}"
   ```

## Verify

### Check gossip sync (both nodes)

```bash
curl http://127.0.0.1:5551/v1/status
# connected_peers should be >= 1
```

### Check enrolled users synced

```bash
curl "http://127.0.0.1:5551/v1/enrolled-users?device_urn="
# Should show the admin user enrolled on the first node
```

On Windows, this may take up to 60 seconds (anti-entropy sync interval).

### Windows logon screen

After the admin user's `UserAuthAttestation` syncs via gossip to the
Windows node, the DDS Credential Provider will enumerate them on the
logon screen. The admin can then authenticate with their FIDO2 key.

The flow:
1. User clicks DDS tile → CP sends DDS_START_AUTH via IPC
2. Auth Bridge calls Windows WebAuthn API → user touches FIDO2 key
3. Auth Bridge POSTs assertion to dds-node `/v1/session/assert`
4. dds-node verifies against trust graph → returns session token
5. Auth Bridge decrypts Windows password from vault → LSA logon
