# dfnet

A Linux terminal interface and CLI for network triage: interface and MAC management,
local ARP discovery, read-only SMB/NFS mounts, TCP image reception, and Wi-Fi hotspots.
It uses NetworkManager and the system networking tools. Network operations generally
require root; receiving into a writable directory on an unprivileged port does not.

## Acquisition

### Authenticated streams from a running system (`dfnet stream`)

For a running suspect system, use `dfnet stream` with
[`dflive send`](https://github.com/tylerstyle/dflive) on the suspect side.
dfnet shows a one-time pairing code; the examiner types it into dflive. Both sides
run SPAKE2 on the code, so nobody on the network learns it or can join, and every
frame after that is encrypted and authenticated (ChaCha20-Poly1305). Lengths need
not be known in advance, and one session can carry several streams.

```bash
dfnet stream --bind 10.42.0.1 -o /media/target/case01/live \
  -C "VG 12345/26" -E live01 -e "KHK Muster"
# [*] Pairing code: 482 913 0576

# On the suspect system, from the field kit:
dflive send /dev/nvme0n1 --to 10.42.0.1:9998 --code "482 913 0576"
```

- The output directory must be new or empty and not in RAM (`--allow-tmpfs`).
- Each stream becomes `NNN-<name>.raw` and an item of a dfcore collection
  (`manifest.json`, `items.jsonl`, `footprint.jsonl`, `items.csv`, audit copy;
  `dfcollect verify` checks it) with the sender's and the receiver's SHA-256, the
  source's identity and the sender's read errors.
- A stream counts only when the sender's end record arrived and byte counts and
  hashes match. Each file is written as `*.incomplete` and renamed only then, so an
  interruption of any kind never leaves a file that looks complete; anything else is
  recorded as an error.
- Failed pairings are recorded; after three, dfnet shows a new code.
- Exit codes: 0 complete, 4 nothing arrived, 5 hashes differ, 6 incomplete,
  7 complete but the sender zero-filled unreadable sectors.

### Raw TCP streams (`dfnet receive`)

The receiver uses buffered Rust I/O and computes SHA-256 as data is written. It
accepts one TCP connection, refuses existing images or sidecars (including symlinks),
and creates files with owner-only permissions. The output directory must exist.

Every reception is checked against the exact source size and SHA-256:

- `--bind <address>` or `--interface <name>` is required. The receiver listens on that
  one address; `0.0.0.0`, `::`, broadcast and multicast addresses are refused.
- `--expected-bytes` is required (sender: `blockdev --getsize64 <device>`).
- The source hash is either given up front with `--expected-sha256`, or entered on
  stdin after the transfer with `--prompt-sha256`. The latter lets the sender hash
  while streaming, so the source is read only once; the receiver does not print its
  own hash until the sender's hash has been entered.
- `--allow-peer <address>` (repeatable) accepts only those senders. Other connections
  are closed, logged in the manifest's `rejected_peers`, and do not use up the single
  acquisition connection.

```bash
mkdir -p /media/target/case01
dfnet receive 9999 /media/target/case01/disk.raw --interface wlan0 \
  --expected-bytes 1000204886016 --allow-peer 10.42.0.23 --prompt-sha256

# Sender, with OpenBSD netcat; select the actual source device first.
sudo blockdev --getsize64 /dev/nvme0n1
sudo dd if=/dev/nvme0n1 bs=1M status=progress | tee >(sha256sum > source.sha256) \
  | nc -N 10.42.0.1 9999
# Then type the hash from source.sha256 at the receiver's prompt.
```

A completed reception produces `disk.raw`, `disk.raw.sha256`, and `disk.raw.json`.
The checksum file can be checked from the image directory with
`sha256sum -c disk.raw.sha256`. The JSON record includes byte count, SHA-256,
peer address, timestamps, expected values, and status:

- `verified`: reception completed with the expected size and the expected source hash.
- `incomplete`: reception failed, the stream was empty, size/hash validation failed,
  no hash was entered, or the process was interrupted before finalization. Keep
  partial files for review; use a new destination for another attempt.

Short or oversized streams are rejected. `--timeout` sets the sender
idle timeout in seconds (default 60); waiting for the first connection is indefinite.
Progress reports include bytes written and average throughput. The receiver no longer
requires `nc` or `pv` locally. Raw TCP has no sender authentication or encryption:
the sender allowlist is address-based and the hash check is what proves integrity, so
use a trusted acquisition network or an authenticated transport/tunnel. A hash
record does not replace source identification or an examiner's acquisition log.

### Network traffic at the scene (`dfnet pcap`)

```bash
dfnet pcap eth1 --silent -o /media/target/case01/pcap \
  -C "VG 12345/26" -E net01 -e "KHK Muster" --legal-basis "order ..." \
  -f "host 192.0.2.7" --duration 3600
```

dfnet runs dumpcap and puts the capture into a dfcore collection:

- **Files.** pcapng files of `--file-size` MiB (default 1024). Each file is
  hashed (SHA-256) as soon as dumpcap closes it. Old files are never replaced.
- **The interface as it was.** Driver, link, MAC, addresses and offload
  settings are recorded. GRO and LRO merge received packets, so the capture would
  no longer show the frames as they were on the wire; they are switched off for
  the capture and restored afterwards (`--keep-offloads` leaves them on). Every
  change and every restoration is in the footprint.
- **Silent capture.** `--silent`, for a SPAN port or a tap, stops the interface
  from sending anything: ARP off, IPv6 off. The interface must have no IPv4
  address. Both settings are restored afterwards.
- **Loss.** dumpcap's counts of packets captured and dropped (pcap, dumpcap,
  interface) and the card's own missed/FIFO/overrun counters, before and after,
  are recorded. Any loss makes the capture incomplete: exit 7.
- **Stopping.** At `--duration`, on Ctrl-C/SIGTERM, or when less than 512 MiB
  is free on the target. The collection is finished in every case.

Exit codes: 0 complete, 7 complete with packet loss, 6 dumpcap failed, 4
nothing captured. Lawful interception runs on other systems; `--legal-basis`
records the order this capture rests on.

### Audit trail

Each reception appends `receive_started` and `receive_finished` records to the
hash-chained dfnix audit log (via [`dfcore`](https://github.com/tylerstyle/dfcore),
`/run/dfnix/audit.jsonl`). The manifest's `audit_anchor` is the hash of the start
record; the finish record holds the manifest's SHA-256. Hotspot start and stop are
recorded with the IPv4 forwarding state before and after; the WPA2 passphrase is
redacted from the recorded command line.

## Wi-Fi hotspots and routing

```bash
# Default: block forwarding from/to AP clients. A password is generated if omitted.
sudo dfnet hotspot start --iface wlan0 --ssid DF-FIELD-AP

# Explicitly allow IPv4 NAT through the current default-route interface.
sudo dfnet hotspot start --iface wlan0 --uplink eth0 --ssid DF-FIELD-AP

sudo dfnet hotspot status
sudo dfnet hotspot stop

sudo dfnet route status --ap wlan0
sudo dfnet route isolate --ap wlan0
sudo dfnet route enable --ap wlan0 --uplink eth0
sudo dfnet route reset --ap wlan0
```

The hotspot profile is configured for WPA2/RSN, wireless client isolation, disabled
IPv6, and no automatic activation. Both IPv4 and IPv6 forwarding guards are installed
**before** NetworkManager activates the AP. If either firewall family cannot be
configured, the hotspot is not activated. `--isolate` explicitly selects the default
blocked-forwarding mode and conflicts with `--uplink`.

The host INPUT policy admits IPv4 DHCP, DNS, TCP port 9999, and established/related
traffic on the AP interface; other new connections are blocked. Custom receiver
ports and additional services need a deliberate firewall policy adjustment. IPv6
forwarding stays blocked in both modes. NAT is scoped to the AP's IPv4 subnet.
The selected uplink must match the current default route; dfnet does not rewrite
system routes. Standalone `route enable` requires IPv4 forwarding already enabled.

NetworkManager's shared mode switches on global `net.ipv4.ip_forward` and leaves it
on after the AP goes down. `hotspot start` therefore records the value found before
the first start in `/run/dfnet/ip_forward.json`, and `hotspot stop` (also a failed
start's rollback) sets it back to `0` if it was off before, unless another active
NetworkManager connection still uses IPv4 sharing. It also deletes a leftover
`nm-shared-<ap>` nftables table if NetworkManager did not remove it.

Rules are tagged with `dfnet:<interface>`. Cleanup removes only these owned rules;
it never flushes unrelated rules. `route reset` leaves global forwarding unchanged.
`route reset` without `--ap` removes all tagged dfnet rules. Stop the hotspot before
resetting its rules: reset removes the guards too. Rules left by older dfnet releases
have no ownership tags and require manual review rather than automatic deletion.

Status describes the configured dfnet rules, not a complete audit of every firewall
backend or policy-routing rule. This is **software forwarding control, not a physical
air gap**. The workstation remains accessible on the allowed services; DNS and other
host services can themselves contact external networks. Wireless client isolation
also depends on driver support. Verify the deployment's traffic policy before use.
The neighbor display is an ARP/neighbor cache, not an authoritative Wi-Fi association
list. Use a dedicated acquisition host when strict separation is required.

## Other commands

```bash
sudo dfnet                         # TUI
sudo dfnet ip                      # NetworkManager's nmtui
sudo dfnet mac eth0
sudo dfnet restore eth0
sudo dfnet scan eth0
sudo dfnet smb //192.168.1.50/share case01 examiner
sudo dfnet nfs 192.168.1.50:/export case01
```

MAC operations restore the interface's original up/down state and report helper
failures. Randomizing a MAC does not provide anonymity or erase prior network logs.
Discovery runs `arp-scan` on the local IPv4 segment; it does not probe storage ports
or prove that a discovered host is a NAS.

Shares mount below `/media/target/smb_<name>` or `/media/target/nfs_<name>` with
`ro,noatime,nosuid,nodev,noexec` (`nolock` additionally for NFS). Folder names reject path separators and traversal components. Read-only client access does not freeze a live server or guarantee
that the server records no access metadata. Mounting alone does not acquire or hash
files. Unmount with the system's `umount` command when finished.

## TUI

Use `1`–`4`, Tab/Shift+Tab, or the mouse to switch tabs; `r` refreshes and `q` exits.

- Interfaces: arrows or `j`/`k` select; `m` randomizes the MAC, `p` restores it, `n` opens nmtui.
- Discovery: `s` scans the default interface.
- Receiver: `l` asks for the listen interface or address, the exact source size, an
  optional sender address, the source hash (or to enter it after the transfer) and
  the destination (default `/media/target/network_stream.raw`), then receives on 9999.
- Hotspot: arrows select fields/values, Enter edits, and `H` starts/stops the AP.

Hotspot status is cached for two seconds; interface discovery uses a single JSON
query to `ip`. Quitting the TUI leaves a running hotspot active; stop it explicitly
with `dfnet hotspot stop`.

## Compatibility commands

Nix installs `dfnet-cli` and `df-net`, which translate older positional forms and
then execute the same Rust backend. There is no separate networking implementation.

```bash
sudo df-net hotspot start wlan0 DF-FIELD-AP 'a-unique-passphrase' --isolate
sudo df-net route enable wlan0 eth0
sudo df-net mac-restore eth0
```

## Build and checks

```bash
cargo build --locked
cargo test --locked

nix build .#dfnet
nix develop
nix build .#checks.x86_64-linux.pcap    # VM test: two machines, dfnet pcap
```

Runtime dependencies: `iproute2`, `dumpcap` (wireshark-cli) and `ethtool` for
`dfnet pcap`, NetworkManager (including its hotspot DHCP/DNS
support), `iptables`/`ip6tables`, `macchanger`, `arp-scan`, `cifs-utils`, and `nfs-utils`.
The Nix package wraps the executable with its command dependencies; the host must
still run NetworkManager and support AP mode and both firewall families.

Tests cover real loopback TCP transfers and use mocked commands for firewall and
NetworkManager operations. They require Bash and permission to bind loopback sockets;
they do not modify the host network. Live AP/driver and firewall interoperability
still need testing on a dedicated host or VM.

Dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
