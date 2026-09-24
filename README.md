# dfnet

A Linux terminal interface and CLI for network triage: interface and MAC management,
local ARP discovery, read-only SMB/NFS mounts, TCP image reception, and Wi-Fi hotspots.
It uses NetworkManager and the system networking tools. Network operations generally
require root; receiving into a writable directory on an unprivileged port does not.

## Acquisition

The receiver uses buffered Rust I/O and computes SHA-256 as data is written. It
accepts one TCP connection, refuses existing images or sidecars (including symlinks),
and creates files with owner-only permissions. The output directory must exist.

```bash
mkdir -p /media/target/case01
dfnet receive 9999 /media/target/case01/disk.raw --bind 10.42.0.1 \
  --expected-bytes 1000000000 --expected-sha256 <64-hex-digit-source-hash>

# Sender, with OpenBSD netcat; select the actual source device first.
sudo dd if=/dev/nvme0n1 bs=1M status=progress | nc -N 10.42.0.1 9999
```

A completed reception produces `disk.raw`, `disk.raw.sha256`, and `disk.raw.json`.
The checksum file can be checked from the image directory with
`sha256sum -c disk.raw.sha256`. The JSON record includes byte count, SHA-256,
peer address, timestamps, expected values, and status:

- `verified`: reception completed and the expected source hash matched.
- `received_unverified`: reception completed without a supplied source hash.
  TCP EOF alone cannot establish that the entire source image arrived.
- `incomplete`: reception failed, the stream was empty, size/hash validation failed,
  or the process was interrupted before finalization. Keep partial files for review;
  use a new destination for another attempt.

`--expected-bytes` rejects short or oversized streams. `--timeout` sets the sender
idle timeout in seconds (default 60); waiting for the first connection is indefinite.
Progress reports include bytes written and average throughput. The receiver no longer
requires `nc` or `pv` locally. Raw TCP has no sender authentication or encryption;
use a trusted acquisition network or an authenticated transport/tunnel. A hash
record does not replace source identification or an examiner's acquisition log.

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
NetworkManager manages forwarding for shared hotspot profiles.

Rules are tagged with `dfnet:<interface>`. Cleanup removes only these owned rules;
it never flushes unrelated rules or resets global forwarding/reverse-path settings.
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
- Receiver: `l` receives to `/media/target/network_stream.raw` on port 9999. Use the
  CLI for a custom destination, bind address, expected size, or expected hash.
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
```

Runtime dependencies: `iproute2`, NetworkManager (including its hotspot DHCP/DNS
support), `iptables`/`ip6tables`, `macchanger`, `arp-scan`, `cifs-utils`, and `nfs-utils`.
The Nix package wraps the executable with its command dependencies; the host must
still run NetworkManager and support AP mode and both firewall families.

Tests cover real loopback TCP transfers and use mocked commands for firewall and
NetworkManager operations. They require Bash and permission to bind loopback sockets;
they do not modify the host network. Live AP/driver and firewall interoperability
still need testing on a dedicated host or VM.

Dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
