# dfnet 🌐🔒
> **Modern Forensic Network Operations, Stealth MAC Cloaking, Share Ingestion, Wi-Fi Hotspot AP & Raw Stream Receiver TUI for Digital Forensics and Incident Response.**

`dfnet` is a high-performance terminal utility designed for DFIR examiners, incident responders, and forensic field investigators. It provides fast network interface management, instantaneous MAC address randomization/cloaking, local subnet ARP reconnaissance (locating NAS/SAN devices), remote SMB/NFS share mounting, Wi-Fi hotspot AP creation for ad-hoc field ingest, and raw network disk stream ingestion with an interactive **Ratatui TUI** dashboard.

---

## ⚡ Key Features

- **Stealth MAC Cloaking**:
  - One-key MAC address randomization (`macchanger -r`) to prevent logging real hardware MACs on suspect networks.
  - One-key restoration of permanent factory hardware MAC (`macchanger -p`).
- **Network Discovery & Reconnaissance**:
  - Built-in local ARP scanner to enumerate connected devices, identify vendor OUIs, and flag potential network storage targets.
- **Network Ingestion Helper**:
  - Mounts on-premise Windows/Samba (`mount.cifs`) and NFS (`mount.nfs`) shares into `/media/target/` with read-only forensic flags.
- **Wi-Fi Hotspot / Access Point**:
  - Launch an isolated, on-demand forensic Wi-Fi access point directly from the TUI or CLI for triage and field acquisition.
  - Interactive SSID and WPA2 password editing with real-time connected client tracking (`ip neigh`).
  - Creates a dedicated local subnet (default `10.42.0.1/24`) to ingest evidence streams directly from suspect laptops, mobile phones, or IoT devices without bridging to corporate networks.
- **Live Raw Disk Stream Receiver**:
  - Listens on TCP port (default `9999`) to receive piped raw disk streams (`dd | nc`) directly to attached ingestion media with `pv` rate monitoring and on-the-fly SHA-256 hash manifest creation.
- **Modern TUI with Mouse & Keyboard Control**:
  - High-contrast categorized tab bar with numbered badges (`[1]` to `[4]`).
  - Full mouse support: click tabs, click interface rows, click Wi-Fi configuration fields, and scroll with the mouse wheel.

---

## 📡 Wi-Fi Hotspot (Forensic Access Point)

In field investigations, connecting suspect laptops or mobile devices directly to an evidence acquisition workstation often requires an isolated, controlled wireless environment without exposing the device to production networks or the internet.

`dfnet` provides a built-in Wi-Fi Hotspot manager:
- **TUI Mode (`[4] 📡 Wi-Fi Hotspot / AP`)**:
  - Select wireless interface from detected 802.11 adapters (with sysfs fallback).
  - Edit **SSID** and **WPA2 Password** inline.
  - Press `Space` or click **`[ START WI-FI HOTSPOT ]`** to broadcast.
  - Monitor real-time client associations (IP and MAC addresses) under **Connected Evidence & Client Devices**.
- **CLI Mode**:
  ```bash
  # Start hotspot on specific adapter
  sudo dfnet hotspot start --iface wlan0 --ssid "DF-FIELD-AP" --password "Investigate2026!"

  # Inspect active hotspot and connected devices
  sudo dfnet hotspot status

  # Stop and clean up hotspot connection
  sudo dfnet hotspot stop
  ```
- **Companion CLI Script (`df-net` / `dfnet-cli`)**:
  ```bash
  sudo df-net hotspot start wlan0 DF-FIELD-AP Investigate2026!
  sudo df-net hotspot status
  sudo df-net hotspot stop
  ```

---

## 🖥️ TUI Navigation & Shortcuts

### Navigation
- **Category Tabs**: Click on tabs directly or press `1`, `2`, `3`, `4`, `Tab`, or `Shift+Tab` (`BackTab`).
- **Mouse Wheel**: Scroll on the tab bar to cycle categories, or on tables to select items.

### Tab Shortcuts
- `[1] 🌐 Interfaces & MAC Cloaking`:
  - `↑` / `↓` / `k` / `j` (or click): Select network adapter
  - `m`: **Randomize MAC** address on selected interface
  - `p`: **Restore permanent MAC** address
  - `n`: Launch **`nmtui`** (NetworkManager TUI for static IP / VLAN / Wi-Fi)
- `[2] 🔍 Subnet Discovery & ARP`:
  - `s`: Run **local subnet ARP scan**
- `[3] ⚡ Stream Receiver`:
  - `l`: Start listening for incoming raw disk stream
- `[4] 📡 Wi-Fi Hotspot / AP`:
  - `↑` / `↓`: Navigate configuration fields (Interface, SSID, Password, Action)
  - `←` / `→`: Select wireless interface
  - `Enter`: Edit SSID / Password or trigger Start/Stop Hotspot
  - `Space`: Quick toggle Start/Stop Hotspot
- **Global**:
  - `r`: Refresh interfaces and devices
  - `q` / `Esc`: Quit

---

## 📦 CLI Usage

`dfnet` can be run in interactive TUI mode or directly via subcommands:

```bash
# Launch interactive TUI
sudo dfnet

# Randomize MAC address
sudo dfnet mac eth0

# Restore permanent MAC
sudo dfnet restore eth0

# Scan local subnet
sudo dfnet scan

# Mount remote SMB share read-only
sudo dfnet smb //192.168.1.50/share target_folder examiner

# Mount remote NFS export read-only
sudo dfnet nfs 192.168.1.50:/volume1/nas target_folder

# Listen for incoming raw disk stream
dfnet receive 9999 /media/target/server_disk.raw

# Wi-Fi Hotspot Management
sudo dfnet hotspot start --iface wlan0 --ssid "DF-FIELD-AP" --password "Investigate2026!"
sudo dfnet hotspot status
sudo dfnet hotspot stop
```

---

## 🚀 Installation & Nix Usage

### Running with Nix Flakes
```bash
# Run directly from GitHub
nix run github:tylerstyle/dfnet

# Build package locally
nix build .#dfnet
```

### Developing
```bash
# Enter development shell with cargo, rustc, and tools
nix develop
```

---

## 📜 License

This project is dual-licensed under either:
* **MIT License** ([LICENSE-MIT](LICENSE-MIT))
* **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

See [LICENSE](LICENSE) for details.
