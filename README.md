# dfnet 🌐🔒
> **Modern Forensic Network Operations, Stealth MAC Cloaking, Share Ingestion & Raw Stream Receiver TUI for Digital Forensics and Incident Response.**

`dfnet` is a high-performance terminal utility designed for DFIR examiners, incident responders, and forensic field investigators. It provides fast network interface management, instantaneous MAC address randomization/cloaking, local subnet ARP reconnaissance (locating NAS/SAN devices), remote SMB/NFS share mounting, and raw network disk stream ingestion with a **Ratatui TUI** dashboard.

---

## ⚡ Key Features

- **Stealth MAC Cloaking**:
  - One-key MAC address randomization (`macchanger -r`) to prevent logging real hardware MACs on suspect networks.
  - One-key restoration of permanent factory hardware MAC (`macchanger -p`).
- **Network Discovery & Reconnaissance**:
  - Built-in local ARP scanner to enumerate connected devices, identify vendor OUIs, and flag common forensic targets (`445` SMB, `2049` NFS, `22` SSH, `3260` iSCSI).
- **Network Ingestion Helper**:
  - Mounts on-premise Windows/Samba (`mount.cifs`) and NFS (`mount.nfs`) shares into `/media/target/` with read-only forensic flags.
- **Live Raw Disk Stream Receiver**:
  - Listens on TCP port (default `9999`) to receive piped raw disk streams (`dd | nc`) directly to attached ingestion media with `pv` rate monitoring.

---

## ⌨️ TUI Keyboard Shortcuts

- `Tab`: Switch between **Interfaces**, **Network Discovery**, and **Stream Receiver**
- `↑` / `↓` / `k` / `j`: Select network interface
- `m`: **Randomize MAC** address on selected interface
- `p`: **Restore permanent MAC** address
- `n`: Launch **`nmtui`** (NetworkManager TUI for static IP / VLAN / Wi-Fi)
- `s`: Run **local subnet ARP scan**
- `r`: Refresh network status
- `q` / `Esc`: Quit

---

## 📦 CLI Usage

```bash
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
```

---

## 📜 License
Distributed under the **MIT** or **Apache-2.0** License.
