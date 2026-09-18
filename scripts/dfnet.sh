#!/usr/bin/env bash
# ==============================================================================
# df-net: Forensic Network Operations & Triage Helper for df-nix
# Handles MAC address faking, network discovery, share ingestion, and live streams
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

cmd_mac_fake() {
    local iface="${1:-}"
    if [[ -z "$iface" ]]; then
        echo -e "${YELLOW}[*] Available network interfaces:${NC}"
        ip -br link show
        read -rp "Enter interface to spoof (e.g. eth0, wlan0): " iface
    fi

    echo -e "${CYAN}[*] Spoofing MAC address on $iface...${NC}"
    ip link set dev "$iface" down
    macchanger -r "$iface"
    ip link set dev "$iface" up
    echo -e "${GREEN}[✓] New MAC assigned to $iface.${NC}"
}

cmd_mac_restore() {
    local iface="${1:-}"
    if [[ -z "$iface" ]]; then
        ip -br link show
        read -rp "Enter interface to restore permanent MAC: " iface
    fi
    ip link set dev "$iface" down
    macchanger -p "$iface"
    ip link set dev "$iface" up
    echo -e "${GREEN}[✓] Permanent hardware MAC restored on $iface.${NC}"
}

cmd_scan() {
    local iface="${1:-}"
    if [[ -z "$iface" ]]; then
        iface=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1 || true)
    fi

    if [[ -z "$iface" ]]; then
        echo -e "${RED}[!] No active default network interface found. Connect first with 'df-net ip' (nmtui).${NC}" >&2
        exit 1
    fi

    echo -e "${CYAN}${BOLD}[*] Scanning local network on $iface via ARP...${NC}"
    arp-scan --interface="$iface" --localnet || true
}

cmd_mount_smb() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: df-net smb <//server/share> <local_folder_name> [username]"
        echo "Example: df-net smb //192.168.1.50/evidence case01 examiner"
        exit 1
    fi

    local remote="$1"
    local folder="$2"
    local user="${3:-guest}"
    local mountpoint="/media/target/smb_${folder}"

    mkdir -p "$mountpoint"
    echo -e "${CYAN}[*] Mounting SMB share $remote -> $mountpoint (read-only safe copy)...${NC}"
    mount.cifs "$remote" "$mountpoint" -o "username=$user,ro,noatime"
    echo -e "${GREEN}[✓] Successfully mounted SMB share at $mountpoint.${NC}"
}

cmd_mount_nfs() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: df-net nfs <server:/export> <local_folder_name>"
        echo "Example: df-net nfs 192.168.1.50:/volume1/nas case01"
        exit 1
    fi

    local remote="$1"
    local folder="$2"
    local mountpoint="/media/target/nfs_${folder}"

    mkdir -p "$mountpoint"
    echo -e "${CYAN}[*] Mounting NFS export $remote -> $mountpoint...${NC}"
    mount -t nfs -o ro,nolock,noatime "$remote" "$mountpoint"
    echo -e "${GREEN}[✓] Successfully mounted NFS export at $mountpoint.${NC}"
}

cmd_receive_raw_disk() {
    local port="${1:-9999}"
    local outfile="${2:-/media/target/network_stream.raw}"

    echo -e "${YELLOW}${BOLD}[*] Listening on TCP port $port for raw incoming disk stream...${NC}"
    echo -e "${CYAN}    Command to run on remote evidence machine:${NC}"
    echo -e "    ${BOLD}sudo dd if=/dev/nvme0n1 bs=64K status=progress | nc $(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}') $port${NC}"
    echo "----------------------------------------------------------------------------------"
    nc -l -p "$port" | pv > "$outfile"
    echo -e "${GREEN}[✓] Network acquisition complete. Saved to $outfile.${NC}"
}

usage() {
    echo -e "${BOLD}df-net${NC} — Forensic Network Operations Helper"
    echo "Usage:"
    echo "  df-net ip                    Launch NetworkManager TUI (nmtui) to configure static IP / Wi-Fi"
    echo "  df-net mac [iface]           Spoof/randomize MAC address for stealth connection"
    echo "  df-net mac-restore [iface]   Restore original factory hardware MAC address"
    echo "  df-net scan [iface]          Quick ARP network discovery of local servers/NAS"
    echo "  df-net smb <//srv/sh> <dir>  Mount an on-premise Windows/Samba share to /media/target"
    echo "  df-net nfs <srv:/exp> <dir>  Mount an on-premise NFS export to /media/target"
    echo "  df-net receive [port] [out]  Listen on network port to receive raw disk stream over netcat"
    exit 1
}

case "${1:-}" in
    ip)
        exec nmtui
        ;;
    mac)
        cmd_mac_fake "${2:-}"
        ;;
    mac-restore)
        cmd_mac_restore "${2:-}"
        ;;
    scan)
        cmd_scan "${2:-}"
        ;;
    smb)
        shift
        cmd_mount_smb "$@"
        ;;
    nfs)
        shift
        cmd_mount_nfs "$@"
        ;;
    receive)
        shift
        cmd_receive_raw_disk "$@"
        ;;
    *)
        usage
        ;;
esac
