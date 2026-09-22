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

    mkdir -p "$(dirname "$outfile")"

    local local_ip
    local_ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' || true)
    if [[ -z "$local_ip" ]]; then
        local_ip=$(ip -br addr show 2>/dev/null | grep -v 'LOOPBACK\|DOWN' | awk '{print $3}' | cut -d/ -f1 | head -n1 || true)
    fi
    local_ip="${local_ip:-<EXAMINER_IP>}"

    echo -e "${YELLOW}${BOLD}[*] Listening on TCP port $port for raw incoming disk stream...${NC}"
    echo -e "${YELLOW}[!] NOTICE: Raw netcat streams lack encryption, authentication, and packet protection.${NC}"
    echo -e "${CYAN}    Recommended remote command (with on-the-fly source SHA-256 hash):${NC}"
    echo -e "    ${BOLD}sudo dd if=/dev/nvme0n1 bs=64K status=progress | tee >(sha256sum | awk '{print \$1}' > source.sha256) | nc $local_ip $port${NC}"
    echo ""
    echo -e "${CYAN}    Preferred secure alternative (SSH with mutual authentication & dual-ended hashes):${NC}"
    echo -e "    ${BOLD}ssh examiner@$local_ip \"tee >(sha256sum | awk '{print \$1}' > ${outfile}.sha256) | pv > $outfile\" < <(sudo dd if=/dev/nvme0n1 bs=64K status=progress | tee >(sha256sum | awk '{print \$1}' > source.sha256))${NC}"
    echo "----------------------------------------------------------------------------------"

    # Detect whether netcat supports OpenBSD or GNU flags
    if nc -h 2>&1 | grep -q -- "-p port"; then
        nc -l -p "$port" | tee >(sha256sum | awk '{print $1}' > "${outfile}.sha256") | pv > "$outfile"
    else
        nc -l "$port" | tee >(sha256sum | awk '{print $1}' > "${outfile}.sha256") | pv > "$outfile"
    fi

    local recv_hash
    recv_hash=$(cat "${outfile}.sha256" 2>/dev/null || echo "N/A")
    echo ""
    echo -e "${GREEN}${BOLD}[✓] Network acquisition complete!${NC}"
    echo -e "    Saved to:      $outfile"
    echo -e "    SHA-256 Hash:  $recv_hash"
    echo -e "    Hash Manifest: ${outfile}.sha256"
}

cmd_wifi_hotspot_status() {
    echo -e "${BOLD}[*] Wi-Fi Hotspot Status:${NC}"
    local active_con
    active_con=$(nmcli -t -f NAME,TYPE connection show --active 2>/dev/null | grep ':802-11-wireless$' | cut -d: -f1 || true)
    if [[ "$active_con" == "dfnet-hotspot" ]]; then
        local dev
        dev=$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | grep '^dfnet-hotspot:' | cut -d: -f2 || true)
        local ip
        ip=$(ip -4 addr show dev "$dev" 2>/dev/null | awk '/inet /{print $2}' || echo "10.42.0.1/24")
        echo -e "  Status:     ${GREEN}${BOLD}ACTIVE (Broadcasting)${NC}"
        echo -e "  Interface:  ${CYAN}${dev}${NC}"
        echo -e "  Gateway IP: ${GREEN}${ip}${NC}"
        echo -e "  Security:   WPA2-Personal (Shared NAT)"
        echo ""
        echo -e "${BOLD}[*] Associated / Connected Clients:${NC}"
        ip neigh show dev "$dev" 2>/dev/null || echo "  (No clients detected)"
    else
        echo -e "  Status: ${YELLOW}INACTIVE${NC}"
        echo -e "${YELLOW}[*] Available Wi-Fi interfaces:${NC}"
        local devs
        devs=$(nmcli -t -f DEVICE,TYPE dev 2>/dev/null | grep ':wifi$' | cut -d: -f1 || true)
        if [[ -n "$devs" ]]; then
            while IFS= read -r d; do
                echo "    - $d"
            done <<< "$devs"
        else
            echo "    (None detected)"
        fi
    fi
}

cmd_wifi_hotspot_stop() {
    echo -e "${CYAN}[*] Stopping Wi-Fi hotspot...${NC}"
    nmcli connection down id dfnet-hotspot 2>/dev/null || true
    nmcli connection delete id dfnet-hotspot 2>/dev/null || true
    echo -e "${GREEN}[✓] Wi-Fi hotspot stopped and profile cleared.${NC}"
}

cmd_wifi_hotspot_start() {
    local iface="${1:-}"
    local ssid="${2:-DF-FORENSICS-AP}"
    local pass="${3:-Forensics2026!}"

    if [[ -z "$iface" ]]; then
        iface=$(nmcli -t -f DEVICE,TYPE dev 2>/dev/null | grep ':wifi$' | cut -d: -f1 | head -n1 || true)
        if [[ -z "$iface" ]]; then
            for path in /sys/class/net/*/wireless; do
                if [[ -d "$path" ]]; then
                    iface=$(basename "$(dirname "$path")")
                    break
                fi
            done
        fi
    fi

    if [[ -z "$iface" ]]; then
        echo -e "${RED}[!] Error: No Wi-Fi interface detected on this system.${NC}" >&2
        exit 1
    fi

    if [[ ${#pass} -lt 8 ]]; then
        echo -e "${RED}[!] Error: WPA2 password must be at least 8 characters.${NC}" >&2
        exit 1
    fi

    echo -e "${CYAN}[*] Initializing Wi-Fi Hotspot on interface: ${BOLD}$iface${NC}..."
    echo -e "    SSID:     ${YELLOW}$ssid${NC}"
    echo -e "    Password: ${YELLOW}$pass${NC}"

    # Tear down existing profile if lingering
    nmcli connection down id dfnet-hotspot 2>/dev/null || true
    nmcli connection delete id dfnet-hotspot 2>/dev/null || true

    if nmcli device wifi hotspot ifname "$iface" con-name "dfnet-hotspot" ssid "$ssid" password "$pass"; then
        echo -e "${GREEN}${BOLD}[✓] Wi-Fi Hotspot successfully activated!${NC}"
        echo -e "    Broadcasting SSID: ${CYAN}$ssid${NC}"
        echo -e "    WPA2 Key:          ${CYAN}$pass${NC}"
        local ip
        ip=$(ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet /{print $2}' || echo "10.42.0.1/24")
        echo -e "    Hotspot IP:        ${GREEN}$ip${NC}"
        echo -e "    Target systems can join and stream forensic data directly."
    else
        echo -e "${RED}[!] Failed to bring up Wi-Fi hotspot on $iface.${NC}" >&2
        exit 1
    fi
}

usage() {
    echo -e "${BOLD}df-net${NC} — Forensic Network Operations Helper"
    echo "Usage:"
    echo "  df-net ip                              Launch NetworkManager TUI (nmtui) to configure static IP / Wi-Fi"
    echo "  df-net mac [iface]                     Spoof/randomize MAC address for stealth connection"
    echo "  df-net mac-restore [iface]             Restore original factory hardware MAC address"
    echo "  df-net scan [iface]                    Quick ARP network discovery of local servers/NAS"
    echo "  df-net smb <//srv/sh> <dir>            Mount an on-premise Windows/Samba share to /media/target"
    echo "  df-net nfs <srv:/exp> <dir>            Mount an on-premise NFS export to /media/target"
    echo "  df-net receive [port] [out]            Listen on network port to receive raw disk stream over netcat"
    echo "  df-net hotspot [start|stop|status] ... Manage Wi-Fi hotspot / forensic access point"
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
    hotspot)
        shift
        case "${1:-status}" in
            start)
                shift
                cmd_wifi_hotspot_start "$@"
                ;;
            stop)
                cmd_wifi_hotspot_stop
                ;;
            status)
                cmd_wifi_hotspot_status
                ;;
            *)
                echo "Usage: df-net hotspot [start|stop|status] [iface] [ssid] [password]"
                exit 1
                ;;
        esac
        ;;
    *)
        usage
        ;;
esac
