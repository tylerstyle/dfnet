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

cmd_route_status() {
    local iface="${1:-}"
    echo -e "${BOLD}[*] Network Routing & Forensic Isolation Status:${NC}"
    local fwd
    fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
    if [[ "$fwd" == "1" ]]; then
        echo -e "  IP Forwarding:   ${GREEN}${BOLD}Enabled (net.ipv4.ip_forward=1)${NC}"
    else
        echo -e "  IP Forwarding:   ${YELLOW}Disabled (net.ipv4.ip_forward=0)${NC}"
    fi

    local def_gw
    def_gw=$(ip route show default 2>/dev/null | head -n1 || true)
    echo -e "  Default Route:   ${CYAN}${def_gw:-None}${NC}"

    echo -e "  Active iptables Forward Rules:"
    iptables -S FORWARD 2>/dev/null | while read -r line; do
        echo -e "    $line"
    done || echo -e "    (Unable to read iptables rules)"

    echo -e "  Active NAT Masquerade Rules:"
    iptables -t nat -S POSTROUTING 2>/dev/null | grep MASQUERADE | while read -r line; do
        echo -e "    $line"
    done || echo -e "    (None or permission denied)"
}

cmd_route_enable() {
    local ap="${1:-}"
    local uplink="${2:-}"
    if [[ -z "$ap" || -z "$uplink" ]]; then
        echo "Usage: df-net route enable <ap_iface> <uplink_iface>"
        exit 1
    fi

    echo -e "${CYAN}[*] Enabling NAT Passthrough: $ap -> $uplink...${NC}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    iptables -t nat -A POSTROUTING -o "$uplink" -j MASQUERADE
    iptables -A FORWARD -i "$ap" -o "$uplink" -j ACCEPT
    iptables -A FORWARD -i "$uplink" -o "$ap" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$uplink" -o "$ap" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    echo -e "${GREEN}[✓] NAT Passthrough enabled via $uplink.${NC}"
}

cmd_route_isolate() {
    local ap="${1:-}"
    if [[ -z "$ap" ]]; then
        echo "Usage: df-net route isolate <ap_iface>"
        exit 1
    fi

    echo -e "${CYAN}[*] Isolating AP $ap (Strict Forensic Air-Gap)...${NC}"
    sysctl -w net.ipv4.ip_forward=0 >/dev/null
    iptables -I FORWARD 1 -i "$ap" -j DROP
    iptables -I FORWARD 1 -o "$ap" -j DROP
    echo -e "${GREEN}[✓] Forensic Air-Gap active on $ap. Forwarding to LAN/Internet blocked.${NC}"
}

cmd_route_reset() {
    local ap="${1:-}"
    local uplink="${2:-}"
    echo -e "${CYAN}[*] Resetting and flushing routing & forward rules...${NC}"
    if [[ -n "$ap" ]]; then
        iptables -D FORWARD -i "$ap" -j DROP 2>/dev/null || true
        iptables -D FORWARD -o "$ap" -j DROP 2>/dev/null || true
        if [[ -n "$uplink" ]]; then
            iptables -D FORWARD -i "$ap" -o "$uplink" -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -i "$uplink" -o "$ap" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -i "$uplink" -o "$ap" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
            iptables -t nat -D POSTROUTING -o "$uplink" -j MASQUERADE 2>/dev/null || true
        fi
    fi
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
    echo -e "${GREEN}[✓] Routing rules flushed and forwarding reset.${NC}"
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
        echo -e "  Security:   WPA2-Personal • 802.11 AP"

        local fwd
        fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
        if [[ "$fwd" == "1" ]]; then
            echo -e "  IP Forward: ${GREEN}Enabled (1)${NC}"
        else
            echo -e "  IP Forward: ${YELLOW}Disabled (0)${NC}"
        fi

        local drop_rule
        drop_rule=$(iptables -S FORWARD 2>/dev/null | grep -- "-i $dev -j DROP" || true)
        if [[ -n "$drop_rule" ]]; then
            echo -e "  Firewall:   ${MAGENTA}${BOLD}Air-Gapped / Isolated (Strict DROP)${NC}"
        else
            local fwd_rule
            fwd_rule=$(iptables -S FORWARD 2>/dev/null | grep -- "-i $dev -o " | head -n1 || true)
            if [[ -n "$fwd_rule" ]]; then
                local up
                up=$(echo "$fwd_rule" | awk '{for(i=1;i<=NF;i++) if($i=="-o") print $(i+1)}')
                echo -e "  Firewall:   ${GREEN}${BOLD}Routed to LAN via ${up} (NAT Masquerade)${NC}"
            else
                echo -e "  Firewall:   Standby / Unmanaged"
            fi
        fi

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
    local dev="${1:-}"
    if [[ -z "$dev" ]]; then
        dev=$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | grep '^dfnet-hotspot:' | cut -d: -f2 || true)
    fi

    echo -e "${CYAN}[*] Stopping Wi-Fi hotspot...${NC}"
    nmcli connection down id dfnet-hotspot 2>/dev/null || true
    nmcli connection delete id dfnet-hotspot 2>/dev/null || true

    if [[ -n "$dev" ]]; then
        cmd_route_reset "$dev" ""
    fi
    echo -e "${GREEN}[✓] Wi-Fi hotspot stopped, routing flushed, and profile cleared.${NC}"
}

cmd_wifi_hotspot_start() {
    local iface=""
    local ssid="DF-FORENSICS-AP"
    local pass="Forensics2026!"
    local uplink=""
    local isolate="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --uplink)
                uplink="$2"
                shift 2
                ;;
            --isolate)
                isolate="true"
                shift
                ;;
            -*)
                shift
                ;;
            *)
                if [[ -z "$iface" ]]; then
                    iface="$1"
                elif [[ "$ssid" == "DF-FORENSICS-AP" ]]; then
                    ssid="$1"
                elif [[ "$pass" == "Forensics2026!" ]]; then
                    pass="$1"
                fi
                shift
                ;;
        esac
    done

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

        if [[ "$isolate" == "true" ]]; then
            cmd_route_isolate "$iface"
        elif [[ -n "$uplink" ]]; then
            cmd_route_enable "$iface" "$uplink"
        else
            local def_up
            def_up=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)
            if [[ -n "$def_up" && "$def_up" != "$iface" ]]; then
                cmd_route_enable "$iface" "$def_up"
            else
                cmd_route_isolate "$iface"
            fi
        fi
    else
        echo -e "${RED}[!] Failed to bring up Wi-Fi hotspot on $iface.${NC}" >&2
        exit 1
    fi
}

usage() {
    echo -e "${BOLD}df-net${NC} — Forensic Network Operations Helper"
    echo "Usage:"
    echo "  df-net ip                                      Launch NetworkManager TUI (nmtui) to configure static IP / Wi-Fi"
    echo "  df-net mac [iface]                             Spoof/randomize MAC address for stealth connection"
    echo "  df-net mac-restore [iface]                     Restore original factory hardware MAC address"
    echo "  df-net scan [iface]                            Quick ARP network discovery of local servers/NAS"
    echo "  df-net smb <//srv/sh> <dir>                    Mount an on-premise Windows/Samba share to /media/target"
    echo "  df-net nfs <srv:/exp> <dir>                    Mount an on-premise NFS export to /media/target"
    echo "  df-net receive [port] [out]                    Listen on network port to receive raw disk stream over netcat"
    echo "  df-net hotspot [start|stop|status] ...         Manage Wi-Fi hotspot / forensic access point"
    echo "  df-net route [status|enable|isolate|reset] ... Manage NAT passthrough routing and forensic air-gap"
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
                shift
                cmd_wifi_hotspot_stop "${1:-}"
                ;;
            status)
                cmd_wifi_hotspot_status
                ;;
            *)
                echo "Usage: df-net hotspot start [iface] [ssid] [pass] [--uplink <dev>] [--isolate]"
                echo "       df-net hotspot stop [iface]"
                echo "       df-net hotspot status"
                exit 1
                ;;
        esac
        ;;
    route)
        shift
        case "${1:-status}" in
            status)
                shift
                cmd_route_status "$@"
                ;;
            enable)
                shift
                cmd_route_enable "$@"
                ;;
            isolate)
                shift
                cmd_route_isolate "$@"
                ;;
            reset)
                shift
                cmd_route_reset "$@"
                ;;
            *)
                echo "Usage: df-net route [status|enable|isolate|reset] ..."
                exit 1
                ;;
        esac
        ;;
    *)
        usage
        ;;
esac

