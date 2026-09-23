use anyhow::{Context, Result};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotspotRoutingMode {
    NatPassthrough,
    Isolated,
}

impl HotspotRoutingMode {
    pub fn label(&self) -> &'static str {
        match self {
            HotspotRoutingMode::NatPassthrough => "Routed to LAN (NAT Passthrough)",
            HotspotRoutingMode::Isolated => "Air-Gapped / Isolated (Forensic Ingest)",
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            HotspotRoutingMode::NatPassthrough => "Routed to LAN",
            HotspotRoutingMode::Isolated => "Air-Gapped / Isolated",
        }
    }

    pub fn toggle(&self) -> Self {
        match self {
            HotspotRoutingMode::NatPassthrough => HotspotRoutingMode::Isolated,
            HotspotRoutingMode::Isolated => HotspotRoutingMode::NatPassthrough,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoutingStatus {
    pub ip_forwarding_enabled: bool,
    pub mode: Option<HotspotRoutingMode>,
    pub active_uplink: Option<String>,
    pub firewall_status: String,
    pub default_gateway: Option<String>,
}

/// Reads current IPv4 forwarding state from procfs or sysctl
pub fn get_ip_forwarding() -> bool {
    if let Ok(val) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
        return val.trim() == "1";
    }
    if let Ok(out) = Command::new("sysctl")
        .args(["-n", "net.ipv4.ip_forward"])
        .output()
    {
        let val = String::from_utf8_lossy(&out.stdout);
        return val.trim() == "1";
    }
    false
}

/// Sets IPv4 forwarding state via procfs and sysctl
pub fn set_ip_forwarding(enable: bool) -> Result<()> {
    let val_str = if enable { "1" } else { "0" };

    // Try direct procfs write first
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", format!("{}\n", val_str));

    // Also call sysctl to notify kernel / systemd
    let output = Command::new("sysctl")
        .args(["-w", &format!("net.ipv4.ip_forward={}", val_str)])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            return Ok(());
        }
    }

    if get_ip_forwarding() == enable {
        return Ok(());
    }

    anyhow::bail!("Failed to set net.ipv4.ip_forward={}", val_str)
}

/// Detects system default gateway interface from `ip route show default`
pub fn get_default_gateway_interface() -> Option<String> {
    if let Ok(out) = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        parse_default_gateway_output(&String::from_utf8_lossy(&out.stdout))
    } else {
        None
    }
}

pub fn parse_default_gateway_output(output: &str) -> Option<String> {
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = parts.iter().position(|&x| x == "dev") {
            if pos + 1 < parts.len() {
                return Some(parts[pos + 1].to_string());
            }
        }
    }
    None
}

/// Enables NAT Masquerade on uplink and forward rules between AP interface and uplink
pub fn enable_nat_routing(ap_iface: &str, uplink: &str) -> Result<()> {
    // 1. Teardown any conflicting rules for this AP interface
    let _ = teardown_routing(ap_iface, Some(uplink));

    // 2. Enable IPv4 forwarding
    set_ip_forwarding(true).context("Failed to enable net.ipv4.ip_forward=1")?;

    // 3. Masquerade on uplink
    let masq_check = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-o",
            uplink,
            "-j",
            "MASQUERADE",
        ])
        .status();
    if !masq_check.map(|s| s.success()).unwrap_or(false) {
        let out = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                uplink,
                "-j",
                "MASQUERADE",
            ])
            .output()
            .context("Failed to execute iptables POSTROUTING MASQUERADE")?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("iptables NAT Masquerade error: {}", err.trim());
        }
    }

    // 4. FORWARD rule from ap_iface to uplink
    let fwd_out_check = Command::new("iptables")
        .args(["-C", "FORWARD", "-i", ap_iface, "-o", uplink, "-j", "ACCEPT"])
        .status();
    if !fwd_out_check.map(|s| s.success()).unwrap_or(false) {
        let out = Command::new("iptables")
            .args(["-A", "FORWARD", "-i", ap_iface, "-o", uplink, "-j", "ACCEPT"])
            .output()
            .context("Failed to execute iptables FORWARD out rule")?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("iptables FORWARD out error: {}", err.trim());
        }
    }

    // 5. FORWARD rule from uplink to ap_iface for established / related traffic
    let fwd_in_check = Command::new("iptables")
        .args([
            "-C",
            "FORWARD",
            "-i",
            uplink,
            "-o",
            ap_iface,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ])
        .status();
    if !fwd_in_check.map(|s| s.success()).unwrap_or(false) {
        let out = Command::new("iptables")
            .args([
                "-A",
                "FORWARD",
                "-i",
                uplink,
                "-o",
                ap_iface,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ])
            .output();
        let success = out.as_ref().map(|o| o.status.success()).unwrap_or(false);
        if !success {
            // Fallback for modern kernels supporting --ctstate
            let out2 = Command::new("iptables")
                .args([
                    "-A",
                    "FORWARD",
                    "-i",
                    uplink,
                    "-o",
                    ap_iface,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ])
                .output()
                .context("Failed to execute iptables FORWARD return rule")?;
            if !out2.status.success() {
                let err = String::from_utf8_lossy(&out2.stderr);
                anyhow::bail!("iptables FORWARD return error: {}", err.trim());
            }
        }
    }

    Ok(())
}

/// Strictly isolates AP clients from all external networks (Air-Gapped Forensic Mode)
pub fn enable_isolated_routing(ap_iface: &str) -> Result<()> {
    // 1. Teardown any conflicting forwarding/NAT rules
    let _ = teardown_routing(ap_iface, None);

    // 2. Disable global IP forwarding
    let _ = set_ip_forwarding(false);

    // 3. Strict DROP on forward traffic originating from ap_iface
    let drop_out_check = Command::new("iptables")
        .args(["-C", "FORWARD", "-i", ap_iface, "-j", "DROP"])
        .status();
    if !drop_out_check.map(|s| s.success()).unwrap_or(false) {
        let out = Command::new("iptables")
            .args(["-I", "FORWARD", "1", "-i", ap_iface, "-j", "DROP"])
            .output()
            .context("Failed to insert iptables DROP rule for ap_iface")?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("iptables DROP insertion error: {}", err.trim());
        }
    }

    // 4. Also block forward traffic destined to ap_iface from external networks
    let drop_in_check = Command::new("iptables")
        .args(["-C", "FORWARD", "-o", ap_iface, "-j", "DROP"])
        .status();
    if !drop_in_check.map(|s| s.success()).unwrap_or(false) {
        let _ = Command::new("iptables")
            .args(["-I", "FORWARD", "1", "-o", ap_iface, "-j", "DROP"])
            .output();
    }

    Ok(())
}

/// Flushes all forwarding and NAT rules associated with ap_iface and uplink, restoring forward state
pub fn teardown_routing(ap_iface: &str, uplink: Option<&str>) -> Result<()> {
    // 1. Remove DROP rules for ap_iface
    if !ap_iface.is_empty() {
        while Command::new("iptables")
            .args(["-D", "FORWARD", "-i", ap_iface, "-j", "DROP"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {}
        while Command::new("iptables")
            .args(["-D", "FORWARD", "-o", ap_iface, "-j", "DROP"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {}
    }

    // 2. Remove known uplink rules if uplink provided
    if let Some(up) = uplink {
        if !ap_iface.is_empty() {
            while Command::new("iptables")
                .args(["-D", "FORWARD", "-i", ap_iface, "-o", up, "-j", "ACCEPT"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {}
            while Command::new("iptables")
                .args([
                    "-D",
                    "FORWARD",
                    "-i",
                    up,
                    "-o",
                    ap_iface,
                    "-m",
                    "state",
                    "--state",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {}
            while Command::new("iptables")
                .args([
                    "-D",
                    "FORWARD",
                    "-i",
                    up,
                    "-o",
                    ap_iface,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {}
        }
        while Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-o",
                up,
                "-j",
                "MASQUERADE",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {}
    }

    // 3. Parse iptables -S FORWARD to catch any remaining rules matching ap_iface
    if !ap_iface.is_empty() {
        if let Ok(out) = Command::new("iptables").args(["-S", "FORWARD"]).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if line.contains(ap_iface) && line.starts_with("-A FORWARD") {
                    let rule_args: Vec<&str> = line.split_whitespace().collect();
                    if rule_args.len() >= 3 {
                        let mut del_cmd = vec!["-D", "FORWARD"];
                        del_cmd.extend_from_slice(&rule_args[2..]);
                        let _ = Command::new("iptables").args(&del_cmd).output();
                    }
                    // Also check if line specified an uplink interface
                    for (idx, &part) in rule_args.iter().enumerate() {
                        if (part == "-o" || part == "-i") && idx + 1 < rule_args.len() {
                            let candidate = rule_args[idx + 1];
                            if candidate != ap_iface && !candidate.is_empty() {
                                let _ = Command::new("iptables")
                                    .args([
                                        "-t",
                                        "nat",
                                        "-D",
                                        "POSTROUTING",
                                        "-o",
                                        candidate,
                                        "-j",
                                        "MASQUERADE",
                                    ])
                                    .output();
                            }
                        }
                    }
                }
            }
        }
    }

    // 4. Restore net.ipv4.ip_forward=0
    let _ = set_ip_forwarding(false);

    Ok(())
}

/// Inspects current firewall, NAT masquerade, and IP forwarding rules
pub fn get_routing_status(ap_iface: Option<&str>) -> RoutingStatus {
    let ip_forwarding_enabled = get_ip_forwarding();
    let default_gateway = get_default_gateway_interface();

    let mut detected_mode = None;
    let mut detected_uplink = None;
    let mut firewall_status = "Disabled / Inactive".to_string();

    if let Some(ap) = ap_iface {
        if let Ok(out) = Command::new("iptables").args(["-S", "FORWARD"]).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if line.contains(ap) {
                    if line.contains("-j DROP") {
                        detected_mode = Some(HotspotRoutingMode::Isolated);
                        firewall_status =
                            "Isolated (Strict DROP: LAN/WAN blocked)".to_string();
                        break;
                    }
                    if line.contains("-j ACCEPT") && line.contains(&format!("-i {}", ap)) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(pos) = parts.iter().position(|&x| x == "-o") {
                            if pos + 1 < parts.len() {
                                let up = parts[pos + 1].to_string();
                                detected_mode = Some(HotspotRoutingMode::NatPassthrough);
                                detected_uplink = Some(up.clone());
                                firewall_status =
                                    format!("Active (NAT Passthrough -> {})", up);
                            }
                        }
                    }
                }
            }
        }
    }

    RoutingStatus {
        ip_forwarding_enabled,
        mode: detected_mode,
        active_uplink: detected_uplink,
        firewall_status,
        default_gateway,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_mode_toggle() {
        let mode = HotspotRoutingMode::NatPassthrough;
        assert_eq!(mode.toggle(), HotspotRoutingMode::Isolated);
        assert_eq!(mode.toggle().toggle(), HotspotRoutingMode::NatPassthrough);
    }

    #[test]
    fn test_routing_mode_labels() {
        assert_eq!(
            HotspotRoutingMode::NatPassthrough.label(),
            "Routed to LAN (NAT Passthrough)"
        );
        assert_eq!(
            HotspotRoutingMode::Isolated.label(),
            "Air-Gapped / Isolated (Forensic Ingest)"
        );
    }

    #[test]
    fn test_parse_default_gateway() {
        let sample = "default via 192.168.178.1 dev enp0s31f6 proto dhcp src 192.168.178.80 metric 100\n";
        assert_eq!(
            parse_default_gateway_output(sample),
            Some("enp0s31f6".to_string())
        );

        let empty = "";
        assert_eq!(parse_default_gateway_output(empty), None);
    }
}
