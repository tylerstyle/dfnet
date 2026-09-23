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

/// Safely executes an iptables command with stdout/stderr captured in memory.
/// Never leaks command output or error messages to the terminal/TUI screen.
fn iptables_exec(args: &[&str]) -> (bool, String) {
    match Command::new("iptables").args(args).output() {
        Ok(out) => (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ),
        Err(e) => (false, e.to_string()),
    }
}

/// Checks if an iptables rule exists in a given table and chain.
/// Never outputs to stderr or stdout.
fn iptables_rule_exists(table: Option<&str>, chain: &str, rule: &[&str]) -> bool {
    let mut args = Vec::new();
    if let Some(t) = table {
        args.extend_from_slice(&["-t", t]);
    }
    args.extend_from_slice(&["-C", chain]);
    args.extend_from_slice(rule);
    let (success, _) = iptables_exec(&args);
    success
}

/// Deletes a single occurrence of an iptables rule if it exists.
fn iptables_delete_rule(table: Option<&str>, chain: &str, rule: &[&str]) -> bool {
    let mut args = Vec::new();
    if let Some(t) = table {
        args.extend_from_slice(&["-t", t]);
    }
    args.extend_from_slice(&["-D", chain]);
    args.extend_from_slice(rule);
    let (success, _) = iptables_exec(&args);
    success
}

/// Deletes all occurrences of an iptables rule cleanly without emitting errors when none remain.
fn iptables_delete_all(table: Option<&str>, chain: &str, rule: &[&str]) {
    while iptables_delete_rule(table, chain, rule) {}
}

/// Appends a rule to an iptables chain if it does not already exist.
fn iptables_append_unique(table: Option<&str>, chain: &str, rule: &[&str]) -> Result<()> {
    if !iptables_rule_exists(table, chain, rule) {
        let mut args = Vec::new();
        if let Some(t) = table {
            args.extend_from_slice(&["-t", t]);
        }
        args.extend_from_slice(&["-A", chain]);
        args.extend_from_slice(rule);
        let (success, err) = iptables_exec(&args);
        if !success {
            anyhow::bail!("iptables rule append failed: {}", err);
        }
    }
    Ok(())
}

/// Inserts a rule at position 1 of an iptables chain if it does not already exist.
fn iptables_insert_unique(table: Option<&str>, chain: &str, pos: usize, rule: &[&str]) -> Result<()> {
    if !iptables_rule_exists(table, chain, rule) {
        let mut args = Vec::new();
        if let Some(t) = table {
            args.extend_from_slice(&["-t", t]);
        }
        let pos_str = pos.to_string();
        args.extend_from_slice(&["-I", chain, &pos_str]);
        args.extend_from_slice(rule);
        let (success, err) = iptables_exec(&args);
        if !success {
            anyhow::bail!("iptables rule insert failed: {}", err);
        }
    }
    Ok(())
}

/// Enables NAT Masquerade on uplink and forward rules between AP interface and uplink
pub fn enable_nat_routing(ap_iface: &str, uplink: &str) -> Result<()> {
    if ap_iface.is_empty() {
        anyhow::bail!("Wi-Fi AP interface cannot be empty.");
    }
    if uplink.is_empty() {
        anyhow::bail!("Uplink interface cannot be empty for NAT passthrough.");
    }

    // 1. Teardown any conflicting rules for this AP interface
    let _ = teardown_routing(ap_iface, Some(uplink));

    // 2. Enable IPv4 forwarding
    set_ip_forwarding(true).context("Failed to enable net.ipv4.ip_forward=1")?;

    // 3. Masquerade on uplink
    iptables_append_unique(
        Some("nat"),
        "POSTROUTING",
        &["-o", uplink, "-j", "MASQUERADE"],
    )
    .context("Failed to configure iptables NAT Masquerade on uplink")?;

    // 4. FORWARD rule from ap_iface to uplink
    iptables_append_unique(
        None,
        "FORWARD",
        &["-i", ap_iface, "-o", uplink, "-j", "ACCEPT"],
    )
    .context("Failed to configure iptables FORWARD out rule")?;

    // 5. FORWARD return rule from uplink to ap_iface for established / related traffic
    let conntrack_rule = [
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
    ];
    let state_rule = [
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
    ];

    if !iptables_rule_exists(None, "FORWARD", &conntrack_rule)
        && !iptables_rule_exists(None, "FORWARD", &state_rule)
    {
        // Try modern conntrack first
        if iptables_append_unique(None, "FORWARD", &conntrack_rule).is_err() {
            // Fallback to legacy state module if conntrack failed
            iptables_append_unique(None, "FORWARD", &state_rule).context(
                "Failed to configure iptables FORWARD return rule (both conntrack and state modules failed)",
            )?;
        }
    }

    Ok(())
}

/// Strictly isolates AP clients from all external networks (Air-Gapped Forensic Mode)
pub fn enable_isolated_routing(ap_iface: &str) -> Result<()> {
    if ap_iface.is_empty() {
        anyhow::bail!("Wi-Fi AP interface cannot be empty.");
    }

    // 1. Teardown any conflicting forwarding/NAT rules
    let _ = teardown_routing(ap_iface, None);

    // 2. Disable global IP forwarding
    let _ = set_ip_forwarding(false);

    // 3. Strict DROP on forward traffic originating from ap_iface
    iptables_insert_unique(None, "FORWARD", 1, &["-i", ap_iface, "-j", "DROP"])
        .context("Failed to insert iptables DROP rule for ap_iface outbound")?;

    // 4. Also block forward traffic destined to ap_iface from external networks
    iptables_insert_unique(None, "FORWARD", 1, &["-o", ap_iface, "-j", "DROP"])
        .context("Failed to insert iptables DROP rule for ap_iface inbound")?;

    Ok(())
}

/// Flushes all forwarding and NAT rules associated with ap_iface and uplink, restoring forward state
pub fn teardown_routing(ap_iface: &str, uplink: Option<&str>) -> Result<()> {
    // 1. Remove DROP rules for ap_iface
    if !ap_iface.is_empty() {
        iptables_delete_all(None, "FORWARD", &["-i", ap_iface, "-j", "DROP"]);
        iptables_delete_all(None, "FORWARD", &["-o", ap_iface, "-j", "DROP"]);
    }

    // 2. Remove known uplink rules if uplink provided
    if let Some(up) = uplink {
        if !ap_iface.is_empty() {
            iptables_delete_all(None, "FORWARD", &["-i", ap_iface, "-o", up, "-j", "ACCEPT"]);
            iptables_delete_all(
                None,
                "FORWARD",
                &[
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
                ],
            );
            iptables_delete_all(
                None,
                "FORWARD",
                &[
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
                ],
            );
        }
        iptables_delete_all(Some("nat"), "POSTROUTING", &["-o", up, "-j", "MASQUERADE"]);
    }

    // 3. Parse iptables -S FORWARD to catch any remaining rules matching ap_iface
    if !ap_iface.is_empty() {
        let (success, _) = iptables_exec(&["-S", "FORWARD"]);
        if success {
            if let Ok(out) = Command::new("iptables").args(["-S", "FORWARD"]).output() {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    if line.contains(ap_iface) && line.starts_with("-A FORWARD") {
                        let rule_args: Vec<&str> = line.split_whitespace().collect();
                        if rule_args.len() >= 3 {
                            let mut del_cmd = vec!["-D", "FORWARD"];
                            del_cmd.extend_from_slice(&rule_args[2..]);
                            let _ = iptables_exec(&del_cmd);
                        }
                        // Also check if line specified an uplink interface
                        for (idx, &part) in rule_args.iter().enumerate() {
                            if (part == "-o" || part == "-i") && idx + 1 < rule_args.len() {
                                let candidate = rule_args[idx + 1];
                                if candidate != ap_iface && !candidate.is_empty() {
                                    iptables_delete_all(
                                        Some("nat"),
                                        "POSTROUTING",
                                        &["-o", candidate, "-j", "MASQUERADE"],
                                    );
                                }
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
