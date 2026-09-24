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
            HotspotRoutingMode::Isolated => "Forwarding Blocked (Local Ingest)",
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            HotspotRoutingMode::NatPassthrough => "Routed to LAN",
            HotspotRoutingMode::Isolated => "Forwarding Blocked",
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
    pub ip_forwarding_enabled: Option<bool>,
    pub mode: Option<HotspotRoutingMode>,
    pub active_uplink: Option<String>,
    pub firewall_status: String,
    pub default_gateway: Option<String>,
}

// Rules carry an exact owner tag. Never infer ownership from an interface substring.
const OWNER: &str = "dfnet:";

pub fn validate_interface(name: &str) -> Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 15
            && !name.starts_with('-')
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)),
        "Invalid interface name: {name}"
    );
    Ok(())
}

fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Cannot run {program}"))?;
    anyhow::ensure!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn get_ip_forwarding() -> Option<bool> {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .ok()
        .or_else(|| run("sysctl", &["-n", "net.ipv4.ip_forward"]).ok())
        .and_then(|s| match s.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        })
}

pub fn get_default_gateway_interface() -> Option<String> {
    run("ip", &["route", "show", "default"])
        .ok()
        .and_then(|s| parse_default_gateway_output(&s))
}

pub fn parse_default_gateway_output(output: &str) -> Option<String> {
    output
        .lines()
        .filter(|line| line.starts_with("default "))
        .find_map(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            option(&parts, "dev").map(str::to_owned)
        })
}

fn option<'a>(parts: &[&'a str], key: &str) -> Option<&'a str> {
    parts
        .windows(2)
        .find(|pair| pair[0] == key)
        .map(|pair| pair[1])
}

fn owned_rule(line: &str, ap: &str) -> bool {
    let parts: Vec<_> = line.split_whitespace().collect();
    let Some(tag) = option(&parts, "--comment") else {
        return false;
    };
    let tag = tag.trim_matches('"');
    if ap.is_empty() {
        tag.strip_prefix(OWNER)
            .is_some_and(|name| validate_interface(name).is_ok())
    } else {
        tag == format!("{OWNER}{ap}")
    }
}

fn rule(program: &str, table: &str, chain: &str, ap: &str, args: &[&str]) -> Result<()> {
    let tag = format!("{OWNER}{ap}");
    let mut check = vec!["-w", "5", "-t", table, "-C", chain];
    check.extend_from_slice(args);
    check.extend_from_slice(&["-m", "comment", "--comment", &tag]);
    let out = Command::new(program)
        .args(&check)
        .output()
        .with_context(|| format!("Cannot run {program}"))?;
    if out.status.success() {
        return Ok(());
    }
    anyhow::ensure!(
        out.status.code() == Some(1),
        "Cannot inspect {program}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut insert = vec!["-w", "5", "-t", table, "-I", chain, "1"];
    insert.extend_from_slice(&check[6..]);
    run(program, &insert)?;
    Ok(())
}

fn remove_owned(ap: &str, keep_drops: bool) -> Result<()> {
    let mut failures = Vec::new();
    for (program, table, chain) in [
        ("iptables", "filter", "INPUT"),
        ("iptables", "filter", "FORWARD"),
        ("iptables", "nat", "POSTROUTING"),
        ("ip6tables", "filter", "INPUT"),
        ("ip6tables", "filter", "FORWARD"),
    ] {
        match run(program, &["-w", "5", "-t", table, "-S", chain]) {
            Ok(output) => {
                for line in output.lines().filter(|l| owned_rule(l, ap)) {
                    let parts: Vec<_> = line
                        .split_whitespace()
                        .map(|p| p.trim_matches('"'))
                        .collect();
                    if parts.first() != Some(&"-A") || parts.get(1) != Some(&chain) {
                        continue;
                    }
                    if keep_drops && option(&parts, "-j") == Some("DROP") {
                        continue;
                    }
                    let mut delete = vec!["-w", "5", "-t", table, "-D", chain];
                    delete.extend_from_slice(&parts[2..]);
                    if let Err(e) = run(program, &delete) {
                        failures.push(e.to_string());
                    }
                }
            }
            Err(e) => failures.push(e.to_string()),
        }
    }
    anyhow::ensure!(
        failures.is_empty(),
        "Firewall cleanup incomplete: {}",
        failures.join("; ")
    );
    Ok(())
}

/// Install forwarding guards before activating an AP. IPv6 is blocked in both modes.
/// Never change global forwarding or the administrator's existing rules.
pub fn prepare_routing(ap: &str) -> Result<()> {
    validate_interface(ap)?;
    run("ip", &["link", "show", "dev", ap])?;
    for program in ["iptables", "ip6tables"] {
        rule(program, "filter", "FORWARD", ap, &["-i", ap, "-j", "DROP"])?;
        rule(program, "filter", "FORWARD", ap, &["-o", ap, "-j", "DROP"])?;
        rule(program, "filter", "INPUT", ap, &["-i", ap, "-j", "DROP"])?;
    }
    Ok(())
}

fn allow_ingest(ap: &str) -> Result<()> {
    // Only DHCP, DNS, the default receiver and replies to workstation traffic.
    for args in [
        vec![
            "-i",
            ap,
            "-p",
            "udp",
            "-m",
            "multiport",
            "--dports",
            "53,67",
            "-j",
            "ACCEPT",
        ],
        vec![
            "-i",
            ap,
            "-p",
            "tcp",
            "-m",
            "multiport",
            "--dports",
            "53,9999",
            "-j",
            "ACCEPT",
        ],
        vec![
            "-i",
            ap,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    ] {
        rule("iptables", "filter", "INPUT", ap, &args)?;
    }
    Ok(())
}

pub fn enable_isolated_routing(ap: &str) -> Result<()> {
    prepare_routing(ap)?;
    remove_owned(ap, true)?;
    allow_ingest(ap)
}

pub fn validate_uplink(ap: &str, uplink: &str) -> Result<()> {
    validate_interface(ap)?;
    validate_interface(uplink)?;
    anyhow::ensure!(ap != uplink, "AP and uplink must be different interfaces");
    anyhow::ensure!(
        get_default_gateway_interface().as_deref() == Some(uplink),
        "Uplink must be the current default-route interface; configure the system route first"
    );
    Ok(())
}

pub fn enable_nat_routing(ap: &str, uplink: &str) -> Result<()> {
    validate_uplink(ap, uplink)?;
    anyhow::ensure!(
        get_ip_forwarding() == Some(true),
        "IPv4 forwarding must already be enabled (NetworkManager sharing enables it for hotspots)"
    );
    let output = run("ip", &["-j", "-4", "addr", "show", "dev", ap])?;
    let addresses: serde_json::Value = serde_json::from_str(&output)?;
    let address = addresses
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|v| v["addr_info"].as_array().into_iter().flatten())
        .find(|v| v["scope"] == "global")
        .context("AP has no global IPv4 address")?;
    let ip: std::net::Ipv4Addr = address["local"]
        .as_str()
        .context("Missing AP IPv4 address")?
        .parse()?;
    let prefix = address["prefixlen"]
        .as_u64()
        .filter(|p| *p <= 32)
        .context("Invalid AP prefix")?;
    let subnet = format!("{ip}/{prefix}");
    prepare_routing(ap)?;
    remove_owned(ap, true)?;
    let result = (|| -> Result<()> {
        allow_ingest(ap)?;
        rule(
            "iptables",
            "nat",
            "POSTROUTING",
            ap,
            &["-s", &subnet, "-o", uplink, "-j", "MASQUERADE"],
        )?;
        rule(
            "iptables",
            "filter",
            "FORWARD",
            ap,
            &[
                "-i",
                uplink,
                "-o",
                ap,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        )?;
        rule(
            "iptables",
            "filter",
            "FORWARD",
            ap,
            &["-i", ap, "-o", uplink, "-s", &subnet, "-j", "ACCEPT"],
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        // Retain the guards if setup fails, including on the standalone route CLI.
        if let Err(cleanup) = remove_owned(ap, true) {
            anyhow::bail!("{error:#}; rollback failed: {cleanup:#}");
        }
        return Err(error);
    }
    Ok(())
}

pub fn teardown_routing(ap: &str, _uplink: Option<&str>) -> Result<()> {
    if !ap.is_empty() {
        validate_interface(ap)?;
    }
    remove_owned(ap, false)
}

/// Describe configured dfnet rules, not a claim that every firewall backend was audited.
pub fn get_routing_status(ap: Option<&str>) -> RoutingStatus {
    let mut status = RoutingStatus {
        ip_forwarding_enabled: get_ip_forwarding(),
        mode: None,
        active_uplink: None,
        firewall_status: "No AP selected".into(),
        default_gateway: get_default_gateway_interface(),
    };
    let Some(ap) = ap else {
        return status;
    };
    let result = (|| -> Result<(String, String, String)> {
        Ok((
            run("iptables", &["-w", "5", "-S", "FORWARD"])?,
            run("ip6tables", &["-w", "5", "-S", "FORWARD"])?,
            run("iptables", &["-w", "5", "-t", "nat", "-S", "POSTROUTING"])?,
        ))
    })();
    match result {
        Err(e) => status.firewall_status = format!("Unknown: {e}"),
        Ok((v4, v6, nat)) => {
            let (mode, uplink) = configured_mode(ap, &v4, &v6, &nat);
            status.mode = mode;
            status.active_uplink = uplink;
            status.firewall_status = match mode {
                Some(HotspotRoutingMode::Isolated) => "IPv4/IPv6 forwarding guards configured",
                Some(HotspotRoutingMode::NatPassthrough)
                    if status.ip_forwarding_enabled == Some(true) =>
                {
                    "IPv4 NAT rules configured; IPv6 blocked"
                }
                Some(HotspotRoutingMode::NatPassthrough) => {
                    "NAT rules present; forwarding disabled or unknown"
                }
                None => "Unmanaged or incomplete dfnet rules",
            }
            .into();
        }
    }
    status
}

fn configured_mode(
    ap: &str,
    v4: &str,
    v6: &str,
    nat: &str,
) -> (Option<HotspotRoutingMode>, Option<String>) {
    let rules = |text: &str| {
        text.lines()
            .filter(|line| owned_rule(line, ap))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let v4 = rules(v4);
    let v6 = rules(v6);
    let has_drop = |rules: &[String], direction| {
        rules.iter().any(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            option(&parts, direction) == Some(ap) && option(&parts, "-j") == Some("DROP")
        })
    };
    if ![&v4, &v6]
        .iter()
        .all(|r| has_drop(r, "-i") && has_drop(r, "-o"))
    {
        return (None, None);
    }
    for line in &v4 {
        let parts: Vec<_> = line.split_whitespace().collect();
        if option(&parts, "-i") == Some(ap) && option(&parts, "-j") == Some("ACCEPT") {
            if let Some(up) = option(&parts, "-o") {
                let has_nat = rules(nat).iter().any(|line| {
                    let p: Vec<_> = line.split_whitespace().collect();
                    option(&p, "-o") == Some(up) && option(&p, "-j") == Some("MASQUERADE")
                });
                let has_return = v4.iter().any(|line| {
                    let p: Vec<_> = line.split_whitespace().collect();
                    option(&p, "-i") == Some(up)
                        && option(&p, "-o") == Some(ap)
                        && option(&p, "-j") == Some("ACCEPT")
                        && option(&p, "--ctstate").is_some_and(|states| {
                            let states: Vec<_> = states.split(',').collect();
                            states.contains(&"ESTABLISHED") && states.contains(&"RELATED")
                        })
                });
                if has_nat && has_return {
                    return (Some(HotspotRoutingMode::NatPassthrough), Some(up.into()));
                }
                return (None, None);
            }
        }
    }
    (Some(HotspotRoutingMode::Isolated), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ownership_is_exact() {
        let line = "-A FORWARD -i wlan01 -m comment --comment \"dfnet:wlan01\" -j DROP";
        assert!(!owned_rule(line, "wlan0"));
        assert!(owned_rule(line, "wlan01"));
        assert!(!owned_rule("-A FORWARD -i wlan0 -j DROP", "wlan0"));
    }
    #[test]
    fn status_requires_both_families_and_directions() {
        let drops = "-A FORWARD -i wlan0 -m comment --comment dfnet:wlan0 -j DROP\n-A FORWARD -o wlan0 -m comment --comment dfnet:wlan0 -j DROP";
        assert_eq!(configured_mode("wlan0", drops, "", "").0, None);
        assert_eq!(
            configured_mode("wlan0", drops, drops, "").0,
            Some(HotspotRoutingMode::Isolated)
        );
        assert_eq!(configured_mode("wlan01", drops, drops, "").0, None);
    }
    #[test]
    fn validates_interfaces_and_gateway() {
        for invalid in ["", "wlan+", "../x", "--help", "a b", "abcdefghijklmnop"] {
            assert!(validate_interface(invalid).is_err());
        }
        assert!(validate_interface("wlan0").is_ok());
        assert_eq!(
            parse_default_gateway_output("default via 192.0.2.1 dev eth0 metric 10"),
            Some("eth0".into())
        );
        assert_eq!(parse_default_gateway_output(""), None);
    }
}
