use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, path::PathBuf, process::Command};

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
    run("sysctl", &["-n", "net.ipv4.ip_forward"])
        .ok()
        .or_else(|| std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").ok())
        .and_then(|s| match s.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        })
}

fn set_ip_forwarding(enabled: bool) -> Result<()> {
    let value = if enabled { "1" } else { "0" };
    run("sysctl", &["-w", &format!("net.ipv4.ip_forward={value}")])?;
    anyhow::ensure!(
        get_ip_forwarding() == Some(enabled),
        "net.ipv4.ip_forward did not change to {value}"
    );
    Ok(())
}

/// Global IPv4 address and prefix of an interface, from `ip -j -4 addr show dev`.
pub fn parse_global_ipv4(json: &str) -> Result<(Ipv4Addr, u8)> {
    let addresses: serde_json::Value = serde_json::from_str(json)?;
    let address = addresses
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|v| v["addr_info"].as_array().into_iter().flatten())
        .find(|v| v["scope"] == "global" && v["family"] != "inet6")
        .context("Interface has no global IPv4 address")?;
    let ip: Ipv4Addr = address["local"]
        .as_str()
        .context("Missing IPv4 address")?
        .parse()?;
    let prefix = address["prefixlen"]
        .as_u64()
        .filter(|p| *p <= 32)
        .context("Invalid IPv4 prefix")?;
    Ok((ip, prefix as u8))
}

pub fn interface_ipv4(iface: &str) -> Result<(Ipv4Addr, u8)> {
    validate_interface(iface)?;
    parse_global_ipv4(&run("ip", &["-j", "-4", "addr", "show", "dev", iface])?)
        .with_context(|| format!("No usable IPv4 address on {iface}"))
}

// NetworkManager's "shared" IPv4 method turns on net.ipv4.ip_forward for the whole
// host and leaves it on when the connection goes down. The value found before the
// first hotspot start is kept under /run (cleared on reboot, like the sysctl itself)
// so a later `hotspot stop`, possibly from another process, can put it back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ForwardingState {
    ap: String,
    ip_forward_before: bool,
}

fn state_path() -> PathBuf {
    std::env::var_os("DFNET_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/dfnet"))
        .join("ip_forward.json")
}

/// Record the pre-hotspot forwarding state. An existing record is kept: it holds the
/// value from before the first of several restarts.
pub fn remember_ip_forwarding(ap: &str) -> Result<()> {
    let path = state_path();
    if path.exists() {
        return Ok(());
    }
    let before = get_ip_forwarding().context("Cannot read net.ipv4.ip_forward")?;
    std::fs::create_dir_all(path.parent().expect("state path has a parent"))?;
    let state = ForwardingState {
        ap: ap.into(),
        ip_forward_before: before,
    };
    std::fs::write(&path, serde_json::to_vec(&state)?)
        .with_context(|| format!("Cannot record forwarding state in {}", path.display()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardingAction {
    Disable,
    Keep(String),
}

pub fn forwarding_action(
    before: Option<bool>,
    now: Option<bool>,
    other_shared: &[String],
) -> ForwardingAction {
    match (before, now) {
        (_, Some(false)) => ForwardingAction::Keep("IPv4 forwarding is disabled".into()),
        (Some(true), _) => {
            ForwardingAction::Keep("IPv4 forwarding was already enabled before the hotspot".into())
        }
        (Some(false), _) if !other_shared.is_empty() => ForwardingAction::Keep(format!(
            "IPv4 forwarding left enabled: shared connection(s) {} still active",
            other_shared.join(", ")
        )),
        (Some(false), _) => ForwardingAction::Disable,
        (None, _) => ForwardingAction::Keep(
            "IPv4 forwarding left as is: no state recorded before the hotspot started \
             (check `sysctl net.ipv4.ip_forward`)"
                .into(),
        ),
    }
}

/// Active NetworkManager connections other than ours that use IPv4 sharing.
fn other_shared_connections() -> Result<Vec<String>> {
    let active = run(
        "nmcli",
        &["-t", "-f", "NAME,UUID", "connection", "show", "--active"],
    )?;
    let mut shared = Vec::new();
    for line in active.lines() {
        let Some((name, uuid)) = line.rsplit_once(':') else {
            continue;
        };
        if name == "dfnet-hotspot" {
            continue;
        }
        let method = run("nmcli", &["-g", "ipv4.method", "connection", "show", uuid])?;
        if method.trim() == "shared" {
            shared.push(name.to_string());
        }
    }
    Ok(shared)
}

/// Put net.ipv4.ip_forward back to its pre-hotspot value. Call after the AP is down.
pub fn restore_ip_forwarding() -> Result<String> {
    let path = state_path();
    let before = match std::fs::read(&path) {
        Ok(bytes) => Some(
            serde_json::from_slice::<ForwardingState>(&bytes)
                .with_context(|| format!("Corrupt forwarding state {}", path.display()))?
                .ip_forward_before,
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("Cannot read {}", path.display())),
    };
    let now = get_ip_forwarding();
    let others = if before == Some(false) && now == Some(true) {
        other_shared_connections()?
    } else {
        Vec::new()
    };
    let message = match forwarding_action(before, now, &others) {
        ForwardingAction::Disable => {
            set_ip_forwarding(false)?;
            "IPv4 forwarding restored to disabled (net.ipv4.ip_forward=0).".to_string()
        }
        ForwardingAction::Keep(reason) => format!("{reason}."),
    };
    if before.is_some() {
        std::fs::remove_file(&path).with_context(|| format!("Cannot remove {}", path.display()))?;
    }
    Ok(message)
}

/// Remove the nftables table NetworkManager creates for a shared connection if it
/// outlived the connection. Absent `nft` means there is nothing of ours to check.
pub fn remove_stale_nm_shared_table(ap: &str) -> Result<Option<String>> {
    validate_interface(ap)?;
    let tables = match Command::new("nft").args(["list", "tables"]).output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("Cannot run nft"),
        Ok(out) => {
            anyhow::ensure!(
                out.status.success(),
                "nft list tables failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            String::from_utf8_lossy(&out.stdout).into_owned()
        }
    };
    let table = format!("nm-shared-{ap}");
    if !stale_shared_table(&tables, &table) {
        return Ok(None);
    }
    run("nft", &["delete", "table", "ip", &table])?;
    Ok(Some(format!("Removed leftover nftables table ip {table}.")))
}

fn stale_shared_table(nft_tables: &str, table: &str) -> bool {
    nft_tables.lines().any(|line| {
        let parts: Vec<_> = line.split_whitespace().collect();
        parts == ["table", "ip", table]
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
    let (ip, prefix) = interface_ipv4(ap).context("AP has no global IPv4 address")?;
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
    fn forwarding_is_only_disabled_when_we_turned_it_on() {
        use ForwardingAction::*;
        assert_eq!(forwarding_action(Some(false), Some(true), &[]), Disable);
        assert!(matches!(
            forwarding_action(Some(true), Some(true), &[]),
            Keep(_)
        ));
        assert!(matches!(
            forwarding_action(Some(false), Some(false), &[]),
            Keep(_)
        ));
        assert!(
            matches!(forwarding_action(None, Some(true), &[]), Keep(r) if r.contains("no state recorded"))
        );
        let other = vec!["Hotspot-eth1".to_string()];
        assert!(
            matches!(forwarding_action(Some(false), Some(true), &other), Keep(r) if r.contains("Hotspot-eth1"))
        );
        // Unknown current value with a recorded "off" still tries to switch it off
        assert_eq!(forwarding_action(Some(false), None, &[]), Disable);
    }

    #[test]
    fn nm_shared_table_match_is_exact() {
        let tables = "table inet filter\ntable ip nm-shared-wlan01\ntable ip nm-shared-wlan0\n";
        assert!(stale_shared_table(tables, "nm-shared-wlan0"));
        assert!(!stale_shared_table(
            "table ip nm-shared-wlan01\n",
            "nm-shared-wlan0"
        ));
        assert!(!stale_shared_table(
            "table inet nm-shared-wlan0\n",
            "nm-shared-wlan0"
        ));
    }

    #[test]
    fn parses_global_ipv4() {
        let json = r#"[{"ifname":"wlan0","addr_info":[
            {"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"},
            {"family":"inet","local":"10.42.0.1","prefixlen":24,"scope":"global"}]}]"#;
        assert_eq!(
            parse_global_ipv4(json).unwrap(),
            ("10.42.0.1".parse().unwrap(), 24)
        );
        assert!(parse_global_ipv4("[]").is_err());
        assert!(parse_global_ipv4(
            r#"[{"addr_info":[{"local":"10.0.0.1","prefixlen":40,"scope":"global"}]}]"#
        )
        .is_err());
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
