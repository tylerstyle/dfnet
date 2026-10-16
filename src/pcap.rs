//! `dfnet pcap`: capture network traffic at the scene with dumpcap into a
//! dfcore collection.
//!
//! - pcapng files of a fixed size; every file is hashed as soon as dumpcap
//!   closes it. Old files are never replaced (no ring of N files).
//! - The interface is recorded as it was: driver, link, addresses and the
//!   offloads (GRO/LRO coalesce received packets, so the capture no longer
//!   shows the frames as they were on the wire). GRO and LRO are switched off
//!   for the capture and restored afterwards. `--silent` also stops the
//!   interface from sending anything (ARP off, IPv6 off), for a SPAN port or
//!   a tap.
//! - dumpcap's and the kernel's drop counters are recorded. Packets dropped
//!   by the capture make it incomplete (exit 7).
//! - The capture stops at `--duration`, on Ctrl-C or SIGTERM, or when the
//!   target is nearly full.

use anyhow::{bail, Context, Result};
use dfcore::manifest::{
    Case, Clocks, Collection, Completion, FootprintEntry, Header, Item, ItemStatus, Method, Scope,
    Source,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

/// Stop when less than this is free on the target
const MIN_FREE: u64 = 512 << 20;
/// Time dumpcap gets to close its file after SIGINT before it is killed
const GRACE: Duration = Duration::from_secs(10);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

pub struct Options<'a> {
    pub iface: &'a str,
    pub output: &'a Path,
    pub case: Case,
    pub legal_basis: Option<String>,
    pub filter: Option<String>,
    pub file_size_mib: u64,
    pub duration: Option<u64>,
    pub snaplen: Option<u32>,
    pub promiscuous: bool,
    pub silent: bool,
    pub keep_offloads: bool,
    pub allow_tmpfs: bool,
}

fn run_cmd(program: &str, args: &[&str]) -> Value {
    match Command::new(program).args(args).output() {
        Ok(o) => json!({
            "command": format!("{program} {}", args.join(" ")),
            "exit": o.status.code(),
            "stdout": String::from_utf8_lossy(&o.stdout).trim_end(),
            "stderr": String::from_utf8_lossy(&o.stderr).trim_end(),
        }),
        Err(e) => {
            json!({ "command": format!("{program} {}", args.join(" ")), "error": e.to_string() })
        }
    }
}

fn ok(v: &Value) -> bool {
    v["exit"] == 0
}

fn sysfs(iface: &str, attr: &str) -> Option<String> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/{attr}"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// The interface counters that show packets lost before dumpcap saw them
fn counters(iface: &str) -> Value {
    let mut m = serde_json::Map::new();
    for c in [
        "rx_packets",
        "rx_bytes",
        "rx_dropped",
        "rx_missed_errors",
        "rx_fifo_errors",
        "rx_over_errors",
        "rx_errors",
    ] {
        m.insert(
            c.into(),
            json!(sysfs(iface, &format!("statistics/{c}")).and_then(|v| v.parse::<u64>().ok())),
        );
    }
    Value::Object(m)
}

/// `ethtool -k` lines as {feature: on/off}
pub fn parse_features(text: &str) -> serde_json::Map<String, Value> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let (k, v) = l.trim().split_once(':')?;
            let v = v.split_whitespace().next()?;
            Some((k.trim().to_string(), json!(v)))
        })
        .collect()
}

/// dumpcap's closing statistics: (captured, received, dropped)
pub fn parse_stats(stderr: &str) -> (Option<u64>, Option<u64>, Option<u64>) {
    let mut captured = None;
    let (mut received, mut dropped) = (None, None);
    // dumpcap updates its running count with carriage returns
    for l in stderr.split(['\n', '\r']) {
        if let Some(n) = l.trim().strip_prefix("Packets captured:") {
            captured = n.trim().parse().ok();
        }
        // Packets received/dropped on interface 'eth0': 100/2 (pcap:2/dumpcap:0/flushed:0/ps_ifdrop:0) (98.0%)
        if let Some(rest) = l
            .trim()
            .strip_prefix("Packets received/dropped on interface")
        {
            if let Some((_, nums)) = rest.split_once("':") {
                let first = nums.split_whitespace().next().unwrap_or("");
                if let Some((r, d)) = first.split_once('/') {
                    received = r.parse().ok();
                    dropped = d.parse().ok();
                }
                // The total counts pcap's, dumpcap's and flushed drops; packets the
                // interface dropped before pcap (ps_ifdrop) come on top
                if let Some(inner) = nums.split('(').nth(1) {
                    let ifdrop: u64 = inner
                        .trim_end_matches([')', ' '])
                        .split('/')
                        .filter_map(|p| p.strip_prefix("ps_ifdrop:")?.parse::<u64>().ok())
                        .sum();
                    dropped = Some(dropped.unwrap_or(0) + ifdrop);
                }
            }
        }
    }
    (captured, received, dropped)
}

fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: zeroed statvfs is a valid out-parameter
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid C string and out-pointer
    (unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0)
        .then(|| s.f_bavail as u64 * s.f_frsize as u64)
}

/// Stop dumpcap if it is still running: SIGINT, then SIGKILL after the grace
/// period. A child that was already reaped is left alone.
fn stop_child(child: &mut std::process::Child, pid: libc::pid_t) {
    if !matches!(child.try_wait(), Ok(None)) {
        return;
    }
    // SAFETY: signalling our own child, not reaped yet (try_wait said running)
    unsafe {
        libc::kill(pid, libc::SIGINT);
    }
    let deadline = Instant::now() + GRACE;
    while Instant::now() < deadline {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn sha256_file(path: &Path) -> Result<(u64, String)> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n_total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        n_total += n as u64;
    }
    Ok((n_total, format!("{:x}", h.finalize())))
}

struct Changes {
    iface: String,
    restore: Vec<(String, Vec<String>)>,
}

impl Changes {
    fn apply(
        &mut self,
        c: &mut Collection,
        program: &str,
        args: &[&str],
        undo: &[&str],
    ) -> Result<()> {
        let r = run_cmd(program, args);
        // The undo is kept before anything else can fail
        if ok(&r) {
            self.restore.push((
                program.to_string(),
                undo.iter().map(|s| s.to_string()).collect(),
            ));
        }
        c.footprint(FootprintEntry::new("interface_change", r.clone()))?;
        if !ok(&r) {
            bail!("{} failed: {}", r["command"], r["stderr"]);
        }
        Ok(())
    }

    /// Undo every change, newest first; a failing record (a full target)
    /// never stops the remaining undos and is reported afterwards.
    fn restore(self, c: &mut Collection) -> Result<()> {
        let mut first_error = None;
        for (program, args) in self.restore.into_iter().rev() {
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            let r = run_cmd(&program, &a);
            if !ok(&r) {
                eprintln!("[!] Could not restore {}: {}", self.iface, r["stderr"]);
            }
            if let Err(e) = c.footprint(FootprintEntry::new("interface_restore", r)) {
                first_error.get_or_insert(e);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

pub fn run(opts: Options) -> Result<u8> {
    let iface = opts.iface;
    crate::routing::validate_interface(iface)?;
    if iface == "." || iface == ".." || !Path::new(&format!("/sys/class/net/{iface}")).exists() {
        bail!("{iface}: no such network interface");
    }
    let output = crate::stream::check_output(opts.output, opts.allow_tmpfs)?;
    let dumpcap_version = run_cmd("dumpcap", &["-v"]);
    if dumpcap_version.get("error").is_some() {
        bail!("dumpcap is not installed (it comes with Wireshark/tshark)");
    }
    let features_before = run_cmd("ethtool", &["-k", iface]);
    let features = parse_features(features_before["stdout"].as_str().unwrap_or(""));
    let addresses = run_cmd("ip", &["-j", "addr", "show", "dev", iface]);
    let has_ipv4 = addresses["stdout"]
        .as_str()
        .is_some_and(|s| s.contains("\"family\":\"inet\""));
    if opts.silent && has_ipv4 {
        return Err(dfcore::Refusal(format!(
            "{iface} has IPv4 addresses; --silent captures on an interface without any (remove them or use a dedicated port)"
        ))
        .into());
    }
    let identity = json!({
        "interface": iface,
        "mac": sysfs(iface, "address"),
        "mtu": sysfs(iface, "mtu"),
        "operstate": sysfs(iface, "operstate"),
        "speed_mbps": sysfs(iface, "speed"),
        "driver": run_cmd("ethtool", &["-i", iface]),
        "link": run_cmd("ethtool", &[iface]),
        "addresses": serde_json::from_str::<Value>(addresses["stdout"].as_str().unwrap_or("null")).unwrap_or(Value::Null),
        "offloads": features,
        "dumpcap": dumpcap_version["stdout"].as_str().and_then(|s| s.lines().next()).map(str::to_string),
    });

    let file_kib = opts.file_size_mib.max(1) * 1024;
    let mut args: Vec<String> = vec![
        "-i".into(),
        iface.into(),
        "-w".into(),
        output.join("capture.pcapng").display().to_string(),
        "-b".into(),
        format!("filesize:{file_kib}"),
        "-b".into(),
        "printname:stdout".into(),
    ];
    if let Some(f) = &opts.filter {
        args.extend(["-f".into(), f.clone()]);
    }
    if let Some(d) = opts.duration {
        args.extend(["-a".into(), format!("duration:{d}")]);
    }
    if let Some(s) = opts.snaplen {
        args.extend(["-s".into(), s.to_string()]);
    }
    if !opts.promiscuous {
        args.push("-p".into());
    }

    let header = Header {
        action: "network_capture".into(),
        case: opts.case.clone(),
        source: Source {
            kind: "network-interface".into(),
            locator: format!(
                "{iface} ({})",
                sysfs(iface, "address").unwrap_or_else(|| "no MAC".into())
            ),
            identity: identity.clone(),
            details: json!({ "filter": opts.filter, "snaplen": opts.snaplen, "promiscuous": opts.promiscuous, "silent": opts.silent }),
        },
        method: Method {
            tool: crate::audit::TOOL.into(),
            tool_version: crate::audit::VERSION.into(),
            system_revision: dfcore::release::system_revision(),
            argv: std::env::args().collect(),
            read_only_primitives: vec![
                "passive capture with dumpcap; with --silent the interface sends nothing (ARP and IPv6 off)".into(),
            ],
            description: Some(format!(
                "dumpcap {} into pcapng files of {} MiB, each hashed when closed; GRO/LRO off during the capture \
                 unless --keep-offloads; drop counters of dumpcap and the interface recorded",
                args.join(" "),
                opts.file_size_mib
            )),
        },
        scope: Scope {
            legal_basis: opts.legal_basis.clone(),
            ..Scope::default()
        },
        clocks: Clocks::default(),
    };
    let mut collection = Collection::create(&output, header)?;

    let mut changes = Changes {
        iface: iface.to_string(),
        restore: Vec::new(),
    };
    let prepared = (|| -> Result<()> {
        if !opts.keep_offloads {
            for f in ["generic-receive-offload", "large-receive-offload"] {
                if features.get(f).and_then(Value::as_str) == Some("on") {
                    let short = if f.starts_with("generic") {
                        "gro"
                    } else {
                        "lro"
                    };
                    changes.apply(
                        &mut collection,
                        "ethtool",
                        &["-K", iface, short, "off"],
                        &["-K", iface, short, "on"],
                    )?;
                }
            }
        }
        if opts.silent {
            let key = format!("net.ipv6.conf.{iface}.disable_ipv6");
            let before = run_cmd("sysctl", &["-n", &key]);
            let was = before["stdout"].as_str().unwrap_or("0").trim().to_string();
            let undo = format!("{key}={was}");
            changes.apply(
                &mut collection,
                "sysctl",
                &["-w", &format!("{key}=1")],
                &["-w", &undo],
            )?;
            if sysfs(iface, "flags")
                .and_then(|f| u32::from_str_radix(f.trim_start_matches("0x"), 16).ok())
                .is_some_and(|f| f & 0x80 == 0)
            {
                // IFF_NOARP is clear: ARP is on
                changes.apply(
                    &mut collection,
                    "ip",
                    &["link", "set", iface, "arp", "off"],
                    &["link", "set", iface, "arp", "on"],
                )?;
            }
            if sysfs(iface, "operstate").as_deref() == Some("down") {
                changes.apply(
                    &mut collection,
                    "ip",
                    &["link", "set", iface, "up"],
                    &["link", "set", iface, "down"],
                )?;
            }
        }
        Ok(())
    })();
    if let Err(e) = prepared {
        let restored = changes.restore(&mut collection);
        let reason = format!("{e:#}");
        collection.finish(Completion::Aborted {
            reason: reason.clone(),
        })?;
        restored?;
        bail!(reason);
    }
    let counters_before = counters(iface);

    // SAFETY: the handler only stores into an atomic
    unsafe {
        libc::signal(
            libc::SIGINT,
            on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
    }
    let started = dfcore::host::rfc3339_utc_ns(dfcore::host::unix_now_ns());
    let mut child = match Command::new("dumpcap")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let restored = changes.restore(&mut collection);
            let reason = format!("Cannot start dumpcap: {e}");
            collection.finish(Completion::Aborted {
                reason: reason.clone(),
            })?;
            restored?;
            bail!(reason);
        }
    };
    let child_pid = child.id() as libc::pid_t;

    let mut hashed: BTreeSet<PathBuf> = BTreeSet::new();
    let mut tally = (0u64, 0u64);
    let mut stop_reason: Option<String> = None;
    let mut signalled = false;
    // Everything that can fail while dumpcap runs; on failure dumpcap is
    // stopped, the interface restored and the collection aborted below
    let capture = (|| -> Result<(std::process::ExitStatus, std::thread::JoinHandle<String>)> {
        collection.footprint(FootprintEntry::new(
            "capture_start",
            json!({ "command": format!("dumpcap {}", args.join(" ")), "pid": child_pid, "started": started }),
        ))?;
        println!(
            "[*] Capturing on {iface} -> {} (Ctrl-C stops)",
            output.display()
        );
        let (tx, rx) = mpsc::channel::<String>();
        let stdout = child.stdout.take().context("dumpcap stdout")?;
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut stderr = child.stderr.take().context("dumpcap stderr")?;
        let err_thread = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            s
        });
        let mut add = |collection: &mut Collection, path: &Path| -> Result<()> {
            if !hashed.insert(path.to_path_buf()) {
                return Ok(());
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut item = match sha256_file(path) {
                Ok((bytes, sha)) => {
                    tally.0 += 1;
                    tally.1 += bytes;
                    let mut i = Item::new(ItemStatus::Acquired, name.clone());
                    i.size = Some(bytes);
                    i.hashes.sha256 = Some(sha);
                    i
                }
                Err(e) => {
                    let mut i = Item::new(ItemStatus::Error, name.clone());
                    i.reason = Some(format!("cannot hash: {e}"));
                    i
                }
            };
            item.kind = Some("pcapng".into());
            item.stored_as = Some(name);
            collection.add(item)?;
            Ok(())
        };
        let mut signalled_at: Option<Instant> = None;
        let status = loop {
            // One file per turn at most; stop, space and exit are checked every turn
            if let Ok(line) = rx.recv_timeout(Duration::from_millis(500)) {
                let p = PathBuf::from(line.trim());
                if p.starts_with(&output) && p.is_file() {
                    add(&mut collection, &p)?;
                }
            }
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if signalled_at.is_some_and(|t| t.elapsed() > GRACE) {
                eprintln!(
                    "[!] dumpcap did not stop within {} s; killing it",
                    GRACE.as_secs()
                );
                let _ = child.kill();
                signalled_at = None;
            }
            if !signalled {
                if STOP.load(Ordering::SeqCst) {
                    stop_reason = Some("stopped by the examiner (signal)".into());
                } else if free_bytes(&output).is_some_and(|f| f < MIN_FREE) {
                    stop_reason = Some(format!(
                        "stopped: less than {} MiB free on the target",
                        MIN_FREE >> 20
                    ));
                }
                if stop_reason.is_some() {
                    // SAFETY: signalling our own child, not reaped yet (try_wait said running)
                    unsafe {
                        libc::kill(child_pid, libc::SIGINT);
                    }
                    signalled = true;
                    signalled_at = Some(Instant::now());
                }
            }
        };
        // Ctrl-C reaches dumpcap directly too; it may have exited before the loop saw it
        if STOP.load(Ordering::SeqCst) {
            signalled = true;
            stop_reason.get_or_insert_with(|| "stopped by the examiner (signal)".into());
        }
        // Lines printed just before dumpcap exited
        while let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
            let p = PathBuf::from(line.trim());
            if p.starts_with(&output) && p.is_file() {
                add(&mut collection, &p)?;
            }
        }
        // Any capture file dumpcap wrote but did not name
        let mut rest: Vec<PathBuf> = std::fs::read_dir(&output)?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "pcapng"))
            .collect();
        rest.sort();
        for p in rest {
            add(&mut collection, &p)?;
        }
        Ok((status, err_thread))
    })();
    let (status, err_thread) = match capture {
        Ok(v) => v,
        Err(e) => {
            stop_child(&mut child, child_pid);
            let restored = changes.restore(&mut collection);
            let reason = format!("{e:#}");
            collection.finish(Completion::Aborted {
                reason: reason.clone(),
            })?;
            restored?;
            bail!(reason);
        }
    };
    let stderr_text = err_thread.join().unwrap_or_default();
    let finished = dfcore::host::rfc3339_utc_ns(dfcore::host::unix_now_ns());
    let counters_after = counters(iface);
    let (captured, received, dropped) = parse_stats(&stderr_text);
    let delta = |k: &str| -> Option<u64> {
        Some(
            counters_after[k]
                .as_u64()?
                .saturating_sub(counters_before[k].as_u64()?),
        )
    };
    let hw_lost = ["rx_missed_errors", "rx_fifo_errors", "rx_over_errors"]
        .iter()
        .filter_map(|k| delta(k))
        .sum::<u64>();
    let recorded = collection.footprint(FootprintEntry::new(
        "capture_stop",
        json!({
            "finished": finished,
            "exit": status.code(),
            "reason": stop_reason,
            "packets_captured": captured,
            "packets_received": received,
            "packets_dropped": dropped,
            "interface_before": counters_before,
            "interface_after": counters_after,
            "interface_rx_dropped_delta": delta("rx_dropped"),
            "interface_hardware_lost": hw_lost,
            "dumpcap_stderr": stderr_text.lines().rev().take(20).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>(),
        }),
    ));
    let restored = changes.restore(&mut collection);
    recorded?;
    restored?;

    let mut problems = Vec::new();
    if dropped.unwrap_or(0) > 0 {
        problems.push(format!(
            "{} packets dropped during the capture (dumpcap)",
            dropped.unwrap_or(0)
        ));
    }
    if hw_lost > 0 {
        problems.push(format!(
            "{hw_lost} packets lost by the network card (missed/FIFO/overrun)"
        ));
    }
    let failed = !(status.success() || signalled);
    if failed {
        problems.push(format!(
            "dumpcap exited with {:?}: {}",
            status.code(),
            stderr_text.lines().last().unwrap_or("")
        ));
    }
    for p in &problems {
        collection.error(p.clone());
    }
    let done = collection.finish(Completion::Done { errors: vec![] })?;
    for w in &done.warnings {
        eprintln!("[!] WARNING: {w}");
    }
    println!(
        "[*] {} file(s), {} bytes, {} packets captured, {} dropped -> {}",
        tally.0,
        tally.1,
        captured.map_or("?".into(), |c| c.to_string()),
        dropped.map_or("?".into(), |d| d.to_string()),
        output.display()
    );
    for p in &problems {
        eprintln!("[!] {p}");
    }
    Ok(if failed {
        6
    } else if tally.0 == 0 {
        4
    } else if !problems.is_empty() {
        7
    } else {
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dumpcap_statistics() {
        let err = "Capturing on 'eth1'\nFile: /out/capture_00001_20261016.pcapng\nPackets captured: 1234\n\
                   Packets received/dropped on interface 'eth1': 1234/5 (pcap:5/dumpcap:2/flushed:0/ps_ifdrop:1) (99.6%)\n";
        assert_eq!(parse_stats(err), (Some(1234), Some(1234), Some(6)));
        let clean = "Packets captured: 10\nPackets received/dropped on interface 'eth1': 10/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)\n";
        assert_eq!(parse_stats(clean), (Some(10), Some(10), Some(0)));
        assert_eq!(parse_stats("nothing"), (None, None, None));
        let live = "Capturing on 'eth1'\n\rPackets: 1 \rPackets: 3027 \rPackets captured: 3027\n\
                    Packets received/dropped on interface 'eth1': 3027/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)\n";
        assert_eq!(parse_stats(live), (Some(3027), Some(3027), Some(0)));
    }

    #[test]
    fn ethtool_features() {
        let text = "Features for eth1:\nrx-checksumming: on\ngeneric-receive-offload: on\nlarge-receive-offload: off [fixed]\n";
        let f = parse_features(text);
        assert_eq!(f["generic-receive-offload"], "on");
        assert_eq!(f["large-receive-offload"], "off");
        assert!(!f.contains_key("Features for eth1"));
    }
}
