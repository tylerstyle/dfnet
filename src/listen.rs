//! Listening for inbound connections on dfnix, which keeps the NixOS firewall
//! on: dfnet opens exactly the bound address and port while it listens (one
//! ACCEPT rule at the top of INPUT, tagged as dfnet's) and removes it when it
//! stops. While nobody has connected yet, Ctrl-C stops the listener cleanly;
//! a rule left by a run that was killed later is removed at the next start.

use anyhow::{bail, Context, Result};
use std::{
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

/// Comment prefix of the rules a listener owns
pub const LISTEN_TAG: &str = "dfnet-listen:";

fn program(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() {
        "iptables"
    } else {
        "ip6tables"
    }
}

fn spec(ip: IpAddr, port: u16, tag: &str) -> Vec<String> {
    [
        "-p",
        "tcp",
        "-d",
        &ip.to_string(),
        "--dport",
        &port.to_string(),
        "-m",
        "comment",
        "--comment",
        tag,
        "-j",
        "ACCEPT",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn iptables(program: &str, args: &[&str]) -> Result<std::process::Output> {
    Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Cannot run {program}"))
}

/// An ACCEPT rule for one address and port, removed on drop (or by `close`)
pub struct Opening {
    program: &'static str,
    spec: Vec<String>,
    pub description: String,
}

impl Opening {
    /// Accept TCP to `ip:port`. `tag` names the owner, e.g.
    /// `dfnet-listen:stream:9998`.
    pub fn open(ip: IpAddr, port: u16, tag: &str) -> Result<Opening> {
        let program = program(ip);
        let spec = spec(ip, port, tag);
        let s: Vec<&str> = spec.iter().map(String::as_str).collect();
        let mut check = vec!["-w", "5", "-C", "INPUT"];
        check.extend(&s);
        let present = iptables(program, &check)?.status.success();
        if !present {
            let mut insert = vec!["-w", "5", "-I", "INPUT", "1"];
            insert.extend(&s);
            let out = iptables(program, &insert)?;
            if !out.status.success() {
                bail!(
                    "{program} could not open {ip}:{port}: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
        }
        Ok(Opening {
            program,
            description: format!("{program} -I INPUT {}", spec.join(" ")),
            spec,
        })
    }

    pub fn close(&self) -> Result<()> {
        let s: Vec<&str> = self.spec.iter().map(String::as_str).collect();
        let mut delete = vec!["-w", "5", "-D", "INPUT"];
        delete.extend(&s);
        let out = iptables(self.program, &delete)?;
        if !out.status.success() {
            bail!(
                "{} could not remove its rule: {}",
                self.program,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
}

/// Removes the rule when the listener ends normally or with an error
pub struct Guard(pub Option<Opening>);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(o) = self.0.take() {
            if let Err(e) = o.close() {
                eprintln!("[!] {e:#}");
            }
        }
    }
}

/// Rules whose comment starts with `prefix`, as `-S INPUT` lines
pub fn tagged_rules(listing: &str, prefix: &str) -> Vec<Vec<String>> {
    listing
        .lines()
        .filter_map(|l| {
            let parts: Vec<String> = l
                .split_whitespace()
                .map(|p| p.trim_matches('"').to_string())
                .collect();
            let i = parts.iter().position(|p| p == "--comment")?;
            (parts.first().map(String::as_str) == Some("-A")
                && parts.get(1).map(String::as_str) == Some("INPUT")
                && parts.get(i + 1).is_some_and(|c| c.starts_with(prefix)))
            .then(|| parts[2..].to_vec())
        })
        .collect()
}

/// Remove every INPUT rule tagged `prefix` (rules a killed run left behind)
pub fn remove_tagged(prefix: &str) -> Vec<String> {
    let mut removed = Vec::new();
    for program in ["iptables", "ip6tables"] {
        let Ok(out) = iptables(program, &["-w", "5", "-S", "INPUT"]) else {
            continue;
        };
        for rule in tagged_rules(&String::from_utf8_lossy(&out.stdout), prefix) {
            let mut delete = vec!["-w", "5", "-D", "INPUT"];
            delete.extend(rule.iter().map(String::as_str));
            if iptables(program, &delete).is_ok_and(|o| o.status.success()) {
                removed.push(format!("{program} {}", rule.join(" ")));
            }
        }
    }
    removed
}

/// Open the firewall for a listener: stale openings first, then this one.
/// Without iptables (not dfnix) the listener still works where nothing blocks.
pub fn open_for(addr: SocketAddr, owner: &str) -> Guard {
    // The firewall never filters loopback (NixOS trusts lo)
    if addr.ip().is_loopback() {
        return Guard(None);
    }
    // SAFETY: no arguments
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "[!] Not root: the firewall is left as it is; connections to {addr} may be dropped"
        );
        return Guard(None);
    }
    for r in remove_tagged(LISTEN_TAG) {
        eprintln!("[*] Removed a stale firewall opening: {r}");
    }
    let tag = format!("{LISTEN_TAG}{owner}:{}", addr.port());
    match Opening::open(addr.ip(), addr.port(), &tag) {
        Ok(o) => {
            println!("[*] Firewall: accepting TCP to {addr} while listening");
            Guard(Some(o))
        }
        Err(e) => {
            eprintln!("[!] Firewall not opened ({e:#}); connections may be dropped");
            Guard(None)
        }
    }
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Wait for a connection; Ctrl-C/SIGTERM while waiting returns an error, so
/// the caller unwinds and the firewall opening is removed. Once a connection
/// is accepted, the signals act as before (terminate).
pub fn accept(listener: &TcpListener) -> Result<(TcpStream, SocketAddr)> {
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: the handler only stores into an atomic
    let (old_int, old_term) = unsafe {
        (
            libc::signal(libc::SIGINT, handler),
            libc::signal(libc::SIGTERM, handler),
        )
    };
    listener.set_nonblocking(true)?;
    let result = loop {
        if STOP.load(Ordering::SeqCst) {
            break Err(anyhow::anyhow!("stopped while waiting for a connection"));
        }
        match listener.accept() {
            Ok((s, a)) => break Ok((s, a)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => break Err(e).context("accept"),
        }
    };
    let _ = listener.set_nonblocking(false);
    // SAFETY: restoring the previous dispositions
    unsafe {
        libc::signal(libc::SIGINT, old_int);
        libc::signal(libc::SIGTERM, old_term);
    }
    let (stream, addr) = result?;
    stream.set_nonblocking(false)?;
    Ok((stream, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_and_tags() {
        let s = spec(
            "10.0.0.1".parse().unwrap(),
            9998,
            "dfnet-listen:stream:9998",
        );
        assert_eq!(s.join(" "), "-p tcp -d 10.0.0.1 --dport 9998 -m comment --comment dfnet-listen:stream:9998 -j ACCEPT");
        assert_eq!(program("fe80::1".parse().unwrap()), "ip6tables");
        let listing = "-P INPUT ACCEPT\n\
            -A INPUT -d 10.0.0.1/32 -p tcp -m tcp --dport 9998 -m comment --comment \"dfnet-listen:stream:9998\" -j ACCEPT\n\
            -A INPUT -d 10.0.0.1/32 -p tcp -m tcp --dport 22 -m comment --comment \"dfnet-ssh:22\" -j ACCEPT\n\
            -A INPUT -j nixos-fw\n";
        let found = tagged_rules(listing, LISTEN_TAG);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].join(" "), "-d 10.0.0.1/32 -p tcp -m tcp --dport 9998 -m comment --comment dfnet-listen:stream:9998 -j ACCEPT");
        assert_eq!(tagged_rules(listing, "dfnet-ssh:").len(), 1);
    }

    #[test]
    fn accept_returns_a_connection() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || TcpStream::connect(addr).unwrap());
        let (s, _) = accept(&l).unwrap();
        assert!(!s.peer_addr().unwrap().ip().is_unspecified());
        t.join().unwrap();
    }
}
