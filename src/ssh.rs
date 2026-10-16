//! `dfnet ssh`: a temporary SSH server into dfnix with a per-case key, for
//! working on a headless server from the examiner's laptop. dfnix runs no
//! SSH server otherwise.
//!
//! - A fresh host key per session; its fingerprint is printed, for the
//!   examiner to compare when connecting.
//! - Only the given public keys, only root, no passwords, no forwarding,
//!   bound to one address. The firewall opens that address and port and
//!   nothing else.
//! - sshd runs as a transient systemd unit (`dfnet-sshd`). `dfnet ssh stop`
//!   ends it, closes the port, deletes the host key and the keys, and records
//!   every accepted login in the audit log.

use crate::{audit, listen};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{
    net::{IpAddr, SocketAddr},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const UNIT: &str = "dfnet-sshd";
const TAG: &str = "dfnet-ssh:";

fn dir() -> PathBuf {
    std::env::var_os("DFNET_SSH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/dfnet/ssh"))
}

fn run(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Cannot run {program}"))?;
    if !out.status.success() {
        bail!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// sshd must be started by its absolute path
fn sshd_path() -> Result<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .map(|d| d.join("sshd"))
        .find(|p| p.is_file())
        .context("sshd is not installed (openssh)")
}

/// The sshd configuration of a session
pub fn config(listen: SocketAddr, dir: &Path) -> String {
    let d = dir.display();
    format!(
        "ListenAddress {listen}\n\
         HostKey {d}/host_ed25519_key\n\
         AuthorizedKeysFile {d}/authorized_keys\n\
         AuthenticationMethods publickey\n\
         PubkeyAuthentication yes\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         PermitEmptyPasswords no\n\
         PermitRootLogin prohibit-password\n\
         AllowUsers root\n\
         UsePAM no\n\
         X11Forwarding no\n\
         AllowAgentForwarding no\n\
         AllowTcpForwarding no\n\
         AllowStreamLocalForwarding no\n\
         PermitTunnel no\n\
         PermitUserEnvironment no\n\
         LogLevel VERBOSE\n\
         LoginGraceTime 30\n\
         MaxAuthTries 3\n\
         ClientAliveInterval 60\n\
         ClientAliveCountMax 3\n\
         PidFile {d}/sshd.pid\n\
         Subsystem sftp internal-sftp\n"
    )
}

/// `ssh-keygen -l` lines as fingerprints ("256 SHA256:… comment (ED25519)")
pub fn fingerprints(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let _bits = f.next()?;
            let fp = f.next()?;
            fp.starts_with("SHA256:").then(|| l.trim().to_string())
        })
        .collect()
}

/// "Accepted publickey for root from 10.0.0.2 port 51234 ssh2: ED25519 SHA256:…"
pub fn accepted_logins(journal: &str) -> Vec<String> {
    journal
        .lines()
        .filter_map(|l| {
            l.find("Accepted publickey for")
                .map(|i| l[i..].trim().to_string())
        })
        .collect()
}

fn unit_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", UNIT])
        .status()
        .is_ok_and(|s| s.success())
}

pub fn start(key_file: &Path, bind: IpAddr, port: u16) -> Result<()> {
    crate::receive::validate_bind(bind)?;
    // SAFETY: no arguments
    if unsafe { libc::geteuid() } != 0 {
        bail!("dfnet ssh needs root");
    }
    if unit_active() {
        bail!(
            "an SSH session is already open; `dfnet ssh status` shows it, `dfnet ssh stop` ends it"
        );
    }
    // What an earlier session that died may have left: a failed unit, a rule
    let _ = Command::new("systemctl")
        .args(["reset-failed", UNIT])
        .status();
    for r in listen::remove_tagged(TAG) {
        eprintln!("[*] Removed a stale firewall opening: {r}");
    }
    let listen = SocketAddr::new(bind, port);
    // The address must be this host's and the port free, or sshd would fail after we said "open"
    std::net::TcpListener::bind(listen).with_context(|| format!("cannot listen on {listen}"))?;
    let keys = fingerprints(
        &run("ssh-keygen", &["-l", "-f", &key_file.display().to_string()])
            .context("the key file holds no valid public key")?,
    );
    if keys.is_empty() {
        bail!("{} holds no public key", key_file.display());
    }
    let sshd = sshd_path()?;
    let d = dir();
    if d.exists() {
        std::fs::remove_dir_all(&d)?;
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&d)?;
    let write = |name: &str, data: &[u8]| -> Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(d.join(name))?;
        f.write_all(data)?;
        Ok(())
    };
    write("authorized_keys", &std::fs::read(key_file)?)?;
    run(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "dfnix-session",
            "-f",
            &d.join("host_ed25519_key").display().to_string(),
        ],
    )?;
    let host_fp = fingerprints(&run(
        "ssh-keygen",
        &[
            "-l",
            "-f",
            &d.join("host_ed25519_key.pub").display().to_string(),
        ],
    )?)
    .into_iter()
    .next()
    .unwrap_or_default();
    write("sshd_config", config(listen, &d).as_bytes())?;
    let cfg = d.join("sshd_config").display().to_string();
    run(&sshd.display().to_string(), &["-t", "-f", &cfg])
        .context("sshd rejects the configuration")?;

    let opening = listen::Opening::open(bind, port, &format!("{TAG}{port}"))?;
    let started = run(
        "systemd-run",
        &[
            "--unit",
            UNIT,
            "--description",
            "dfnet ssh: temporary SSH access with a per-case key",
            &sshd.display().to_string(),
            "-D",
            "-e",
            "-f",
            &cfg,
        ],
    );
    // systemd-run returns once sshd is spawned: wait until it really accepts
    let listening = started.and_then(|_| {
        for _ in 0..50 {
            let probe = std::time::Duration::from_millis(200);
            if std::net::TcpStream::connect_timeout(&listen, probe).is_ok() {
                return Ok(());
            }
            if !unit_active() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let log = run(
            "journalctl",
            &["-u", UNIT, "-o", "cat", "--no-pager", "-n", "5"],
        )
        .unwrap_or_default();
        bail!("sshd did not start listening on {listen}: {}", log.trim())
    });
    if let Err(e) = listening {
        let _ = Command::new("systemctl").args(["stop", UNIT]).status();
        let _ = Command::new("systemctl")
            .args(["reset-failed", UNIT])
            .status();
        let _ = opening.close();
        let _ = std::fs::remove_dir_all(&d);
        return Err(e);
    }
    let state = json!({
        "listen": listen.to_string(),
        "keys": keys,
        "host_key": host_fp,
        "firewall": opening.description,
        "started": dfcore::host::rfc3339_utc(dfcore::host::unix_now()),
    });
    write(
        "state.json",
        serde_json::to_string_pretty(&state)?.as_bytes(),
    )?;
    audit::record(
        audit::event("ssh_start")
            .detail("listen", listen.to_string())
            .detail("keys", json!(keys))
            .detail("host_key", host_fp.clone())
            .detail("firewall", opening.description.clone()),
    );
    println!("[✓] SSH open on {listen} for root with these keys only:");
    for k in &keys {
        println!("      {k}");
    }
    println!("[*] Host key (compare it when you connect): {host_fp}");
    println!(
        "[*] Connect: ssh root@{}{}",
        if bind.is_ipv6() {
            format!("[{bind}]")
        } else {
            bind.to_string()
        },
        if port == 22 {
            String::new()
        } else {
            format!(" -p {port}")
        }
    );
    println!("[*] End it with: dfnet ssh stop");
    Ok(())
}

pub fn stop() -> Result<()> {
    let d = dir();
    let state: Value = std::fs::read_to_string(d.join("state.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);
    let journal = run("journalctl", &["-u", UNIT, "-o", "cat", "--no-pager"]).unwrap_or_default();
    let logins = accepted_logins(&journal);
    if unit_active() {
        run("systemctl", &["stop", UNIT])?;
    }
    let _ = Command::new("systemctl")
        .args(["reset-failed", UNIT])
        .status();
    let closed = listen::remove_tagged(TAG);
    if d.exists() {
        std::fs::remove_dir_all(&d)?;
    }
    audit::record(
        audit::event("ssh_stop")
            .detail("session", state.clone())
            .detail("accepted_logins", json!(logins))
            .detail("firewall_closed", json!(closed)),
    );
    println!("[✓] SSH closed; host key and keys deleted");
    if logins.is_empty() {
        println!("[*] No login was accepted");
    }
    for l in &logins {
        println!("      {l}");
    }
    Ok(())
}

pub fn status() -> Result<()> {
    if !unit_active() {
        println!("[*] No SSH session is open");
        return Ok(());
    }
    let state = std::fs::read_to_string(dir().join("state.json")).unwrap_or_default();
    println!("[*] SSH session open:\n{state}");
    let journal = run("journalctl", &["-u", UNIT, "-o", "cat", "--no-pager"]).unwrap_or_default();
    for l in accepted_logins(&journal) {
        println!("      {l}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_is_key_only_and_bound() {
        let c = config("10.0.0.1:22".parse().unwrap(), Path::new("/run/dfnet/ssh"));
        assert!(c.starts_with("ListenAddress 10.0.0.1:22\n"));
        for line in [
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "AuthenticationMethods publickey",
            "AllowUsers root",
            "AllowTcpForwarding no",
            "AuthorizedKeysFile /run/dfnet/ssh/authorized_keys",
            "MaxAuthTries 3",
            "LoginGraceTime 30",
        ] {
            assert!(c.lines().any(|l| l == line), "{line}");
        }
        let c6 = config("[fe80::1%2]:2222".parse().unwrap(), Path::new("/x"));
        assert!(c6.starts_with("ListenAddress [fe80::1%2]:2222\n"), "{c6}");
    }

    #[test]
    fn parsing_keys_and_logins() {
        let l = "256 SHA256:abcd case-key (ED25519)\nnot a key\n3072 SHA256:efgh other (RSA)\n";
        assert_eq!(fingerprints(l).len(), 2);
        let j = "Server listening on 10.0.0.1 port 22.\n\
                 Accepted publickey for root from 10.0.0.2 port 51234 ssh2: ED25519 SHA256:abcd\n\
                 Connection closed by 10.0.0.9 port 40000 [preauth]\n";
        assert_eq!(
            accepted_logins(j),
            vec!["Accepted publickey for root from 10.0.0.2 port 51234 ssh2: ED25519 SHA256:abcd"]
        );
    }
}
