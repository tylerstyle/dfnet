//! `dfnet stream`: receive authenticated, encrypted streams (dfstream/1) from
//! `dflive send` on a running system.
//!
//! dfnet shows a pairing code; the sender types it. The pairing (SPAKE2)
//! proves both sides know the code without revealing it; everything after is
//! encrypted and authenticated. Each stream is written to its own file and
//! recorded as an item of a dfcore collection with the sender's and the
//! receiver's SHA-256. A stream counts only when the sender's END arrived and
//! byte counts and hashes match. Each file is written as `*.incomplete` and
//! renamed to `.raw` only then, so no interruption leaves a `.raw` behind.

use anyhow::{Context, Result};
use dfcore::manifest::{
    Case, Clocks, Collection, Completion, FootprintEntry, Header, Item, ItemStatus, Method, Scope,
    Source, SourceClock, SourceHash,
};
use dfstream::{Channel, Hello, Role, Start, BYE, HELLO, START};
use serde_json::{json, Value};
use std::{
    io::BufWriter,
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::Duration,
};

const TMPFS_MAGIC: u64 = 0x0102_1994;
const RAMFS_MAGIC: u64 = 0x8584_58f6;
/// Failed pairings before the code is replaced
const ATTEMPTS: u32 = 3;
/// A connection must finish pairing within this time
const PAIRING_TIMEOUT: Duration = Duration::from_secs(20);

pub struct Options<'a> {
    pub bind: SocketAddr,
    pub output: &'a Path,
    pub case: Case,
    pub allow_tmpfs: bool,
    pub timeout: Duration,
}

fn statfs_magic(path: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: zeroed statfs is a valid out-parameter
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid C string and out-pointer
    if unsafe { libc::statfs(c.as_ptr(), &mut sfs) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Cannot stat the filesystem of {}", path.display()));
    }
    Ok(sfs.f_type as u64)
}

/// The output directory must be new or empty and not in RAM.
fn check_output(output: &Path, allow_tmpfs: bool) -> Result<PathBuf> {
    let output = std::path::absolute(output)?;
    if output.exists() && std::fs::read_dir(&output)?.next().is_some() {
        return Err(dfcore::Refusal(format!(
            "{} is not empty; choose a new directory",
            output.display()
        ))
        .into());
    }
    let ancestor = dfcore::sysfs::existing_ancestor(&output);
    if matches!(statfs_magic(&ancestor)?, TMPFS_MAGIC | RAMFS_MAGIC) && !allow_tmpfs {
        return Err(dfcore::Refusal(format!(
            "{} is in RAM (tmpfs) and is lost at power-off; choose a target drive or pass --allow-tmpfs",
            output.display()
        ))
        .into());
    }
    Ok(output)
}

/// The file a stream is written to: `<id>-<sanitized name>.raw`.
fn file_name(id: u32, name: &str) -> String {
    format!("{id:03}-{}.raw", dfstream::sanitize_name(name))
}

fn create_new(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .mode(0o600)
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("Cannot create {}", path.display()))
}

/// What one session delivered.
#[derive(Default)]
struct Tally {
    complete: u64,
    incomplete: u64,
    mismatch: u64,
    /// Complete streams in which the sender zero-filled unreadable areas
    with_read_errors: u64,
}

fn receive_one(
    ch: &mut Channel<TcpStream>,
    start: Start,
    output: &Path,
    collection: &mut Collection,
    peer: &str,
    tally: &mut Tally,
) -> Result<bool> {
    // The file carries `.incomplete` until the stream is complete and synced,
    // so an interruption of any kind never leaves a `.raw` that is not
    let name = file_name(start.id, &start.name);
    let partial = format!("{name}.incomplete");
    let partial_path = output.join(&partial);
    let mut sink = BufWriter::new(create_new(&partial_path)?);
    let announced = start.clone();
    let received = dfstream::receive_stream(ch, start, &mut sink);
    let synced = sink
        .into_inner()
        .map_err(|e| anyhow::Error::from(e.into_error()))
        .and_then(|f| f.sync_all().map_err(Into::into));
    let got = match (received, synced) {
        (Ok(got), Ok(())) => got,
        (Err(e), _) | (_, Err(e)) => {
            // Storing failed (e.g. the target is full): record it, end the session
            tally.incomplete += 1;
            let mut item = Item::new(ItemStatus::Error, announced.name.clone());
            item.kind = Some(announced.kind.clone());
            item.stored_as = Some(partial);
            item.reason = Some(format!("storing the stream failed: {e:#}"));
            item.metadata = json!({ "stream": announced, "peer": peer });
            collection.add(item)?;
            collection.error(format!("stream {}: storing failed: {e:#}", announced.id));
            return Ok(false);
        }
    };
    let status = got.status();
    let mut item = Item::new(
        if status == "complete" {
            ItemStatus::Acquired
        } else {
            ItemStatus::Error
        },
        got.start
            .source
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or(&got.start.name)
            .to_string(),
    );
    item.kind = Some(got.start.kind.clone());
    item.size = Some(got.bytes);
    item.hashes.sha256 = Some(got.sha256.clone());
    item.stored_as = Some(partial.clone());
    if let Some(end) = &got.end {
        item.source_hash = Some(SourceHash {
            algorithm: "sha256 (sender)".into(),
            value: end.sha256.clone(),
            matches: end.sha256 == got.sha256,
        });
    }
    item.metadata = json!({
        "stream": got.start,
        "end": got.end,
        "peer": peer,
        "status": status,
    });
    match status {
        "complete" => {
            let final_path = output.join(&name);
            anyhow::ensure!(
                !final_path.exists(),
                "{} exists already",
                final_path.display()
            );
            std::fs::rename(&partial_path, final_path)?;
            item.stored_as = Some(name.clone());
            tally.complete += 1;
            if let Some(end) = got.end.as_ref().filter(|e| !e.read_errors.is_empty()) {
                tally.with_read_errors += 1;
                let bytes: u64 = end.read_errors.iter().map(|e| e.length).sum();
                item.reason = Some(format!(
                    "the sender replaced {} unreadable area(s), {bytes} bytes, by zeros",
                    end.read_errors.len()
                ));
                collection.error(format!(
                    "stream {}: {} unreadable area(s) zero-filled by the sender",
                    got.start.id,
                    end.read_errors.len()
                ));
            }
        }
        other => {
            if other == "mismatch" {
                tally.mismatch += 1;
            } else {
                tally.incomplete += 1;
            }
            item.reason = Some(match (&got.end, &got.broken) {
                (None, Some(why)) => format!("the stream broke off: {why}"),
                (Some(end), _) if end.stopped.is_some() => {
                    format!(
                        "the sender stopped: {}",
                        end.stopped.as_deref().unwrap_or("")
                    )
                }
                (Some(_), _) => "byte count or SHA-256 differs between sender and receiver".into(),
                (None, None) => "the stream ended without the sender's END".into(),
            });
        }
    }
    collection.add(item)?;
    // The session goes on only while the connection is intact
    Ok(got.end.is_some())
}

fn session(
    mut ch: Channel<TcpStream>,
    output: &Path,
    collection: &mut Collection,
    peer: &str,
) -> Result<Tally> {
    let mut tally = Tally::default();
    let hello: Hello = ch.recv_json(HELLO).context("the sender's HELLO")?;
    let local = dfcore::host::unix_now_ns();
    if let Ok(clock) = SourceClock::new(&hello.clock, "dflive HELLO", local) {
        collection.set_source_clock(clock)?;
    }
    collection.set_source_identity(json!({
        "peer": peer,
        "session": ch.session_id,
        "sender": hello,
    }))?;
    loop {
        let (ty, payload) = match ch.recv() {
            Ok(f) => f,
            Err(e) => {
                collection.error(format!("the session ended without BYE: {e:#}"));
                break;
            }
        };
        match ty {
            START => {
                let start: Start = serde_json::from_slice(&payload)?;
                if !receive_one(&mut ch, start, output, collection, peer, &mut tally)? {
                    collection.error("the session broke off inside a stream".to_string());
                    break;
                }
            }
            BYE => break,
            other => {
                collection.error(format!("unexpected frame type {other}; session ended"));
                break;
            }
        }
    }
    Ok(tally)
}

/// Listen, pair, receive one session. Returns the exit code (dfdisk's scheme:
/// 0 all streams complete, 5 a hash mismatch, 6 incomplete, 4 nothing arrived).
pub fn run(opts: Options) -> Result<u8> {
    crate::receive::validate_bind(opts.bind.ip())?;
    let output = check_output(opts.output, opts.allow_tmpfs)?;
    let listener = TcpListener::bind(opts.bind).context("Cannot bind the receiver")?;
    let local = listener.local_addr()?;
    let header = Header {
        action: "stream_receive".into(),
        case: opts.case,
        source: Source {
            kind: "dfstream".into(),
            locator: format!("dfstream/1 on {local}"),
            ..Source::default()
        },
        method: Method {
            tool: crate::audit::TOOL.into(),
            tool_version: crate::audit::VERSION.into(),
            system_revision: dfcore::release::system_revision(),
            argv: std::env::args().collect(),
            read_only_primitives: vec![
                "the sender reads the source; see the sender's record".into()
            ],
            description: Some(
                "dfstream/1: SPAKE2 pairing on a one-time code, ChaCha20-Poly1305 frames; \
                 each stream hashed by the sender and the receiver"
                    .into(),
            ),
        },
        scope: Scope::default(),
        clocks: Clocks::default(),
    };
    let mut collection = Collection::create(&output, header)?;
    let mut code = dfstream::pairing_code()?;
    println!("[*] Listening on {local} -> {}", output.display());
    println!(
        "[*] Pairing code: {}   (on the suspect system: dflive send <source> --to {local})",
        dfstream::display_code(&code)
    );
    let mut failures = 0u32;
    let tally = loop {
        let (conn, peer) = listener.accept().context("accept")?;
        conn.set_read_timeout(Some(PAIRING_TIMEOUT))?;
        conn.set_write_timeout(Some(PAIRING_TIMEOUT))?;
        let peer = peer.to_string();
        match dfstream::handshake(conn, &code, Role::Receiver) {
            Ok(ch) => {
                ch.get_ref().set_read_timeout(Some(opts.timeout))?;
                ch.get_ref().set_write_timeout(Some(opts.timeout))?;
                collection.footprint(FootprintEntry::new(
                    "connect",
                    json!({ "peer": peer, "paired": true, "session": ch.session_id }),
                ))?;
                println!("[✓] Paired with {peer}");
                break session(ch, &output, &mut collection, &peer)?;
            }
            Err(e) => {
                failures += 1;
                collection.footprint(FootprintEntry::new(
                    "connect",
                    json!({ "peer": peer, "paired": false, "error": format!("{e:#}") }),
                ))?;
                eprintln!("[!] Pairing with {peer} failed: {e:#}");
                if failures >= ATTEMPTS {
                    code = dfstream::pairing_code()?;
                    failures = 0;
                    println!(
                        "[*] {ATTEMPTS} failed pairings: new pairing code {}",
                        dfstream::display_code(&code)
                    );
                }
            }
        }
    };
    let finished = collection.finish(Completion::Done { errors: vec![] })?;
    for w in &finished.warnings {
        eprintln!("[!] WARNING: {w}");
    }
    println!(
        "[*] {} stream(s) complete ({} with zero-filled read errors), {} incomplete, {} mismatched -> {}",
        tally.complete,
        tally.with_read_errors,
        tally.incomplete,
        tally.mismatch,
        output.display()
    );
    Ok(if tally.mismatch > 0 {
        5
    } else if tally.incomplete > 0 {
        6
    } else if tally.complete == 0 {
        4
    } else if tally.with_read_errors > 0 {
        7
    } else {
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_file_names_stay_in_the_directory() {
        assert_eq!(file_name(1, "C:"), "001-C_.raw");
        assert_eq!(file_name(2, "../../etc/passwd"), "002-_.._etc_passwd.raw");
        assert_eq!(file_name(3, "...hidden"), "003-hidden.raw");
        assert_eq!(file_name(4, ""), "004-stream.raw");
        assert_eq!(
            file_name(5, "\\\\.\\PhysicalDrive0"),
            "005-__._PhysicalDrive0.raw"
        );
        for n in ["a/b", "..", "x\0y", "/abs"] {
            let f = file_name(9, n);
            assert!(!f.contains('/') && !f.starts_with('.'), "{f}");
        }
    }
}
