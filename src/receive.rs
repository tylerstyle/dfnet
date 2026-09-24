use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, TcpListener},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Serialize)]
struct Manifest {
    status: &'static str,
    peer: String,
    bytes: u64,
    sha256: String,
    started_unix: u64,
    finished_unix: u64,
    expected_bytes: Option<u64>,
    expected_sha256: Option<String>,
    error: Option<String>,
}

pub struct Options<'a> {
    pub bind: IpAddr,
    pub port: u16,
    pub output: &'a Path,
    pub expected_bytes: Option<u64>,
    pub expected_sha256: Option<&'a str>,
    pub timeout: Duration,
}

fn create_new(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .mode(0o600)
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "Cannot create {} (existing files are never overwritten)",
                path.display()
            )
        })
}

pub fn parse_hash(value: &str) -> std::result::Result<String, String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected a 64-character hexadecimal SHA-256 hash".into());
    }
    Ok(value.to_ascii_lowercase())
}

fn copy_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    bytes: &mut u64,
    hash: &mut Sha256,
    expected: Option<u64>,
) -> Result<()> {
    let mut buffer = [0u8; 256 * 1024];
    let started = Instant::now();
    let mut reported = Instant::now();
    loop {
        let size = match reader.read(&mut buffer) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.context("Stream read failed; image is incomplete")?,
        };
        if size == 0 {
            break;
        }
        if expected.is_some_and(|limit| *bytes + size as u64 > limit) {
            bail!("Stream exceeds the expected byte count");
        }
        // Track only bytes successfully written, including partial writes on failure.
        let mut offset = 0;
        while offset < size {
            let n = match writer.write(&buffer[offset..size]) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result.context("Image write failed; image is incomplete")?,
            };
            if n == 0 {
                bail!("Image write returned zero bytes");
            }
            hash.update(&buffer[offset..offset + n]);
            *bytes += n as u64;
            offset += n;
        }
        if reported.elapsed() >= Duration::from_secs(1) {
            eprint!(
                "\r{} bytes received ({:.1} MiB/s)",
                *bytes,
                *bytes as f64 / started.elapsed().as_secs_f64() / 1_048_576.0
            );
            reported = Instant::now();
        }
    }
    if *bytes == 0 {
        bail!("Received an empty stream");
    }
    if let Some(expected) = expected {
        if *bytes != expected {
            bail!("Expected {} bytes, received {}", expected, bytes);
        }
    }
    Ok(())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn receive(options: Options<'_>) -> Result<()> {
    let expected_hash = options
        .expected_sha256
        .map(parse_hash)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let mut checksum_path = options.output.as_os_str().to_os_string();
    checksum_path.push(".sha256");
    let mut manifest_path = options.output.as_os_str().to_os_string();
    manifest_path.push(".json");
    let filename = options
        .output
        .file_name()
        .and_then(|name| name.to_str())
        .context("Output filename must be valid UTF-8")?;
    // Check all paths before reserving any of them. create_new still enforces the
    // guarantee if another process creates a path after this preflight.
    for path in [
        options.output,
        Path::new(&manifest_path),
        Path::new(&checksum_path),
    ] {
        match std::fs::symlink_metadata(path) {
            Ok(_) => bail!("Refusing existing acquisition path: {}", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("Cannot inspect {}", path.display())),
        }
    }
    // Bind before creating files, so a busy port cannot leave misleading output.
    let listener =
        TcpListener::bind((options.bind, options.port)).context("Cannot bind receiver")?;
    let mut output = create_new(options.output)?;
    let mut manifest_file = create_new(Path::new(&manifest_path))?;
    let mut checksum_file = create_new(Path::new(&checksum_path))?;
    let started = now();
    // Persist a pending record before accepting data; interruption cannot look successful.
    let mut manifest = Manifest {
        status: "incomplete",
        peer: String::new(),
        bytes: 0,
        sha256: String::new(),
        started_unix: started,
        finished_unix: 0,
        expected_bytes: options.expected_bytes,
        expected_sha256: expected_hash.clone(),
        error: Some("Transfer has not completed".into()),
    };
    serde_json::to_writer_pretty(&mut manifest_file, &manifest)?;
    manifest_file.sync_all()?;
    println!(
        "[*] Listening on {} -> {}",
        listener.local_addr()?,
        options.output.display()
    );
    println!("[*] Raw TCP is unauthenticated. Use a trusted acquisition network.");
    let mut hash = Sha256::new();
    let result = (|| -> Result<()> {
        let (mut stream, peer) = listener.accept().context("Cannot accept stream")?;
        drop(listener); // A single sender per acquisition.
        manifest.peer = peer.to_string();
        stream.set_read_timeout(Some(options.timeout))?;
        copy_stream(
            &mut stream,
            &mut output,
            &mut manifest.bytes,
            &mut hash,
            options.expected_bytes,
        )?;
        output.sync_all().context("Cannot flush image to storage")?;
        Ok(())
    })();
    manifest.sha256 = format!("{:x}", hash.finalize());
    manifest.finished_unix = now();
    let result = result.and_then(|()| {
        if expected_hash
            .as_ref()
            .is_some_and(|expected| expected != &manifest.sha256)
        {
            bail!("SHA-256 does not match the expected source hash");
        }
        Ok(())
    });
    manifest.status = if result.is_err() {
        "incomplete"
    } else if expected_hash.is_some() {
        "verified"
    } else {
        "received_unverified"
    };
    manifest.error = result.as_ref().err().map(|e| format!("{e:#}"));
    if result.is_ok() {
        // Standard checksum format; escape filenames as GNU sha256sum does.
        let name = filename;
        let escaped = name.contains(['\\', '\n', '\r']);
        let name = name
            .replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        writeln!(
            checksum_file,
            "{}{}  {}",
            if escaped { "\\" } else { "" },
            manifest.sha256,
            name
        )?;
        checksum_file.sync_all()?;
    }
    use std::io::{Seek, SeekFrom};
    manifest_file.seek(SeekFrom::Start(0))?;
    manifest_file.set_len(0)?;
    serde_json::to_writer_pretty(&mut manifest_file, &manifest)?;
    manifest_file.sync_all()?;
    eprintln!();
    result?;
    println!(
        "[✓] Received {} bytes; SHA-256: {}",
        manifest.bytes, manifest.sha256
    );
    println!(
        "[*] Status: {}. Manifest: {}",
        manifest.status,
        Path::new(&manifest_path).display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashes_the_bytes_written() {
        let mut output = Vec::new();
        let mut bytes = 0;
        let mut hash = Sha256::new();
        copy_stream(
            &mut &b"abc"[..],
            &mut output,
            &mut bytes,
            &mut hash,
            Some(3),
        )
        .unwrap();
        assert_eq!(output, b"abc");
        assert_eq!(bytes, 3);
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn rejects_empty_short_and_oversized_streams() {
        for (data, expected) in [
            (b"".as_slice(), None),
            (b"a".as_slice(), Some(2)),
            (b"abc".as_slice(), Some(2)),
        ] {
            assert!(copy_stream(
                &mut &data[..],
                &mut Vec::new(),
                &mut 0,
                &mut Sha256::new(),
                expected
            )
            .is_err());
        }
    }
    #[test]
    fn propagates_storage_failure() {
        struct FullDisk;
        impl Write for FullDisk {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(copy_stream(
            &mut &b"abc"[..],
            &mut FullDisk,
            &mut 0,
            &mut Sha256::new(),
            None
        )
        .is_err());
    }
}
