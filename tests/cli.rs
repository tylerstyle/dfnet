use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::{Shutdown, TcpStream},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "dfnet-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dfnet"));
        command
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.0.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("TEST_DIR", &self.0);
        command
    }
    fn script(&self, name: &str, body: &str) {
        let shell = Command::new("bash")
            .args(["-c", "command -v bash"])
            .output()
            .unwrap();
        assert!(shell.status.success());
        let path = self.0.join(name);
        fs::write(
            &path,
            format!(
                "#!{}\n{}\n",
                String::from_utf8_lossy(&shell.stdout).trim(),
                body
            ),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }
    fn firewall(&self) {
        for program in ["iptables", "ip6tables"] {
            self.script(
                program,
                r#"
printf '%s %s\n' "${0##*/}" "$*" >> "$TEST_DIR/log"
if [[ "$*" == *" -C "* ]]; then exit 1; fi
if [[ "$*" == *" -S "* && -f "$TEST_DIR/rules" ]]; then cat "$TEST_DIR/rules"; fi
"#,
            );
        }
        self.script(
            "ip",
            r#"
printf 'ip %s\n' "$*" >> "$TEST_DIR/log"
if [[ "$*" == 'route show default' ]]; then echo 'default via 192.0.2.1 dev eth0'; fi
"#,
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Process {
    fn finish(&mut self) -> std::process::ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "child process timed out"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn transfer(data: &[u8], extra: &[&str]) -> (Fixture, bool, serde_json::Value) {
    let fixture = Fixture::new();
    let out = fixture.0.join("image.raw");
    let mut process = Process(
        fixture
            .command()
            .args(["receive", "0", out.to_str().unwrap(), "--bind", "127.0.0.1"])
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut reader = BufReader::new(process.0.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.starts_with("[*] Listening on "), "{line}");
    let address = line.split_whitespace().nth(3).unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(data).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let ok = process.finish().success();
    let manifest =
        serde_json::from_slice(&fs::read(fixture.0.join("image.raw.json")).unwrap()).unwrap();
    (fixture, ok, manifest)
}

#[test]
fn receives_and_verifies_a_real_tcp_stream() {
    let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let (fixture, ok, manifest) = transfer(
        b"abc",
        &["--expected-bytes", "3", "--expected-sha256", hash],
    );
    assert!(ok);
    assert_eq!(fs::read(fixture.0.join("image.raw")).unwrap(), b"abc");
    assert_eq!(manifest["status"], "verified");
    assert_eq!(manifest["bytes"], 3);
    assert_eq!(manifest["sha256"], hash);
    assert_eq!(
        fs::read_to_string(fixture.0.join("image.raw.sha256")).unwrap(),
        format!("{hash}  image.raw\n")
    );
}

#[test]
fn distinguishes_unverified_truncated_and_mismatched_images() {
    let (_, ok, manifest) = transfer(b"abc", &[]);
    assert!(ok);
    assert_eq!(manifest["status"], "received_unverified");
    for args in [
        vec!["--expected-bytes", "4"],
        vec![
            "--expected-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ],
    ] {
        let (fixture, ok, manifest) = transfer(b"abc", &args);
        assert!(!ok);
        assert_eq!(manifest["status"], "incomplete");
        assert!(!manifest["error"].is_null());
        assert!(fs::read(fixture.0.join("image.raw.sha256"))
            .unwrap()
            .is_empty());
    }
}

#[test]
fn refuses_existing_images_and_symlinks() {
    let fixture = Fixture::new();
    let out = fixture.0.join("evidence.raw");
    fs::write(&out, b"original evidence").unwrap();
    let alias = fixture.0.join("alias.raw");
    std::os::unix::fs::symlink(&out, &alias).unwrap();
    for path in [&out, &alias] {
        let result = fixture.run(&[
            "receive",
            "0",
            path.to_str().unwrap(),
            "--bind",
            "127.0.0.1",
        ]);
        assert!(!result.status.success());
        assert_eq!(fs::read(&out).unwrap(), b"original evidence");
    }
}

#[test]
fn reports_failed_scans() {
    let fixture = Fixture::new();
    fixture.script("arp-scan", "echo 'permission denied' >&2\nexit 1");
    let result = fixture.run(&["scan", "wlan0"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("permission denied"));
}

#[test]
fn removes_only_rules_with_the_exact_owner() {
    let fixture = Fixture::new();
    fixture.firewall();
    fs::write(fixture.0.join("rules"), "-A FORWARD -i wlan01 -m comment --comment dfnet:wlan01 -j DROP\n-A FORWARD -i wlan0 -j ACCEPT\n-A FORWARD -i wlan0 -m comment --comment \"dfnet:wlan0\" -j DROP\n").unwrap();
    let result = fixture.run(&["route", "reset", "--ap", "wlan0"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let log = fs::read_to_string(fixture.0.join("log")).unwrap();
    let deletes: Vec<_> = log.lines().filter(|l| l.contains(" -D ")).collect();
    assert_eq!(deletes.len(), 2); // One owned FORWARD rule in each family.
    assert!(deletes
        .iter()
        .all(|l| l.contains("--comment dfnet:wlan0") && !l.contains("wlan01")));
    assert!(!log.contains("sysctl"));
}

#[test]
fn does_not_mislabel_other_interfaces_or_failed_inspection() {
    let fixture = Fixture::new();
    fixture.firewall();
    fs::write(
        fixture.0.join("rules"),
        "-A FORWARD -i wlan01 -m comment --comment dfnet:wlan01 -j DROP\n",
    )
    .unwrap();
    let result = fixture.run(&["route", "status", "--ap", "wlan0"]);
    assert!(!String::from_utf8_lossy(&result.stdout).contains("Forwarding Blocked"));
    fixture.script("iptables", "echo 'permission denied' >&2\nexit 1");
    let result = fixture.run(&["route", "status", "--ap", "wlan0"]);
    assert!(String::from_utf8_lossy(&result.stdout).contains("Unknown:"));
    let result = fixture.run(&["route", "reset", "--ap", "wlan0"]);
    assert!(!result.status.success());
}

#[test]
fn installs_both_family_guards_before_activating_the_hotspot() {
    let fixture = Fixture::new();
    fixture.firewall();
    fixture.script("nmcli", r#"printf 'nmcli %s\n' "$*" >> "$TEST_DIR/log""#);
    let result = fixture.run(&[
        "hotspot",
        "start",
        "--iface",
        "wlan0",
        "--password",
        "test-passphrase",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let log = fs::read_to_string(fixture.0.join("log")).unwrap();
    let activate = log.find("nmcli connection up").unwrap();
    assert!(
        log.find("iptables -w 5 -t filter -I FORWARD 1 -i wlan0 -j DROP")
            .unwrap()
            < activate
    );
    assert!(
        log.find("ip6tables -w 5 -t filter -I FORWARD 1 -i wlan0 -j DROP")
            .unwrap()
            < activate
    );
    assert!(log.contains("802-11-wireless.ap-isolation yes"));
    assert!(log.contains("ipv6.method disabled"));
    assert!(!log.contains("MASQUERADE"));
}

#[test]
fn refuses_to_activate_if_ipv6_guards_fail() {
    let fixture = Fixture::new();
    fixture.firewall();
    fixture.script("ip6tables", "exit 2");
    fixture.script("nmcli", r#"printf 'nmcli %s\n' "$*" >> "$TEST_DIR/log""#);
    assert!(!fixture
        .run(&[
            "hotspot",
            "start",
            "--iface",
            "wlan0",
            "--password",
            "test-passphrase"
        ])
        .status
        .success());
    let log = fs::read_to_string(fixture.0.join("log")).unwrap();
    assert!(!log.contains("nmcli connection up"));
}

#[test]
fn rejects_a_nondefault_uplink_before_network_changes() {
    let fixture = Fixture::new();
    fixture.firewall();
    let result = fixture.run(&["hotspot", "start", "--iface", "wlan0", "--uplink", "eth1"]);
    assert!(!result.status.success());
    let log = fs::read_to_string(fixture.0.join("log")).unwrap();
    assert!(!log.contains("iptables"));
    assert!(!log.contains("nmcli"));
}

#[test]
fn rejects_mount_traversal_before_running_helpers() {
    let fixture = Fixture::new();
    let result = fixture.run(&["nfs", "server:/share", "a/../../tmp/escape"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Mount name"));
}

#[test]
fn compatibility_wrapper_preserves_arguments() {
    let fixture = Fixture::new();
    fixture.script("dfnet", "printf '%s\\n' \"$@\"");
    let output = Command::new("bash")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/dfnet.sh"))
        .args([
            "hotspot",
            "start",
            "wlan0",
            "Evidence AP",
            "password with spaces",
            "--isolate",
        ])
        .env(
            "PATH",
            format!("{}:{}", fixture.0.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "hotspot\nstart\n--iface\nwlan0\n--ssid\nEvidence AP\n--password\npassword with spaces\n--isolate\n");
}

#[test]
fn sender_idle_timeout_keeps_an_incomplete_manifest() {
    let fixture = Fixture::new();
    let out = fixture.0.join("image.raw");
    let mut process = Process(
        fixture
            .command()
            .args([
                "receive",
                "0",
                out.to_str().unwrap(),
                "--bind",
                "127.0.0.1",
                "--timeout",
                "1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut reader = BufReader::new(process.0.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let _stream = TcpStream::connect(line.split_whitespace().nth(3).unwrap()).unwrap();
    assert!(!process.finish().success());
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.0.join("image.raw.json")).unwrap()).unwrap();
    assert_eq!(manifest["status"], "incomplete");
    assert!(manifest["error"]
        .as_str()
        .unwrap()
        .contains("Stream read failed"));
}

#[test]
fn existing_sidecars_do_not_create_a_new_image() {
    let fixture = Fixture::new();
    let out = fixture.0.join("image.raw");
    fs::write(fixture.0.join("image.raw.sha256"), "original hash").unwrap();
    assert!(!fixture
        .run(&["receive", "0", out.to_str().unwrap()])
        .status
        .success());
    assert!(!out.exists());
    assert_eq!(
        fs::read_to_string(fixture.0.join("image.raw.sha256")).unwrap(),
        "original hash"
    );
}

#[test]
fn activation_failure_stops_ap_before_removing_guards() {
    let fixture = Fixture::new();
    fixture.firewall();
    fs::write(
        fixture.0.join("rules"),
        "-A FORWARD -i wlan0 -m comment --comment dfnet:wlan0 -j DROP\n",
    )
    .unwrap();
    fixture.script(
        "nmcli",
        r#"
printf 'nmcli %s\n' "$*" >> "$TEST_DIR/log"
case "$*" in
    'connection up id dfnet-hotspot') touch "$TEST_DIR/active"; exit 1;;
    '-t -f NAME,DEVICE connection show --active')
        if [[ -f "$TEST_DIR/active" ]]; then echo 'dfnet-hotspot:wlan0'; fi;;
    'connection down id dfnet-hotspot') rm "$TEST_DIR/active";;
esac
"#,
    );
    let result = fixture.run(&[
        "hotspot",
        "start",
        "--iface",
        "wlan0",
        "--password",
        "test-passphrase",
    ]);
    assert!(!result.status.success());
    let log = fs::read_to_string(fixture.0.join("log")).unwrap();
    assert!(log.find("nmcli connection down").unwrap() < log.find(" -D FORWARD").unwrap());
}

#[test]
fn rollback_retains_guards_when_hotspot_cannot_be_stopped() {
    let fixture = Fixture::new();
    fixture.firewall();
    fs::write(
        fixture.0.join("rules"),
        "-A FORWARD -i wlan0 -m comment --comment dfnet:wlan0 -j DROP\n",
    )
    .unwrap();
    fixture.script(
        "nmcli",
        r#"
printf 'nmcli %s\n' "$*" >> "$TEST_DIR/log"
case "$*" in
    'connection up id dfnet-hotspot') touch "$TEST_DIR/active"; exit 1;;
    '-t -f NAME,DEVICE connection show --active')
        if [[ -f "$TEST_DIR/active" ]]; then echo 'dfnet-hotspot:wlan0'; fi;;
    'connection down id dfnet-hotspot') exit 1;;
esac
"#,
    );
    let result = fixture.run(&[
        "hotspot",
        "start",
        "--iface",
        "wlan0",
        "--password",
        "test-passphrase",
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("guards retained"));
    let log = fs::read_to_string(fixture.0.join("log")).unwrap();
    assert!(!log.contains(" -D "));
}
