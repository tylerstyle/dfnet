# dfnet listeners behind the NixOS firewall, as on dfnix: the port is closed
# until dfnet listens; while it listens, exactly its address and port are
# open (a tagged ACCEPT rule); afterwards the rule is gone. A rule left by a
# killed receiver is removed at the next start, and Ctrl-C while waiting for
# a sender ends cleanly without leaving one.
#
#   nix-build tests/listen.nix     (dfcore and dflive from ../dfcore, ../dflive)
{ pkgs ? import <nixpkgs> { }
, dfnet ? pkgs.callPackage ../package.nix { }
}:

pkgs.testers.runNixOSTest {
  name = "dfnet-listen";

  nodes.receiver = {
    # the NixOS default, as on dfnix
    networking.firewall.enable = true;
    environment.systemPackages = [ dfnet pkgs.iptables ];
  };
  nodes.sender = {
    environment.systemPackages = [ pkgs.netcat ];
  };

  testScript = ''
    def rules():
        return receiver.succeed("iptables -S INPUT | grep dfnet-listen || true").strip()

    start_all()
    receiver.wait_for_unit("multi-user.target")
    sender.wait_for_unit("multi-user.target")
    ip = receiver.succeed("ip -4 -o addr show eth1 | awk '{print $4}' | cut -d/ -f1").strip()
    receiver.succeed("mkdir -p /target")
    sender.succeed("printf abc > /tmp/abc")
    abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    with subtest("closed until dfnet listens, open while it does, closed afterwards"):
        sender.fail(f"nc -z -w 2 {ip} 9999")
        receiver.succeed(
            f"systemd-run --unit rx1 dfnet receive 9999 /target/one.raw --bind {ip}"
            f" --expected-bytes 3 --expected-sha256 {abc}"
        )
        receiver.wait_until_succeeds("iptables -S INPUT | grep -q 'dfnet-listen:receive:9999'")
        assert f"-d {ip}/32" in rules(), rules()
        sender.succeed(f"nc -N {ip} 9999 < /tmp/abc")
        receiver.wait_until_fails("systemctl is-active rx1", timeout=30)
        assert receiver.succeed("cat /target/one.raw") == "abc"
        assert rules() == "", rules()
        sender.fail(f"nc -z -w 2 {ip} 9999")

    with subtest("a rule left by a killed receiver is removed at the next start"):
        receiver.succeed(
            f"systemd-run --unit rx2 dfnet receive 9999 /target/two.raw --bind {ip}"
            f" --expected-bytes 3 --expected-sha256 {abc}"
        )
        receiver.wait_until_succeeds("iptables -S INPUT | grep -q dfnet-listen")
        receiver.succeed("systemctl kill --signal=SIGKILL rx2")
        receiver.wait_until_fails("systemctl is-active rx2", timeout=30)
        assert "dfnet-listen" in rules(), "the killed run left no rule to clean"
        receiver.succeed(
            f"systemd-run --unit rx3 dfnet receive 9999 /target/three.raw --bind {ip}"
            f" --expected-bytes 3 --expected-sha256 {abc}"
        )
        receiver.wait_until_succeeds("journalctl -u rx3 | grep -q 'Removed a stale firewall opening'")
        assert rules().count("dfnet-listen") == 1, rules()
        sender.succeed(f"nc -N {ip} 9999 < /tmp/abc")
        receiver.wait_until_fails("systemctl is-active rx3", timeout=30)
        assert rules() == "", rules()

    with subtest("Ctrl-C while waiting ends cleanly and closes the port"):
        receiver.succeed(
            f"systemd-run --unit rx4 dfnet receive 9999 /target/four.raw --bind {ip}"
            f" --expected-bytes 3 --expected-sha256 {abc}"
        )
        receiver.wait_until_succeeds("iptables -S INPUT | grep -q dfnet-listen")
        receiver.succeed("systemctl kill --signal=SIGINT rx4")
        receiver.wait_until_fails("systemctl is-active rx4", timeout=30)
        assert rules() == "", rules()
        receiver.succeed("journalctl -u rx4 | grep -q 'stopped while waiting'")
  '';
}
