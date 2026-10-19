# dfnet pcap between two machines: the capture node records what the peer
# sends (ping, a UDP burst) into pcapng files of 1 MiB, each hashed when
# dumpcap closes it, with GRO switched off and restored. With --silent on an
# interface without IPv4 the capture node sends nothing at all, and ARP/IPv6
# come back afterwards. A capture stopped with SIGINT (Ctrl-C) still finishes
# its collection, and one with --duration ends by itself.
#
# The captures with traffic are stopped only once the last packet the test
# waits for is in a file, so a slow or busy machine cannot cut them short.
#
#   nix-build tests/pcap.nix        (dfcore and dflive from ../dfcore, ../dflive)
{ pkgs ? import <nixpkgs> { }
, dfnet ? pkgs.callPackage ../package.nix { }
}:

pkgs.testers.runNixOSTest {
  name = "dfnet-pcap";

  nodes.capture = {
    networking.firewall.enable = false;
    environment.systemPackages = [ dfnet pkgs.wireshark-cli pkgs.ethtool pkgs.python3 ];
  };
  nodes.peer = {
    networking.firewall.enable = false;
    environment.systemPackages = [ pkgs.python3 ];
  };

  testScript = ''
    import json

    def items(d):
        return [json.loads(l) for l in capture.succeed(f"cat {d}/items.jsonl").splitlines()]

    def footprint(d):
        return [json.loads(l) for l in capture.succeed(f"cat {d}/footprint.jsonl").splitlines()]

    def seen(d, display_filter):
        # The newest file is still being written; tshark reads up to its last whole packet
        return f"for f in {d}/*.pcapng; do tshark -r $f -Y '{display_filter}' 2>/dev/null; done | grep -q ."

    def interrupt(unit):
        capture.succeed(f"systemctl kill --signal=SIGINT {unit}")
        capture.wait_until_fails(f"systemctl is-active {unit}", timeout=60)

    # 3000 datagrams of 1200 bytes, paced, so a full 1 MiB file rotates more than twice
    burst = "python3 -c \"import socket,os,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); [(s.sendto(os.urandom(1200),('capture',9999)), time.sleep(0.001)) for _ in range(3000)]\""
    # Sent after the burst: once it is in a file, so is everything before it
    last = "python3 -c \"import socket; socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'last',('capture',9998))\""

    start_all()
    capture.wait_for_unit("multi-user.target")
    peer.wait_for_unit("multi-user.target")
    capture.succeed("mkdir -p /target")
    gro_before = capture.succeed("ethtool -k eth1 | grep '^generic-receive-offload'").strip()

    with subtest("files of 1 MiB, each hashed, GRO off during the capture and restored"):
        capture.succeed("systemd-run --unit cap1 dfnet pcap eth1 -o /target/cap1 -C CASE -E net01 -e tester --file-size 1")
        capture.wait_until_succeeds("test -n \"$(ls /target/cap1/*.pcapng 2>/dev/null)\"", timeout=30)
        assert "off" in capture.succeed("ethtool -k eth1 | grep '^generic-receive-offload'"), "GRO still on"
        peer.succeed("ping -4 -c 5 capture")
        peer.succeed(burst)
        peer.succeed(last)
        capture.wait_until_succeeds(seen("/target/cap1", "udp.dstport == 9998"), timeout=120)
        interrupt("cap1")
        assert capture.succeed("systemctl show -p ExecMainStatus --value cap1").strip() == "0"
        assert capture.succeed("ethtool -k eth1 | grep '^generic-receive-offload'").strip() == gro_before
        got = items("/target/cap1")
        assert len(got) >= 3, got
        for i in got:
            want = capture.succeed(f"sha256sum /target/cap1/{i['stored_as']}").split()[0]
            assert i["hashes"]["sha256"] == want and i["kind"] == "pcapng", i
        files = " ".join(f"/target/cap1/{i['stored_as']}" for i in got)
        icmp = capture.succeed(f"for f in {files}; do tshark -r $f -Y 'icmp.type == 8' 2>&1; done")
        assert len([l for l in icmp.splitlines() if "Echo (ping) request" in l]) == 5, icmp
        udp = int(capture.succeed(f"for f in {files}; do tshark -r $f -Y 'udp.dstport == 9999' 2>/dev/null; done | wc -l"))
        assert udp > 2500, udp
        fp = footprint("/target/cap1")
        kinds = [f["kind"] for f in fp]
        assert "capture_start" in kinds and "capture_stop" in kinds, kinds
        if "on" in gro_before:
            assert "interface_change" in kinds and "interface_restore" in kinds, kinds
        stop = [f for f in fp if f["kind"] == "capture_stop"][0]["detail"]
        assert stop["packets_dropped"] == 0 and stop["packets_captured"] > 3000, stop
        manifest = json.loads(capture.succeed("cat /target/cap1/manifest.json"))
        assert manifest["status"] == "complete", manifest
        assert manifest["source"]["kind"] == "network-interface", manifest["source"]
        assert manifest["source"]["identity"]["offloads"], manifest["source"]["identity"]

    with subtest("--silent: the capture node sends nothing, ARP and IPv6 come back"):
        mac = capture.succeed("cat /sys/class/net/eth1/address").strip()
        flags_before = capture.succeed("cat /sys/class/net/eth1/flags").strip()
        capture.fail("dfnet pcap eth1 --silent -o /target/refused -C CASE -E net02 -e tester --duration 2")
        capture.fail("dfnet pcap .. -o /target/refused2 -C CASE -E net02 -e tester --duration 2")
        capture.succeed("ip -4 addr flush dev eth1")
        capture.succeed("systemd-run --unit cap2 dfnet pcap eth1 --silent -o /target/cap2 -C CASE -E net02 -e tester")
        capture.wait_until_succeeds("test -n \"$(ls /target/cap2/*.pcapng 2>/dev/null)\"", timeout=30)
        capture.wait_until_succeeds("test $(sysctl -n net.ipv6.conf.eth1.disable_ipv6) = 1", timeout=10)
        # Forget capture's MAC, so the peer has to ask with ARP (which goes unanswered)
        peer.succeed("ip neigh flush all")
        peer.fail("ping -4 -c 3 -W 1 capture")
        capture.wait_until_succeeds(seen("/target/cap2", "arp.opcode == 1"), timeout=120)
        interrupt("cap2")
        got = items("/target/cap2")
        files = " ".join(f"/target/cap2/{i['stored_as']}" for i in got)
        arp = int(capture.succeed(f"for f in {files}; do tshark -r $f -Y 'arp.opcode == 1' 2>/dev/null; done | grep -c ARP || true"))
        mine = capture.succeed(f"for f in {files}; do tshark -r $f -Y 'eth.src == {mac}' 2>/dev/null; done")
        assert arp > 0 and mine.strip() == "", (arp, mine)
        assert capture.succeed("sysctl -n net.ipv6.conf.eth1.disable_ipv6").strip() == "0"
        assert capture.succeed("cat /sys/class/net/eth1/flags").strip() == flags_before

    with subtest("SIGINT stops the capture and the collection still finishes"):
        capture.succeed("systemd-run --unit cap3 dfnet pcap eth1 -o /target/cap3 -C CASE -E net03 -e tester")
        capture.wait_until_succeeds("test -n \"$(ls /target/cap3/*.pcapng 2>/dev/null)\"", timeout=30)
        capture.succeed("sleep 2")
        interrupt("cap3")
        manifest = json.loads(capture.succeed("cat /target/cap3/manifest.json"))
        assert manifest["status"] == "complete", manifest
        stop = [f for f in footprint("/target/cap3") if f["kind"] == "capture_stop"][0]["detail"]
        assert stop["reason"] == "stopped by the examiner (signal)", stop
        assert len(items("/target/cap3")) == 1

    with subtest("--duration ends the capture by itself"):
        capture.succeed("dfnet pcap eth1 -o /target/cap4 -C CASE -E net04 -e tester --duration 3")
        manifest = json.loads(capture.succeed("cat /target/cap4/manifest.json"))
        assert manifest["status"] == "complete", manifest
        stop = [f for f in footprint("/target/cap4") if f["kind"] == "capture_stop"][0]["detail"]
        assert stop["reason"] is None and stop["exit"] == 0, stop
        assert len(items("/target/cap4")) == 1
  '';
}
