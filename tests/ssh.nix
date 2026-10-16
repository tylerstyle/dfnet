# dfnet ssh on a dfnix-like machine (firewall on, no SSH server): nothing
# answers on 22 until the session starts; then only the case key logs in, as
# root, with the host key dfnet printed; passwords and other keys are refused.
# `dfnet ssh stop` closes the port, deletes the keys and records the login.
#
#   nix-build tests/ssh.nix     (dfcore and dflive from ../dfcore, ../dflive)
{ pkgs ? import <nixpkgs> { }
, dfnet ? pkgs.callPackage ../package.nix { }
}:

pkgs.testers.runNixOSTest {
  name = "dfnet-ssh";

  nodes.dfnix = {
    networking.firewall.enable = true;
    services.openssh.enable = false;
    # sshd's privilege separation user, which dfnix provides without the service
    users.users.sshd = { isSystemUser = true; group = "sshd"; description = "SSH privilege separation user"; };
    users.groups.sshd = { };
    environment.systemPackages = [ dfnet pkgs.iptables ];
  };
  nodes.examiner = {
    environment.systemPackages = [ pkgs.openssh pkgs.netcat ];
  };

  testScript = ''
    import json

    start_all()
    dfnix.wait_for_unit("multi-user.target")
    examiner.wait_for_unit("multi-user.target")
    ip = dfnix.succeed("ip -4 -o addr show eth1 | awk '{print $4}' | cut -d/ -f1").strip()
    examiner.succeed("ssh-keygen -q -t ed25519 -N ''' -f /root/case && ssh-keygen -q -t ed25519 -N ''' -f /root/other")
    pub = examiner.succeed("cat /root/case.pub").strip()
    dfnix.succeed(f"echo '{pub}' > /root/case.pub")
    ssh = "ssh -o BatchMode=yes -o UserKnownHostsFile=/root/known -o StrictHostKeyChecking=yes -o ConnectTimeout=5"

    with subtest("nothing answers on 22 before the session"):
        examiner.fail(f"nc -z -w 2 {ip} 22")

    with subtest("only the case key logs in, with the printed host key"):
        out = dfnix.succeed(f"dfnet ssh start --key /root/case.pub --bind {ip}")
        printed = [l for l in out.splitlines() if "Host key" in l][0].split(": ", 1)[1].split()[1]
        examiner.wait_until_succeeds(f"nc -z -w 2 {ip} 22")
        scanned = examiner.succeed(f"ssh-keyscan -t ed25519 {ip} 2>/dev/null | tee /root/known | ssh-keygen -lf - | cut -d' ' -f2").strip()
        assert scanned == printed, (scanned, printed)
        assert examiner.succeed(f"{ssh} -i /root/case root@{ip} 'id -u'").strip() == "0"
        examiner.fail(f"{ssh} -i /root/other root@{ip} true")
        examiner.fail(f"ssh -o BatchMode=no -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o UserKnownHostsFile=/root/known -o NumberOfPasswordPrompts=0 root@{ip} true")
        # No forwarding: a stdio forward opens its channel at once and is refused
        examiner.fail(f"timeout 20 {ssh} -i /root/case -W 127.0.0.1:22 root@{ip} < /dev/null")
        assert "dfnet-ssh:22" in dfnix.succeed("iptables -S INPUT")
        assert "Accepted publickey for root" in dfnix.succeed("dfnet ssh status")

    with subtest("stop closes the port, deletes the keys and records the login"):
        out = dfnix.succeed("dfnet ssh stop")
        assert "Accepted publickey for root" in out, out
        examiner.fail(f"nc -z -w 2 {ip} 22")
        assert "dfnet-ssh" not in dfnix.succeed("iptables -S INPUT")
        dfnix.fail("test -e /run/dfnet/ssh")
        audit = [json.loads(l) for l in dfnix.succeed("cat /run/dfnix/audit.jsonl").splitlines()]
        actions = [a["action"] for a in audit]
        assert "ssh_start" in actions and "ssh_stop" in actions, actions
        stop = [a for a in audit if a["action"] == "ssh_stop"][-1]
        assert stop["details"]["accepted_logins"], stop

    with subtest("refusals: all interfaces, a foreign address, a busy port, an empty key file, a second session"):
        dfnix.fail("dfnet ssh start --key /root/case.pub --bind 0.0.0.0")
        dfnix.fail("dfnet ssh start --key /root/case.pub --bind 192.0.2.99")
        dfnix.succeed(f"systemd-run --unit busy ${pkgs.python3}/bin/python3 -m http.server --bind {ip} 2200")
        dfnix.wait_for_open_port(2200, addr=ip)
        dfnix.fail(f"dfnet ssh start --key /root/case.pub --bind {ip} --port 2200")
        assert "dfnet-ssh" not in dfnix.succeed("iptables -S INPUT")
        dfnix.fail("systemctl is-failed dfnet-sshd")
        dfnix.succeed("touch /root/empty.pub")
        dfnix.fail(f"dfnet ssh start --key /root/empty.pub --bind {ip}")
        dfnix.succeed(f"dfnet ssh start --key /root/case.pub --bind {ip} --port 2222")
        dfnix.fail(f"dfnet ssh start --key /root/case.pub --bind {ip}")
        dfnix.succeed("dfnet ssh stop")
  '';
}
