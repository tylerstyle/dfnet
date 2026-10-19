{ lib
, rustPlatform
, runCommand
, makeWrapper
, macchanger
, networkmanager
, arp-scan
, cifs-utils
, nfs-utils
, iproute2
, util-linux
, iptables
, procps
, nftables
, wireshark-cli
, ethtool
, openssh
, bash
  # dfcore and dflive (for dfstream) are sibling path dependencies; flakes
  # pass their inputs
, dfcoreSrc ? ../dfcore
, dfliveSrc ? ../dflive
}:

let
  clean = src: lib.cleanSourceWith {
    filter = path: type: baseNameOf path != "target";
    src = lib.cleanSource src;
  };
  # Lay out the sources as in ~/git so `path = "../dfcore"` resolves
  src = runCommand "dfnet-src" { } ''
    mkdir -p $out
    cp -r ${clean ./.} $out/dfnet
    cp -r ${clean dfcoreSrc} $out/dfcore
    cp -r ${clean dfliveSrc} $out/dflive
    chmod -R u+w $out
  '';
in
rustPlatform.buildRustPackage {
  pname = "dfnet";
  version = "0.1.6";

  inherit src;
  sourceRoot = "dfnet-src/dfnet";

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [ makeWrapper ];
  # scripts/dfnet.sh starts with `#!/usr/bin/env bash`; with bash as a host input,
  # patchShebangs points dfnet-cli at the store bash instead of /usr/bin/env
  buildInputs = [ bash ];

  postInstall = ''
    # Install companion CLI helper
    cp scripts/dfnet.sh $out/bin/dfnet-cli
    chmod +x $out/bin/dfnet-cli

    # Compatibility symlink
    ln -s $out/bin/dfnet-cli $out/bin/df-net

    wrapProgram $out/bin/dfnet \
      --prefix PATH : ${lib.makeBinPath [
        macchanger
        networkmanager
        arp-scan
        cifs-utils
        nfs-utils
        iproute2
        util-linux
        iptables
        procps
        nftables
        wireshark-cli # dumpcap for dfnet pcap
        ethtool
        openssh # sshd and ssh-keygen for dfnet ssh
      ]}

    wrapProgram $out/bin/dfnet-cli \
      --prefix PATH : $out/bin \
      --prefix PATH : ${lib.makeBinPath [
        macchanger
        networkmanager
        arp-scan
        cifs-utils
        nfs-utils
        iproute2
        util-linux
        iptables
        procps
        nftables
      ]}

    # Desktop entry
    mkdir -p $out/share/applications
    cat > $out/share/applications/dfnet.desktop <<EOF
[Desktop Entry]
Version=1.0
Name=dfnet Network Triage
GenericName=Forensic Network Operations
Comment=MAC spoofing, static IP setup (nmtui), network share mounting, raw disk reception, and Wi-Fi hotspot AP
Exec=kitty --title "dfnet - Forensic Network Operations" sudo dfnet
Icon=network-workgroup
Terminal=false
Type=Application
Categories=System;Network;Forensics;Utility;
Keywords=forensics;network;macchanger;nmtui;smb;nfs;hotspot;
StartupNotify=true
EOF
  '';

  meta = with lib; {
    description = "Linux network triage, MAC management and stream acquisition TUI";
    homepage = "https://github.com/tylerstyle/dfnet";
    license = with licenses; [ mit asl20 ];
    mainProgram = "dfnet";
    platforms = platforms.linux;
  };
}
