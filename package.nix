{ lib
, rustPlatform
, makeWrapper
, macchanger
, networkmanager
, arp-scan
, cifs-utils
, nfs-utils
, netcat-openbsd
, pv
, iproute2
, util-linux
, iptables
}:

rustPlatform.buildRustPackage {
  pname = "dfnet";
  version = "0.1.1";

  src = lib.cleanSource ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [ makeWrapper ];

  postInstall = ''
    # Install companion CLI helper
    cp scripts/dfnet.sh $out/bin/dfnet-cli
    chmod +x $out/bin/dfnet-cli

    # Compatibility symlink
    ln -s $out/bin/dfnet $out/bin/df-net

    wrapProgram $out/bin/dfnet \
      --prefix PATH : ${lib.makeBinPath [
        macchanger
        networkmanager
        arp-scan
        cifs-utils
        nfs-utils
        netcat-openbsd
        pv
        iproute2
        util-linux
        iptables
      ]}

    wrapProgram $out/bin/dfnet-cli \
      --prefix PATH : ${lib.makeBinPath [
        macchanger
        networkmanager
        arp-scan
        cifs-utils
        nfs-utils
        netcat-openbsd
        pv
        iproute2
        util-linux
        iptables
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
    description = "Modern forensic network triage, stealth MAC cloaking & stream ingest TUI";
    homepage = "https://github.com/tylerstyle/dfnet";
    license = with licenses; [ mit asl20 ];
    mainProgram = "dfnet";
    platforms = platforms.linux;
  };
}
