{ lib
, rustPlatform
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
}:

rustPlatform.buildRustPackage {
  pname = "dfnet";
  version = "0.1.3";

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
