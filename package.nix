{ lib
, rustPlatform
, makeWrapper
, macchanger
, networkmanager
, arp-scan
, cifs-utils
, nfs-utils
, netcat
, pv
, iproute2
}:

rustPlatform.buildRustPackage {
  pname = "dfnet";
  version = "0.1.0";

  src = lib.cleanSource ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [ makeWrapper ];

  postInstall = ''
    wrapProgram $out/bin/dfnet \
      --prefix PATH : ${lib.makeBinPath [
        macchanger
        networkmanager
        arp-scan
        cifs-utils
        nfs-utils
        netcat
        pv
        iproute2
      ]}
  '';

  meta = with lib; {
    description = "Modern forensic network triage, stealth MAC cloaking & stream ingest TUI";
    homepage = "https://github.com/tylerstyle/dfnet";
    license = with licenses; [ mit asl20 ];
    mainProgram = "dfnet";
    platforms = platforms.linux;
  };
}
