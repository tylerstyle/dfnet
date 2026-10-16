{
  description = "Linux network triage, MAC management, share access and Wi-Fi AP TUI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Shared safety core, a sibling Cargo path dependency
    dfcore = {
      url = "github:tylerstyle/dfcore";
      flake = false;
    };
    # dfstream/1 protocol crate, a sibling Cargo path dependency (../dflive/dfstream)
    dflive = {
      url = "github:tylerstyle/dflive";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, dfcore, dflive }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dfnet = pkgs.callPackage ./package.nix { dfcoreSrc = dfcore; dfliveSrc = dflive; };
      in
      {
        packages = {
          default = dfnet;
          dfnet = dfnet;
        };

        checks = pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          pcap = import ./tests/pcap.nix { inherit pkgs dfnet; };
        };

        apps = {
          default = flake-utils.lib.mkApp {
            drv = dfnet;
          };
          dfnet = flake-utils.lib.mkApp {
            drv = dfnet;
          };
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ dfnet ];
          buildInputs = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
          ];
        };
      }
    );
}
