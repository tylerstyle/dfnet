{
  description = "Linux network triage, MAC management, share access and Wi-Fi AP TUI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dfnet = pkgs.callPackage ./package.nix { };
      in
      {
        packages = {
          default = dfnet;
          dfnet = dfnet;
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
