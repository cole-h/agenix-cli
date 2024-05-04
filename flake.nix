{
  description = "agenix-cli";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.flake-compat.url = "github:edolstra/flake-compat";

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        lib = pkgs.lib;
      in
      {
        packages.agenix-cli = pkgs.rustPlatform.buildRustPackage {
          pname = "agenix-cli";
          version = (lib.importTOML ./Cargo.toml).package.version;

          src = self;
          cargoLock.lockFile = ./Cargo.lock;
        };

        defaultPackage = self.packages.${system}.agenix-cli;

        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [ rustc cargo rustfmt ];
        };
      });
}
