{
  description = "agenix-cli";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-20.09";
  inputs.crate2nix = { url = "github:kolloch/crate2nix"; flake = false; };
  inputs.mozilla = { url = "github:mozilla/nixpkgs-mozilla"; flake = false; };

  outputs =
    { self
    , nixpkgs
    , mozilla
    , ...
    } @ inputs:
    let
      nameValuePair = name: value: { inherit name value; };
      genAttrs = names: f: builtins.listToAttrs (map (n: nameValuePair n (f n)) names);
      allSystems = [ "x86_64-linux" "aarch64-linux" "i686-linux" "x86_64-darwin" ];

      rustOverlay = final: prev:
        let
          rustChannel = prev.rustChannelOf {
            channel = "1.47.0";
            sha256 = "1hkisci4as93hx8ybf13bmxkj9jsvd4a9ilvjmw6n64w4jkc1nk9";
          };
        in
        {
          inherit rustChannel;
          rustc = rustChannel.rust;
          cargo = rustChannel.rust;
        };

      forAllSystems = f: genAttrs allSystems (system: f {
        inherit system;
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (import "${mozilla}/rust-overlay.nix")
            rustOverlay
          ];
        };
      });

      crate2nix = forAllSystems ({ system, ... }:
        let
          sources = import "${inputs.crate2nix}/nix/sources.nix";
          pkgs = import sources.nixpkgs { inherit system; };
          cargoNix = import "${inputs.crate2nix}/crate2nix/Cargo.nix" {
            inherit pkgs;
            defaultCrateOverrides = pkgs.defaultCrateOverrides // {
              cssparser-macros = { ... }: {
                buildInputs = with pkgs;
                  lib.optionals stdenv.isDarwin [ darwin.apple_sdk.frameworks.Security ];
              };
            };
          };
        in
        cargoNix.rootCrate.build);
    in
    {
      # for use with update.sh script
      inputs = builtins.removeAttrs inputs [ "self" ];

      devShell = forAllSystems ({ system, pkgs, ... }:
        pkgs.mkShell {
          name = "agenix";

          # Eventually crate2nix will provide a devShell that includes transitive dependencies for us.
          # https://github.com/kolloch/crate2nix/issues/111
          buildInputs = with pkgs; [
            # rustChannel.rust provides tools like clippy, rustfmt, cargo,
            # rust-analyzer, rustc, and more.
            (rustChannel.rust.override { extensions = [ "rust-src" ]; })
            crate2nix.${system}
          ];
        });

      packages = forAllSystems
        ({ system, pkgs, ... }:
          let
            agenix =
              let
                cargoNix = import ./Cargo.nix {
                  inherit pkgs;
                };
              in
              cargoNix.rootCrate.build // {
                # buildRustCrate prefixes the package's name with `rust_`,
                # making `nix run` fail. Force the name to `agenix`.
                name = "agenix";
              };
          in
          {
            inherit agenix;
          });

      defaultPackage = forAllSystems ({ system, ... }: self.packages.${system}.agenix);
    };
}
