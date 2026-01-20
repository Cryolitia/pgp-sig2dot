{
  description = "pgp-sig2dot' Nix flake";
  nixConfig = {
    experimental-features = [
      "nix-command"
      "flakes"
    ];
    extra-substituters = [ "https://cryolitia.cachix.org" ];
    extra-trusted-public-keys = [
      "cryolitia.cachix.org-1:/RUeJIs3lEUX4X/oOco/eIcysKZEMxZNjqiMgXVItQ8="
    ];
  };
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };
  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      systems = [
        "x86_64-linux"
        "i686-linux"
        "aarch64-linux"
        "armv6l-linux"
        "armv7l-linux"

        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      devShells = forAllSystems (
        system:
        (
          let
            pkgs = import nixpkgs {
              config = {
                allowUnfree = true;
                cudaSupport = false;
              };
              inherit system;
            };
            rust = (pkgs.rust-bin.stable.latest.rust.override { extensions = [ "rust-src" ]; });
          in
          {
            default = (
              (pkgs.mkShell.override { stdenv = pkgs.llvmPackages.stdenv; }) {
                buildInputs =
                  (with pkgs; [
                    rust
                    pkg-config
                    nettle
                    openssl
                    sqlite
                    gnupg
                  ]);

                LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
                RUST_SRC_PATH = "${rust}/lib/rustlib/src/rust";
                LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc ];

                shellHook = ''
                  rustc --version
                  cargo --version
                  echo ${rust}

                  exec zsh
                '';
              }
            );
          }
        )
      );

      legacyPackages = forAllSystems (
        system:
        (
          let
            pkgs = import nixpkgs {
              inherit system;
            };
            lib = pkgs.lib;
            legacy-meta = with lib; {
              description = "OpenPGP sign party tool —— Visualize the Web of Trust";
              homepage = "https://github.com/Cryolitia/pgp-sig2dot";
              license = licenses.mit;
              maintainers = with maintainers; [ Cryolitia ];
            };
          in
          lib.makeScope pkgs.newScope (
            self:
            let
              inherit (self) callPackage;
            in
            {
              pgp-sig2dot = callPackage (
                {
                  lib,
                  stdenv,
                  rustPlatform,
                  installShellFiles,
                  pkg-config,
                  curl,
                  openssl,
                  nettle,
                  sqlite,
                }:
                rustPlatform.buildRustPackage {
                  pname = "pgp-sig2dot";
                  version = "unstable";

                  src = lib.cleanSource ./.;

                  cargoLock = {
                    lockFile = ./Cargo.lock;
                  };

                  buildFeatures = [
                    "map42"
                    "nix"
                  ];

                  nativeBuildInputs = [
                    pkg-config
                    rustPlatform.bindgenHook
                    installShellFiles
                  ];

                  buildInputs = [
                    openssl
                    nettle
                    sqlite
                  ] ++ lib.optionals stdenv.isDarwin [ curl ];

                  postInstall = lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
                    installShellCompletion --cmd pgp-sig2dot \
                      --bash <($out/bin/pgp-sig2dot cli complete bash) \
                      --fish <($out/bin/pgp-sig2dot cli complete fish) \
                      --zsh <($out/bin/pgp-sig2dot cli complete zsh)

                    mkdir -p manpage
                    $out/bin/pgp-sig2dot cli manpage --path manpage
                    installManPage manpage/*
                  '';

                  meta =
                    legacy-meta
                    // (with lib; {
                      mainProgram = "pgp-sig2dot";
                    });
                }
              ) { };

              pgp-sig2dot-graphviz = callPackage (
                {
                  writeShellApplication,
                  pgp-sig2dot,
                  graphviz-nox,
                }:
                writeShellApplication {
                  name = "pgp-sig2dot-graphviz";
                  runtimeInputs = [ pgp-sig2dot graphviz-nox ];
                  text = ''
                    if grep -q gossip <<<"$@"; then
                      ${pgp-sig2dot}/bin/pgp-sig2dot "$@" -t DOT | ${graphviz-nox}/bin/dot -Goverlap=false -Tsvg -Ktwopi
                    else
                      ${pgp-sig2dot}/bin/pgp-sig2dot "$@" -t DOT | ${graphviz-nox}/bin/dot -Goverlap=false -Tsvg -Ksfdp
                    fi
                  '';
                } // { meta =
                    legacy-meta
                    // (with lib; {
                      mainProgram = "pgp-sig2dot-graphviz";
                    });
                }
              ) { };
            }
          )
        )
      );

      packages = forAllSystems (
        system: nixpkgs.lib.filterAttrs (_: v: nixpkgs.lib.isDerivation v) self.legacyPackages.${system}
      );
    };
}
