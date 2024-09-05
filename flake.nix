{
  description = "pgp-sig2dot' Nix flake";
  nixConfig = {
    experimental-features = [
      "nix-command"
      "flakes"
    ];
    substituters = [
      # "https://mirrors.cernet.edu.cn/nix-channels/store"
      # "https://mirrors.bfsu.edu.cn/nix-channels/store"
      "https://cache.nixos.org/"
    ];
    extra-substituters = [ "https://cryolitia.cachix.org" ];
    extra-trusted-public-keys = [
      "cryolitia.cachix.org-1:/RUeJIs3lEUX4X/oOco/eIcysKZEMxZNjqiMgXVItQ8="
    ];
  };
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
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
              overlays = [ (import rust-overlay) ];
            };
            rust = (pkgs.rust-bin.stable.latest.rust.override { extensions = [ "rust-src" ]; });

            pythonVersion = "python311";
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
                  ])
                  ++ (with pkgs."${pythonVersion}Packages"; [
                    python
                    venvShellHook
                    virtualenv

                    dash
                    matplotlib
                    networkx
                    numpy
                    pandas
                    pydot
                  ]);

                LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
                RUST_SRC_PATH = "${rust}/lib/rustlib/src/rust";
                LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc ];

                shellHook = ''
                  rustc --version
                  cargo --version
                  echo ${rust}

                  echo "`${pkgs."${pythonVersion}Packages".python}/bin/python3 --version`"
                  rm -v python-part/.venv/bin/python
                  virtualenv --no-setuptools python-part/.venv
                  export PATH=$PWD/python-part/.venv/bin:$PATH
                  export PYTHONPATH=$PWD/python-part/.venv/lib/${pythonVersion}/site-packages/:$PYTHONPATH

                  exec zsh
                '';

                postShellHook = ''
                  ln -sf PYTHONPATH/* ${pkgs.virtualenv}/lib/${pythonVersion}/site-packages
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
              overlays = [ (import rust-overlay) ];
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
              pgp-sig2dot-rust-part = callPackage (
                {
                  lib,
                  stdenv,
                  rust-bin,
                  makeRustPlatform,
                  installShellFiles,
                  pkg-config,
                  curl,
                  openssl,
                  nettle,
                  sqlite,
                }:
                let
                  rustPlatform = makeRustPlatform {
                    cargo = rust-bin.stable.latest.minimal;
                    rustc = rust-bin.stable.latest.minimal;
                  };
                in
                rustPlatform.buildRustPackage {
                  pname = "pgp-sig2dot-rust-part";
                  version = "unstable";

                  src = lib.cleanSource ./rust-part;

                  cargoLock = {
                    lockFile = ./rust-part/Cargo.lock;
                  };

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
                      --bash <($out/bin/pgp-sig2dot gen complete bash) \
                      --fish <($out/bin/pgp-sig2dot gen complete fish) \
                      --zsh <($out/bin/pgp-sig2dot gen complete zsh)

                    mkdir -p manpage
                    $out/bin/pgp-sig2dot gen man --path manpage
                    installManPage manpage/*
                  '';

                  meta =
                    legacy-meta
                    // (with lib; {
                      mainProgram = "pgp-sig2dot";
                    });
                }
              ) { };

              visdcc = callPackage (
                {
                  lib,
                  python3Packages,
                  fetchPypi,
                }:
                python3Packages.buildPythonPackage rec {
                  pname = "visdcc";
                  version = "0.0.50";
                  pyproject = true;

                  src = fetchPypi {
                    inherit pname version;
                    hash = "sha256-IqtHcCfaMsoZa/cXXBL4a1CTb9wiJPw67n2or4y70as=";
                  };

                  build-system = [ python3Packages.setuptools ];

                  meta = with lib; {
                    description = "Dash Core Components for Visualization";
                    homepage = "https://github.com/jimmybow/visdcc";
                    license = licenses.mit;
                    maintainers = with maintainers; [ Cryolitia ];
                  };
                }
              ) { python3Packages = pkgs.python3Packages; };

              dash-bootstrap-components-legacy = callPackage (
                { python3Packages, fetchPypi }:
                python3Packages.buildPythonPackage rec {
                  pname = "dash-bootstrap-components";
                  version = "0.13.1";
                  pyproject = true;

                  src = fetchPypi {
                    inherit pname version;
                    hash = "sha256-BK11w3vsAFrBzA/3v7VkXz4sdarKz6ESecQy9Mg65wo=";
                  };

                  build-system = [ python3Packages.setuptools ];

                  dependencies = with python3Packages; [ dash ];

                  meta = python3Packages.dash-bootstrap-components.meta;
                }
              ) { python3Packages = pkgs.python3Packages; };

              jaal = callPackage (
                {
                  lib,
                  python3Packages,
                  fetchFromGitHub,
                  visdcc,
                  dash-bootstrap-components-legacy,
                }:
                python3Packages.buildPythonPackage {
                  pname = "jaal";
                  version = "0.1.7";
                  pyproject = true;

                  src = fetchFromGitHub {
                    owner = "imohitmayank";
                    repo = "jaal";
                    rev = "v0.1.7";
                    hash = "sha256-/XlybjeDGfkchnOXTgJ8odUcgY0X7TlJX8MC7eNXFB8=";
                  };

                  build-system = [ python3Packages.setuptools ];

                  dependencies = with python3Packages; [
                    dash
                    pandas
                    visdcc
                    dash-bootstrap-components-legacy
                  ];

                  meta = with lib; {
                    description = "Your interactive network visualizing dashboard";
                    homepage = "https://github.com/imohitmayank/jaal";
                    license = licenses.mit;
                    maintainers = with maintainers; [ Cryolitia ];
                  };
                }
              ) { python3Packages = pkgs.python3Packages; };

              pgp-sig2dot-python-part = callPackage (
                {
                  lib,
                  python3Packages,
                  jaal,
                }:
                python3Packages.buildPythonApplication {
                  pname = "pgp-sig2dot-python-part";
                  version = "unstable";
                  pyproject = true;

                  src = lib.cleanSource ./python-part;

                  build-system = [ python3Packages.setuptools ];

                  dependencies = with python3Packages; [
                    jaal
                    matplotlib
                    networkx
                    pandas
                    pydot
                  ];

                  meta = legacy-meta;
                }
              ) { python3Packages = pkgs.python3Packages; };

              pgp-sig2dot-jaal = callPackage (
                {
                  writeShellApplication,
                  pgp-sig2dot-python-part,
                  pgp-sig2dot-rust-part,
                }:
                writeShellApplication {
                  name = "pgp-sig2dot-jaal";
                  runtimeInputs = [ pgp-sig2dot-rust-part pgp-sig2dot-rust-part ];
                  text = ''
                    ${pgp-sig2dot-rust-part}/bin/pgp-sig2dot "$@" | ${pgp-sig2dot-python-part}/bin/pgp-sig2dot-python-part.py --jaal
                  '';
                }
              ) { };

              pgp-sig2dot-networkx = callPackage (
                {
                  writeShellApplication,
                  pgp-sig2dot-python-part,
                  pgp-sig2dot-rust-part,
                }:
                writeShellApplication {
                  name = "pgp-sig2dot-networkx";
                  runtimeInputs = [ pgp-sig2dot-rust-part pgp-sig2dot-rust-part ];
                  text = ''
                    ${pgp-sig2dot-rust-part}/bin/pgp-sig2dot "$@" | ${pgp-sig2dot-python-part}/bin/pgp-sig2dot-python-part.py --networkx
                  '';
                }
              ) { };

              pgp-sig2dot-graphviz = callPackage (
                {
                  writeShellApplication,
                  pgp-sig2dot-rust-part,
                  graphviz-nox,
                }:
                writeShellApplication {
                  name = "pgp-sig2dot-graphviz";
                  runtimeInputs = [ pgp-sig2dot-rust-part graphviz-nox ];
                  text = ''
                    if grep -q gossip <<<"$@"; then
                      ${pgp-sig2dot-rust-part}/bin/pgp-sig2dot --simple "$@" | ${graphviz-nox}/bin/dot -Goverlap=false -Tsvg -Ktwopi
                    else
                      ${pgp-sig2dot-rust-part}/bin/pgp-sig2dot --simple "$@" | ${graphviz-nox}/bin/dot -Goverlap=false -Tsvg -Ksfdp
                    fi
                  '';
                }
              ) { };

              pgp-sig2dot = callPackage (
                {
                  runCommand,
                  pgp-sig2dot-rust-part,
                  pgp-sig2dot-python-part,
                  pgp-sig2dot-jaal,
                  pgp-sig2dot-networkx,
                  pgp-sig2dot-graphviz,
                }:
                runCommand "pgp-sig2dot" { } ''
                  mkdir -p $out/bin

                  ln -s ${pgp-sig2dot-rust-part}/bin/pgp-sig2dot $out/bin/pgp-sig2dot
                  ln -s ${pgp-sig2dot-python-part}/bin/pgp-sig2dot-python-part.py $out/bin/pgp-sig2dot-python-part
                  ln -s ${pgp-sig2dot-jaal}/bin/pgp-sig2dot-jaal $out/bin/pgp-sig2dot-jaal
                  ln -s ${pgp-sig2dot-networkx}/bin/pgp-sig2dot-networkx $out/bin/pgp-sig2dot-networkx
                  ln -s ${pgp-sig2dot-graphviz}/bin/pgp-sig2dot-graphviz $out/bin/pgp-sig2dot-graphviz

                  ln -s ${pgp-sig2dot-rust-part}/share $out/share
                ''
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
