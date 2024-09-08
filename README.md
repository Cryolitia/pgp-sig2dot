# pgp-sig2dot

OpenPGP sign party tool —— Visualize the Web of Trust

This tool contains two part:

1. The Rust part parse OpenPGP data, fetching keys from keyserver, and output the DOT of the web of trust.
2. The second part parse DOT input, and call [jaal](https://github.com/imohitmayank/jaal)
   or [networkx](https://github.com/networkx/networkx) or [graphviz](https://graphviz.org/) as a visualization backend.

## Gallery

![demo](https://github.com/Cryolitia/pgp-sig2dot/blob/main/demo.png?raw=true)
![https://openpgpkey.project-trans.org/](https://openpgpkey.project-trans.org/wot.svg)

## Usage Example

### Cargo

The Rust part can be used independently and output in DOT format, and can be further used with tools such as graphviz.

This part has been published to creates.io: https://crates.io/crates/pgp-sig2dot

Run `pgp-sig2dot --help` to find out how to use it.

### Nix

This set of tools is further packaged into Nix, making it easy to use out of the box.

- Show the web of trust in `gpg` keyring, show only primary uid, use `networkx` as backend.

    ```sh
    gpg --export | nix run github:Cryolitia/pgp-sig2dot#pgp-sig2dot-networkx -- -vv --import - -p
    ```

- Show the web of trust in AOSCC 2024 keyring(not provide in this repo), show only primary uid, fetching new signatures
  on keyserver, use `networkx` as backend.

    ```sh
    cat aoscc2024.gpg | nix run github:Cryolitia/pgp-sig2dot#pgp-sig2dot-networkx -- -vv --import - -p --online
    ```

- Show the web of trust from specified keys, automatically fetching from keyserver, use jaal as backend

    ```sh
    nix run github:Cryolitia/pgp-sig2dot#pgp-sig2dot-jaal -- -vv -k 1C3C6547538D7152310C0EEA84DD0C0130A54DF7 892EBC7DC392DFF9C9C03F1D15F4180E73787863 CEDBA39E576BC6C21B71A64825E82BBEA32BD476
    ```

- Show the web of trust with `graphiz` backend

    ```sh
    gpg --export | nix run github:Cryolitia/pgp-sig2dot#pgp-sig2dot-graphviz -- -vv --import - > temp.svg
    ```

- Show help of the rust part

    ```sh
    nix run github:Cryolitia/pgp-sig2dot#pgp-sig2dot-rust-part -- --help
    ```
