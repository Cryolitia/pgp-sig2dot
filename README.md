# pgp-sig2dot

OpenPGP sign party tool —— Visualize the Web of Trust

This project is a part of [the Department of Infrastructure of Project Trans](https://github.com/project-trans/wkd), and powers [Nix CN Meetup](https://nixos.party/).


## Gallery

![https://openpgpkey.project-trans.org/](https://openpgpkey.project-trans.org/wot.svg)

## Usage Example

Run `pgp-sig2dot --help` to find out how to use it.

- Show the web of trust in Nix CN Meetup keyring(not provide in this repo), show only primary uid, fetching new signatures
  on keyserver

    ```sh
    cat nixcn.gpg | pgp-sig2dot --import - -p --online
    ```

- Show the web of trust from specified keys, automatically fetching from keyserver

    ```sh
    pgp-sig2dot draw -vv -k 1C3C6547538D7152310C0EEA84DD0C0130A54DF7 892EBC7DC392DFF9C9C03F1D15F4180E73787863 CEDBA39E576BC6C21B71A64825E82BBEA32BD476
    ```

- Show the web of trust with `graphiz` backend

    ```sh
    gpg --export | pgp-sig2dot draw -t DOT --import - | dot -Goverlap=false -Tsvg -Ksfdp > temp.svg
    ```

- Finding a key by GitHub username

  ```sh
  pgp-sig2dot fetch Cryolitia
  ```

- Show help

    ```sh
    pgp-sig2dot --help
    ```
