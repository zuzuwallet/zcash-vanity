# zcash-vanity

An offline, security-focused vanity address generator for **Zcash mainnet transparent P2PKH (`t1...`) addresses**.

`zcash-vanity` searches for a transparent Zcash address beginning with a prefix you choose, for example:

```text
t1ZuZu...
```

Each candidate uses a fresh 32-byte private-key candidate from the operating-system CSPRNG. A winning key is independently verified before it is encrypted and saved.

The private key is **not printed during generation**.

> [!WARNING]
> This tool generates **transparent `t1` addresses**.
>
> A vanity address does not add Zcash shielded privacy. Payments to a `t1` address are publicly visible on-chain. This project does not generate Sapling, Orchard, TEX, or Unified Addresses.
>
> If your goal is Zcash privacy rather than a transparent vanity address, this is not the right address type.

> [!CAUTION]
> This is key-generation software.
>
> Passing the test suite does not prove that a wallet is safe for significant funds. Review the source, dependency lockfile, wallet format, and compiled binary yourself—or have someone else review them—before funding an address produced by this program.
>
> Never paste a generated WIF, raw private key, wallet passphrase, or encrypted wallet file into a website, AI/chat system, issue tracker, shell command, or online verification service.

---

## Highlights

- Offline Zcash mainnet `t1` vanity address generation
- Fresh 32-byte OS CSPRNG draw for every candidate
- Invalid secp256k1 scalars rejected rather than reduced modulo the curve order
- Compressed secp256k1 public keys
- Zcash mainnet P2PKH version bytes `0x1C 0xB8`
- Multi-threaded vanity search
- Prefix feasibility and difficulty estimation
- Built-in known-answer self-tests
- Independent verification using `k256`, `bitcoin_hashes`, and `zcash_address`
- Argon2id + ChaCha20-Poly1305 encrypted wallet files
- Best-effort secret-memory zeroization
- Atomic, no-overwrite wallet publication
- Wallet files created with mode `0600`
- Terminal-only WIF export
- No runtime RPC, telemetry, update checker, block explorer, or HTTP client
- `#![forbid(unsafe_code)]` in this crate

The compiled generator is designed to work with networking disabled.

---

# Important: this generates transparent addresses

This project generates **mainnet transparent P2PKH addresses only**.

They begin with:

```text
t1
```

For example:

```text
t1ZuZu...
```

The `t1` portion is fixed by the Zcash mainnet P2PKH version bytes and the Base58Check encoding.

A real address is 35 characters long.

The program does **not** generate:

- `t3...` P2SH addresses
- Sapling addresses
- Orchard addresses
- TEX addresses
- Unified Addresses

It also does not substitute one of those address types when a requested `t1` prefix is impossible.

---

# What it does

For each candidate, the program:

1. Reads exactly **32 bytes** from the operating-system CSPRNG using `getrandom`.
2. Accepts them only if they represent a valid secp256k1 scalar in `1..=n-1`.
3. Derives the **compressed** SEC1 public key with libsecp256k1.
4. Computes:

```text
RIPEMD160(
    SHA256(
        compressed public key
    )
)
```

5. Prepends the Zcash mainnet P2PKH bytes:

```text
1C B8
```

6. Adds the four-byte Base58Check checksum.
7. Tests the resulting payload against the requested vanity-prefix range.
8. Builds the Base58 address only when the candidate is inside that range.
9. Performs a final textual prefix check.

A winning candidate is then verified again using an independent implementation stack before any wallet is written.

The 32-byte private scalar is encrypted and stored locally.

The WIF private key is **not displayed during generation**.

---

# Scope

This project intentionally has a narrow scope.

It supports:

- Zcash mainnet
- transparent P2PKH addresses
- compressed secp256k1 public keys
- vanity prefix searching
- encrypted standalone private-key storage
- wallet verification
- compressed mainnet WIF export

It does **not** provide:

- testnet wallets
- `t3` P2SH addresses
- shielded addresses
- Unified Addresses
- HD derivation
- BIP 32
- BIP 39
- ZIP 32
- mnemonic phrases
- transaction signing
- node RPC
- network/address lookup

This project generates **one standalone transparent private key**.

---

# Building on Fedora

The recommended workflow is:

> **Build and inspect the project while online, then disconnect before generating a real wallet.**

The recorded development checks used:

```text
rustc 1.99.0
cargo 1.99.0
```

Install the required tools:

```bash
sudo dnf install gcc python3

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

rustup component add rustfmt clippy

cargo install cargo-audit cargo-deny
```

`python3` is required by the PTY integration test.

`secp256k1` also compiles native C code, so a working C compiler is required.

Before building, a restrictive umask is recommended:

```bash
umask 077
```

Run the development checks:

```bash
cargo fmt --check

cargo clippy \
  --all-targets \
  --all-features \
  -- -D warnings

cargo test --all

cargo audit

cargo deny check advisories bans licenses sources

cargo build --release
```

Read both:

```text
Cargo.toml
Cargo.lock
```

before trusting the resulting binary.

`cargo audit` and `cargo deny` use the network to obtain security/advisory information.

The `zcash-vanity` binary itself does not.

---

# Recommended offline workflow

After building and reviewing the project, disconnect the machine from the network.

For example:

```bash
nmcli networking off
```

or physically disconnect networking.

Then run:

```bash
./target/release/zcash-vanity self-test
```

Generate an address:

```bash
./target/release/zcash-vanity generate t1ZuZu
```

Verify the encrypted wallet:

```bash
./target/release/zcash-vanity verify t1ZuZu-wallet.json
```

For wallet storage, create a private output directory:

```bash
mkdir -m 700 ~/wallet-output
```

and keep:

```bash
umask 077
```

in the shell that runs generation.

Back up the encrypted wallet before funding the address.

For an offline key-generation environment, also consider disabling or avoiding:

- shared clipboard
- shared folders
- VM snapshots containing memory
- unencrypted swap
- hibernation
- crash dumps

The host operating system and hypervisor remain part of your trust boundary.

---

# Commands

### Self-test

```bash
zcash-vanity self-test
```

Runs the built-in cryptographic known-answer checks.

### Generate

```bash
zcash-vanity generate t1ZuZu
```

Specify the worker count:

```bash
zcash-vanity generate t1ZuZu --threads 16
```

Choose the output file:

```bash
zcash-vanity generate t1ZuZu \
  --threads 16 \
  --output t1ZuZu-wallet.json
```

### Verify

```bash
zcash-vanity verify t1ZuZu-wallet.json
```

Decrypts the wallet and independently derives the stored public address again.

### Export

```bash
zcash-vanity export t1ZuZu-wallet.json
```

Displays the compressed mainnet WIF after explicit confirmation.

---

# Generation behavior

`generate` defaults to:

```text
std::thread::available_parallelism()
```

clamped to:

```text
1..=256
```

Values of `0` or greater than `256` are rejected.

The default wallet name is:

```text
{prefix}-wallet.json
```

For example:

```text
t1ZuZu-wallet.json
```

Existing output files are never overwritten.

There is no overwrite flag.

The parent directory must already exist.

If it is writable by group or others, the program prints a warning and continues. For normal offline use, create the directory with:

```bash
mkdir -m 700 ~/wallet-output
```

---

# Search difficulty

Before searching, the program displays:

- requested target
- vanity portion
- approximate expected attempts
- approximate number of attempts for a 50% chance of at least one hit

For:

```text
t1ZuZu
```

the current model gives approximately:

```text
Difficulty: approximately 4,553,521
50% probability after approximately 3,156,260
```

There is **no guaranteed completion time**.

A random search can finish much earlier—or much later—than the expected attempt count.

Prefixes estimated at one billion attempts or more require an additional confirmation:

```text
SEARCH
```

before workers begin.

---

# Why `58^4` is not the right estimate

It may be tempting to assume that four vanity characters cost:

```text
58^4 = 11,316,496
```

attempts.

That is not correct for `t1ZuZu`.

Mainnet transparent P2PKH addresses occupy a restricted numeric range because their first two bytes are fixed:

```text
1C B8
```

As a result, the characters following `t1` are not uniformly distributed across the entire Base58 alphabet.

Under the model used by this generator:

```text
t1ZuZu
```

has an expected search cost of approximately:

```text
4,553,521
```

attempts.

That estimate is a model of the encoding. It is not a proof that HASH160 outputs are perfectly uniform and it is not a wall-clock guarantee.

---

# Prefix rules

A request must describe a possible mainnet P2PKH address.

Examples:

| Prefix | Result |
|---|---|
| `t1ZuZu` | accepted |
| `ZuZu` | rejected — missing `t1` |
| `t3ZuZu` | rejected — `t3` is P2SH |
| `t30` | rejected — `0` is not in Base58 |
| `t1ZuZu0` | rejected — `0` is not in Base58 |
| `t1zuzu` | rejected — impossible for this version-byte range |
| longer than 35 characters | rejected |

The third character of a mainnet `t1` address can only be one of:

```text
HJKLMNPQRSTUVWXYZabcdefgh
```

A full address with an invalid checksum is rejected as impossible.

Extremely rare prefixes whose expected search does not fit within the implementation's attempt counter are rejected before searching.

---

# Passphrases

There is no:

```text
--password
```

option.

Passphrases are read directly from the terminal with echo disabled.

When creating a new wallet, the passphrase must contain:

- at least **12 Unicode scalar values**
- no more than **1024 bytes**

The value is not trimmed.

The 12-character minimum is only intended to stop accidental weak inputs.

It is **not** a password-strength guarantee.

For example, a predictable 12-character password can still be weak.

Use a long, unique, randomly generated passphrase for anything you intend to fund.

`verify` and `export` can still open older wallets using shorter non-empty passphrases so existing files are not stranded.

---

# Ctrl-C and cancellation

Cancellation is designed to fail safely.

Ctrl-C sets an atomic cancellation flag rather than calling:

```text
process::exit()
```

During search:

- workers observe the flag and stop;
- a candidate racing with cancellation is discarded;
- no wallet is written.

At a passphrase prompt:

- terminal echo is restored;
- the command cancels;
- no public address or private WIF is printed.

During Argon2:

- the current calculation finishes internally;
- the program checks the cancellation flag before printing success information.

`export` also checks the flag after the WIF has been encoded and immediately before printing it.

Once terminal output itself has started, it cannot be taken back.

---

# When the public address is shown

The public `t1...` address is deliberately withheld until wallet persistence has succeeded.

The sequence is:

```text
match found
      ↓
passphrase entered
      ↓
wallet encrypted
      ↓
temporary file written
      ↓
file fsynced
      ↓
final destination published
      ↓
parent directory fsynced
      ↓
private key and passphrase dropped
      ↓
FOUND
Address: t1...
```

If wallet saving fails, the program prints:

```text
Wallet was not saved successfully.
```

and does **not** display the generated public address.

This reduces the chance of someone funding an address whose private key was never safely persisted.

---

# Verifying a wallet

Run:

```bash
zcash-vanity verify t1ZuZu-wallet.json
```

The program:

1. validates the wallet format;
2. derives the Argon2id encryption key;
3. authenticates and decrypts the private scalar;
4. derives the compressed secp256k1 public key;
5. derives the Zcash `t1` address;
6. runs the independent verification stack;
7. checks that the result matches the stored public address.

On success, the decrypted private key and passphrase are dropped before the normal success output is printed.

---

# Exporting the private key

Run:

```bash
zcash-vanity export t1ZuZu-wallet.json
```

`export` is the only command that deliberately prints the private key.

It requires explicit confirmation by typing:

```text
EXPORT
```

The output format is **compressed mainnet WIF**.

The wallet itself stores the raw 32-byte scalar, not the WIF text.

> [!CAUTION]
> Anyone with the WIF can control the funds associated with that key.

Never paste the WIF into:

- a website
- an AI/chat service
- an issue report
- email
- a shell command
- an online wallet checker

After securely recording it, clear the terminal scrollback or close the terminal session.

---

# Zcash address derivation

A candidate begins as:

```text
32 random bytes
```

The complete derivation is:

```text
32-byte candidate
       ↓
valid secp256k1 scalar?
       ↓ yes
compressed SEC1 public key
       ↓
SHA-256
       ↓
RIPEMD-160
       ↓
20-byte key hash
       ↓
prepend 1C B8
       ↓
double-SHA-256 checksum
       ↓
Base58Check
       ↓
t1... mainnet address
```

## 1. Private scalar

The secp256k1 curve order is:

```text
FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

A random candidate is accepted only when:

```text
1 <= key < n
```

Zero and values greater than or equal to the curve order are discarded.

They are **not** reduced modulo `n`.

## 2. Public key

libsecp256k1 derives the compressed public key:

```text
02 || x
```

or:

```text
03 || x
```

The uncompressed:

```text
04 || x || y
```

form is not hashed for this address type.

## 3. HASH160

The public-key hash is:

```text
RIPEMD160(
    SHA256(
        compressed public key
    )
)
```

## 4. Mainnet version

The mainnet P2PKH version bytes are:

```text
1C B8
```

These produce the familiar:

```text
t1...
```

address prefix.

## 5. Base58Check

The checksum is the first four bytes of:

```text
SHA256(
    SHA256(
        version || HASH160
    )
)
```

The Base58 alphabet is:

```text
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

It excludes:

```text
0 O I l
```

---

# Independent verification

A search result is not trusted merely because the primary implementation produced the requested text.

The primary search stack uses:

- libsecp256k1 `0.30.0`
- `sha2`
- `ripemd`
- this crate's Base58Check implementation

The independent verification path uses:

- `k256 0.13.4` for secp256k1
- `bitcoin_hashes 0.16.0` for SHA-256 and RIPEMD-160
- `zcash_address 0.13.0` for Zcash address encoding

Both implementations must agree.

A mismatch returns a fatal error, prints no private key, and does not create a wallet.

The check is entirely local and does not contact a Zcash node.

---

# Known-answer tests

Self-tests run before vanity generation begins.

A failure aborts before any search or wallet write.

Examples include:

| Check | Expected value |
|---|---|
| SHA-256 of empty input | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| RIPEMD-160 of `abc` | `8eb208f7e05d987a9b044a8e98c6b087f15a0bfc` |
| Private key `1`, compressed pubkey | `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` |
| Private key `2`, compressed pubkey | `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5` |
| Address of private key `1` | `t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs` |
| Published compressed WIF | `Kz6UJmQACJmLtaQj5A3JAge4kVTNQ8gbvXuwbmCj7bsaabudb3RD` |
| Address derived from that WIF | `t1KNQxUEWUSsDrSw9oFSHdzT4a2HYhRteqc` |

The repository also includes a known uncompressed WIF that must be rejected.

Published private keys and WIFs used by the test suite are **test vectors**, not wallets generated by this program.

---

# Private-key serialization

`export` uses compressed mainnet WIF:

```text
80
||
32-byte private scalar
||
01
||
checksum
```

The checksum is the usual Base58Check double-SHA-256 checksum.

This project does not export:

- testnet WIF
- uncompressed WIF

The encrypted wallet stores the raw scalar rather than the WIF string.

---

# Encrypted wallet format

The wallet contains the encrypted **32-byte private scalar**.

It does not store plaintext WIF.

Version 1 uses:

| Property | Value |
|---|---|
| KDF | Argon2id |
| Argon2 version | 19 / `0x13` |
| Memory | 65,536 KiB |
| Iterations | 3 |
| Parallelism | 4 |
| Salt | 16 random bytes |
| Output key | 32 bytes |
| AEAD | ChaCha20-Poly1305 |
| Nonce | 12 random bytes |
| Plaintext | 32-byte scalar |
| Ciphertext | 48 bytes |
| File mode | `0600` |

Authenticated metadata includes:

```text
zcash-vanity-wallet-v1
public t1 address
p2pkh
compressed
mainnet
```

Changing any authenticated field causes decryption to fail.

Production wallet files must use the expected production Argon2 parameters.

Unexpected KDF settings are rejected before Argon2 is run.

---

# Wallet filesystem safety

Wallet creation uses a temporary file in the destination directory.

The process is:

```text
create temp file with O_CREAT | O_EXCL
        ↓
verify mode 0600
        ↓
write encrypted wallet
        ↓
fsync file
        ↓
hard-link to final destination
        ↓
refuse existing destination
        ↓
remove temporary name
        ↓
fsync parent directory
```

There is no overwrite mode.

If directory synchronization fails after publication, the command returns an error and does not print the address.

The file may still exist and can be checked with:

```bash
zcash-vanity verify <wallet>
```

Wallet reads:

- open the path once;
- use Linux `O_NOFOLLOW`;
- reject symbolic links;
- read metadata and contents from the same file descriptor;
- reject files larger than 1 MiB.

These filesystem protections currently target Linux/Fedora.

---

# Zeroization

Secret values use the `zeroize` crate where practical.

This includes:

- candidate private-key buffers
- decoded WIF buffers
- WIF Base58 working memory
- Argon2 output
- Argon2 working memory
- AEAD key material
- decrypted wallet plaintext
- exported WIF strings

libsecp256k1 private-key handling also uses a private borrowed guard that calls:

```text
non_secure_erase
```

when the temporary `SecretKey` object is dropped.

The secp256k1 context is randomized using fresh `getrandom` bytes before secret-key operations.

This remains **best-effort memory hygiene**.

It cannot guarantee removal of:

- compiler-created copies
- CPU register copies
- dependency-internal temporaries
- swap
- hibernation
- crash dumps
- VM snapshots
- memory obtained by a privileged attacker
- terminal scrollback after WIF export

A process terminated with `SIGKILL` also does not run normal destructors.

---

# Threat model

The project assumes:

- the OS CSPRNG is trustworthy;
- the CPU is trustworthy;
- the operating system is not already compromised;
- the Rust compiler/toolchain is trustworthy;
- the dependency graph has not been maliciously substituted.

The project tries to defend against errors such as:

- wrong secp256k1 derivation;
- wrong compression format;
- wrong HASH160;
- wrong mainnet P2PKH version;
- wrong Base58Check result;
- storing a private key in a world-readable file;
- passing a passphrase on the command line;
- overwriting an existing wallet;
- printing an address before the corresponding encrypted wallet exists;
- tampered wallet metadata or ciphertext;
- continuing the search after a winner has been found.

It does **not** solve:

- host malware
- keyloggers
- physical access
- root access
- memory scraping
- side-channel attacks
- weak but sufficiently long passphrases
- compromised dependencies
- bugs in libsecp256k1, `k256`, `argon2`, or `chacha20poly1305`

---

# Limitations

A few important limitations are intentional:

- The program does not ask the Zcash network whether an address has been used.
- It does not sign transactions.
- Spending requires a separate, reviewed wallet/import workflow.
- Search estimates are probabilistic.
- Workers use fresh random keys rather than splitting the keyspace deterministically.
- A process killed abruptly may not execute secret-zeroization destructors.
- Extremely difficult searches are rejected when the expected attempt count does not fit within the implementation's counter.
- This tool generates one standalone transparent key rather than an HD/ZIP 32 wallet.
- Transparent addresses do not provide shielded privacy.

---

# Benchmarks

The normal miss path performs approximately:

```text
getrandom(32 bytes)
+
secp256k1 public-key derivation
+
SHA-256
+
RIPEMD-160
+
Base58Check checksum
+
26-byte prefix-range comparison
```

Base58 text is built only when the numeric payload lies inside the requested prefix range.

Run Criterion benchmarks with:

```bash
cargo bench --bench derive
```

Benchmark results vary significantly with:

- CPU model
- system load
- VM configuration
- thermal state
- power-management settings
- thread count

Do not treat a single benchmark result as a guaranteed search speed.

---

# Dependency and security review

Notable direct dependencies include:

| Crate | Role |
|---|---|
| `argon2` | wallet KDF |
| `bitcoin_hashes` | independent HASH160 |
| `chacha20poly1305` | authenticated wallet encryption |
| `getrandom` | OS CSPRNG |
| `k256` | independent secp256k1 implementation |
| `ripemd` | primary RIPEMD-160 |
| `secp256k1` | primary libsecp256k1 implementation |
| `sha2` | primary SHA-256 |
| `zcash_address` | independent Zcash address encoder |
| `zcash_protocol` | mainnet network type |
| `zeroize` | secret-memory cleanup |
| `rpassword` | terminal passphrase input |
| `clap` | CLI |

Security/dependency checks used during development include:

```bash
cargo audit

cargo deny check advisories bans licenses sources
```

The compiled generator has no normal runtime HTTP/network stack.

The release binary was also inspected for common network-related dynamic symbols such as:

```text
connect
getaddrinfo
sendto
```

and none were found in the recorded check.

---

# Development checks

Before creating a release:

```bash
cargo fmt --check

cargo clippy \
  --all-targets \
  --all-features \
  -- -D warnings

cargo test --all

cargo audit

cargo deny check advisories bans licenses sources

cargo build --release

./target/release/zcash-vanity self-test
```

The current integration suite includes PTY tests covering:

- Ctrl-C during `verify`
- Ctrl-C during `export`
- Ctrl-C during `generate`
- terminal-echo restoration
- output-file collisions during generation
- suppression of public/private output when persistence fails

Those tests require `python3`.

---

# Repository layout

```text
Cargo.toml
Cargo.lock
deny.toml
.gitignore
LICENSE-APACHE
LICENSE-MIT
NOTICE
README.md

src/
├── lib.rs
├── main.rs
├── error.rs
├── secret.rs
├── hexutil.rs
├── self_test.rs
├── independent.rs
├── verify.rs
├── search.rs
├── wallet.rs
└── zcash/
    ├── base58.rs
    ├── hash.rs
    ├── keys.rs
    ├── prefix.rs
    ├── uint.rs
    └── wif.rs

tests/
├── vectors.rs
├── prefix.rs
├── search.rs
├── cli.rs
├── pty_ctrlc.rs
└── pty_ctrlc.py

benches/
└── derive.rs
```

---

# References

The implementation was developed against:

- Zcash Protocol Specification
- archived `zcashd` source and test vectors
- SEC 1 secp256k1 public-key conventions
- Bitcoin Base58Check/WIF conventions used by Zcash transparent keys
- RFC 9106 — Argon2
- RFC 8439 — ChaCha20-Poly1305

The independent public-address encoder uses:

```text
zcash_address 0.13.0
zcash_protocol 0.10.6
```

with mainnet network settings.

---

# License

Copyright © 2026 ZuZu Wallet

https://ZuZuWallet.com

Support@ZuZuWallet.com

Licensed under either:

- Apache License, Version 2.0 — `LICENSE-APACHE`
- MIT License — `LICENSE-MIT`

at your option.

`publish = false` is set in `Cargo.toml`.

The GitHub repository is the distribution source; this crate is not published to crates.io.
