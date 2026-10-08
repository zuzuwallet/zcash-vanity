# zcash-vanity

Offline generator for a Zcash mainnet transparent P2PKH address whose text starts with a chosen prefix.

The address this mode produces always starts with `t1`. That prefix is fixed by the mainnet P2PKH version bytes and by the 35-character length of the Base58Check encoding. For the target `t1ZuZu`, the vanity-controlled portion is `ZuZu`, matched case-sensitively. A real address is 35 characters. An illustration such as `t1ZuZu` followed by a row of `X`s is not a length claim.

`ZuZu` without `t1` is rejected. `t3ZuZu` is rejected because `t3` is mainnet P2SH, and this mode does not generate P2SH. Sapling, Orchard, TEX, and Unified Addresses are out of scope. The program does not substitute one of those when a `t1` prefix is impossible.

A `t1` address is a transparent address. Every payment to it is visible on the public chain in the same way as a Bitcoin P2PKH payment. Vanity generation does not add shielded privacy. Someone who wants current Zcash privacy should look at the Unified Address and shielded-pool design separately. This program does not create a shielded wallet, and funding a `t1` address does not create one.

Passing `cargo test` does not make a wallet appropriate for significant funds. This is key-generation software. Review the derivation, the wallet format, and the compiled binary yourself, or have someone else review them, before you send value to an address it produced. A green test run shows that this program matched the vectors and checks named below.

Never paste a generated WIF, the raw 32-byte key, the encryption passphrase, or the wallet file into a website, an AI or chat system, an issue tracker, a shell command, or an online verification service. The terminal scrollback, shell history, and process list are copies of a secret. Only the public `t1` address may be shared.

The compiled generator does not open network connections. It has no RPC client, block explorer client, telemetry, update check, or HTTP client. Generation and verification work without a network. `cargo tree` shows no `reqwest`. The release binary's dynamic symbol table, checked with `nm -u`, has no `connect`, `getaddrinfo`, or `sendto`.

## What it does

For each candidate the program:

1. Reads exactly 32 bytes from the operating-system CSPRNG (`getrandom`, one call per candidate).
2. Accepts those bytes only when they are a secp256k1 scalar in `1..=n-1`. Zero and values at or above the curve order are discarded and are not counted as attempts. The bytes are not reduced modulo `n`.
3. Derives the compressed SEC1 public key with libsecp256k1 (`0x02` or `0x03` plus the 32-byte x coordinate). Uncompressed `0x04||x||y` keys are not hashed.
4. Computes HASH160 as RIPEMD-160(SHA-256(compressed public key)).
5. Builds the 26-byte payload `[0x1C, 0xB8] || HASH160 || checksum`, where the checksum is the first 4 bytes of SHA-256(SHA-256(version || hash)).
6. Compares that payload with the inclusive bounds of the requested prefix. Base58 text is built only when the payload is inside the bounds, and the text must still start with the prefix.

The first match is checked again through `k256`, `bitcoin_hashes`, and `zcash_address` 0.13 before it is treated as found. That check runs before any wallet file is created. The 32-byte scalar is then encrypted and written to a new file created with mode `0600`. The WIF is not printed. `export` is the only command that prints a WIF, and it asks you to type `EXPORT` first.

There is no HD path, no BIP 32 / BIP 39 / ZIP 32 derivation, and no mnemonic. ZIP 32 exists in Zcash. This tool generates one standalone transparent key.

## Fedora: build online, then disconnect

Install a C compiler and Rust while the machine can reach the network. `secp256k1` compiles C code through `cc`.

```bash
sudo dnf install gcc python3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
cargo install cargo-audit cargo-deny
```

`python3` is required for the PTY test. The checks recorded in this file used rustc 1.99.0 and cargo 1.99.0. On a machine where `sudo` is unavailable, a user-local GCC works if `CC`, `AR`, `C_INCLUDE_PATH`, and `LIBRARY_PATH` point at that toolchain. A GCC configured with `--prefix=/usr` and then unpacked somewhere else does not search its own `usr/include` unless `C_INCLUDE_PATH` is set. That is an environment workaround, not the normal Fedora install.

From this directory, while still online:

```bash
umask 077
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo audit
cargo deny check advisories bans licenses sources
cargo build --release
```

Read `Cargo.toml` and `Cargo.lock` before you trust the binary. The versions below are the ones resolved for this tree. `cargo audit` and `cargo deny` download advisory data. The `zcash-vanity` binary does not.

Then disconnect and use only the binary you just built:

```bash
nmcli networking off
./target/release/zcash-vanity self-test
./target/release/zcash-vanity generate t1ZuZu
./target/release/zcash-vanity verify t1ZuZu-wallet.json
```

`nmcli networking off` may require privileges. Unplugging the network is the same step. `t3ZuZu`, `ZuZu`, and `t1zuzu` fail before a search and do not write a wallet. `self-test` was run here on the release binary and printed `Cryptographic self-tests: PASS`. A network namespace (`unshare -n`) was not permitted in this environment, so host networking was not switched off. The symbol check above is what was available instead.

Copy the wallet file to offline storage. The file mode is `0600` from the moment it is created. Keep the passphrase with the same care as the file. Set `umask 077` in the shell that runs `generate`. Put the wallet in a directory you create with `mkdir -m 700`. Only after the encrypted secret is backed up, and after a separate review of how you will spend from it, consider funding the address. This program does not sign transactions and does not ask the network whether the address has been used.

## Commands

```bash
zcash-vanity self-test
zcash-vanity generate t1ZuZu
zcash-vanity generate t1ZuZu --threads 16
zcash-vanity generate t1ZuZu --threads 16 --output t1ZuZu-wallet.json
zcash-vanity verify t1ZuZu-wallet.json
zcash-vanity export t1ZuZu-wallet.json
```

`generate` defaults to `std::thread::available_parallelism`, clamped to 1..=256. `--threads 0` and values above 256 are rejected. The default output path is `{prefix}-wallet.json`. An existing output file is refused. There is no overwrite flag. Pick a different `--output` path. The parent directory must already exist. Both checks happen before the search starts. If that directory is writable by group or others, `generate` prints a warning and continues. Create it with `mkdir -m 700`. Mode `0600` on the wallet does not stop someone who can write the directory from unlinking or replacing the file after the public address is printed.

There is no `--password` flag. The passphrase is read from the terminal with echo off. A new wallet rejects a passphrase shorter than 12 Unicode scalar values or longer than 1024 bytes. The value is not trimmed. `verify` and `export` still open a shorter passphrase so an older file is not stranded. The 12-scalar check only stops accidents. It is not a measure of guessing resistance.

Before the search, `generate` prints the target, the vanity portion, the approximate difficulty, and the attempt count at which the model gives about a 50% chance of a hit. For `t1ZuZu` that text is:

```text
Difficulty: approximately 4,553,521
50% probability after approximately 3,156,260
There is no guaranteed completion time.
```

The search is probabilistic. The counter can stop, the process can be cancelled, and the machine can be slower than any average. A prefix whose estimate is at least one billion attempts asks you to type `SEARCH` before workers start. `t1ZuZu` does not.

Ctrl-C sets an atomic flag. It does not call `process::exit`. Workers leave the candidate loop on that flag. A hit that races with Ctrl-C is discarded. If Ctrl-C arrives while the passphrase prompt is up, echo is restored and no address or WIF is printed. `export` checks the flag again after the WIF is encoded and before it is printed.

`generate` prints `FOUND` and the public address only after the wallet file has been linked into place and the parent directory has been synced. On a write error it prints `Wallet was not saved successfully.` and does not print the address. A passphrase failure prints `Wallet was not saved.` The raw key and the passphrase are dropped before the success lines. `verify` drops them before the `PASS` lines. `export` drops the passphrase after decryption and the raw key after WIF encoding, then checks the interrupt flag again, then prints `WIF:`.

## Derivation

Authoritative description: Zcash Protocol Specification version 2026.7.0-280-gfe90b7 [NU6.2], 7 October 2026, section 5.6.1.1. A mainnet transparent P2PKH raw encoding is the two version bytes `0x1CB8` followed by the 20-byte validating-key hash. The hash is RIPEMD-160(SHA-256(compressed ECDSA public key)). Section 5.6.1.2 says transparent private keys are encoded the same way as in Bitcoin. The spec cites Bitcoin Base58Check: version and payload, then the first 4 bytes of SHA-256(SHA-256(of that)). The alphabet is `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`, which excludes `0`, `O`, `I`, and lowercase `l`.

The maintained encoder used as the second implementation is `zcash_address` 0.13.0 with `zcash_protocol` 0.10.6 (`NetworkType::Main`). `ZcashAddress::from_transparent_p2pkh` is the call. Historical zcashd, archived 19 July 2026, is the source of the WIF and address test vectors. It is not linked into this binary. Its `chainparams` comment states that `{0x1C, 0xB8}` produces the `t1` prefix and `{0x1C, 0xBD}` produces `t3`.

Curve order `n` is `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`.

Every mainnet P2PKH payload is a 26-byte integer in `[0x1CB8 << 192, 0x1CB8 << 192 + 2^192)`. Both ends encode to 35 characters:

```text
t1Hsc1LR8yKnbbe3twRp88p6vFfC5nodWNB
t1hDCzSiRgWFUR5Byxr9ScwNhtAT2W3DLgW
```

The only characters shared by that whole interval are `t1`. The third character is one of `HJKLMNPQRSTUVWXYZabcdefgh` (25 symbols, not 58). Lowercase `i` is in the Base58 alphabet and is not a legal third character. `t1ZuZu` sits entirely inside the interval. `t1zuzu` does not, because `z` is past `h`.

### Why `58^4` is the wrong estimate

Four unconstrained Base58 characters would be `58^4 = 11,316,496`. That model pretends the character after `t1` is uniform over the whole alphabet. It is not. Under the model used here, every 26-byte payload that starts with `0x1CB8` is equally likely, and `t1ZuZu` covers `58^29` of them. The expected number of attempts is the nearest integer of `2^192 / 58^29`, which is 4,553,521. The fractional part is about 0.109, so round-half-up does not add one. The 50% figure is `round(4,553,521 * ln 2) = 3,156,260`. `58^4` is about 2.5 times too high for this prefix.

This is a model of the encoding, not a proof that HASH160 outputs are uniform. The checksum is part of the 26-byte value the search compares. For a short interior prefix the checksum cannot move the text out of the prefix, because the prefix bucket is far wider than 2^32. The comparison still includes it so a long or edge prefix stays exact.

`t` and `t1` cover the whole version interval, so the estimate is 1 and the vanity portion is printed as `(none)`. An interior prefix through 13 characters fits in the `u64` attempt counter. Fourteen characters does not, and the command rejects it before searching. A rare prefix that only clips the edge of the version interval can be rejected earlier for the same reason. A full 35-character string with a valid P2PKH checksum is one key out of 2^160 and is rejected because that count does not fit the counter. A full 35-character string with a bad checksum is rejected as impossible.

The in-search counter stops 1,048,576 attempts before a `u64` would wrap.

### Known answers

Self-test compares whole address strings. A failure aborts before any search or wallet write.

| Check | Value | Source |
| --- | --- | --- |
| SHA-256 of the empty string | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | FIPS 180-4 |
| RIPEMD-160 of `abc` | `8eb208f7e05d987a9b044a8e98c6b087f15a0bfc` | the RIPEMD-160 test vector |
| Private key 1, compressed | `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` | SEC 1 generator |
| Private key 2, compressed | `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5` | SEC 1, `2G` |
| HASH160 of the generator point | `751e76e8199196d454941c45d1b3a323f1433bd6` | the published Bitcoin P2PKH hash of that point. The Bitcoin address is not used |
| Address of private key 1 | `t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs` | protocol rules, agreed by libsecp256k1 and by `k256` plus `zcash_address`. Not a line zcashd printed |
| Compressed mainnet WIF | `Kz6UJmQACJmLtaQj5A3JAge4kVTNQ8gbvXuwbmCj7bsaabudb3RD` | zcashd `src/test/data/base58_keys_valid.json` |
| Secret inside that WIF | `55c9bccb9ed68446d1b75273bbce89d7fe013a8acd1625514420fb2aca1a21c4` | the same JSON row |
| Address of that secret | `t1KNQxUEWUSsDrSw9oFSHdzT4a2HYhRteqc` | protocol rules applied to the published secret. Both stacks agree. Not a line zcashd printed |
| HASH160 vector | `65a16059864a2fdbc7c99a4723a8395bc6f188eb` → `t1T8yaLVhNqxA5KJcmiqqFN88e8DNp2PBfF` | the same JSON file. This row is not the key above |
| Uncompressed WIF | `5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr` | the same JSON file. The decoder must reject it |

### Independent check

The search stack is libsecp256k1 0.30.0 (via `secp256k1-sys` 0.10.1), `sha2` 0.10.9, `ripemd` 0.1.3, and this crate's Base58Check. The check that must agree uses different code:

- `k256` 0.13.4 for the compressed public key
- `bitcoin_hashes` 0.16.0 for SHA-256 and RIPEMD-160
- `zcash_address` 0.13.0 for the `t1` text

`confirm_match` does not call this crate's address encoder twice and call that independence. A mismatch returns `FATAL ERROR — DO NOT USE THE WALLET`, prints no key, and does not create a wallet file. The check is local. It does not contact a node.

### Private-key serialization

The export format is compressed mainnet WIF, taken from zcashd `EncodeSecret` and from the JSON vector above: version byte `0x80`, the 32-byte scalar, a trailing `0x01`, then the Base58Check checksum. Bitcoin's mainnet compressed WIF uses those same bytes. This program does not copy Bitcoin testnet's `0xEF`, and it does not emit the uncompressed form (`0x80` and 32 key bytes, with no `0x01`). The protocol sentence that both Zcash networks follow Bitcoin is ambiguous next to zcashd's testnet test generator, which uses `0xEF`. Testnet is out of scope here.

The wallet stores the raw 32-byte scalar, not the WIF text. `export` prints the WIF. Importing that WIF and deriving the address again must produce the stored `t1` address. The self-test and the wallet round trip both do that, and the independent stack checks the address.

## Prefix estimate

Rejected prefixes name the reason:

| Prefix | Reason |
| --- | --- |
| `ZuZu` | this mode generates mainnet P2PKH addresses, which start with `t1` |
| `t3`, `t3ZuZu` | `t3` is mainnet P2SH |
| `t30`, `t1ZuZu0` | a character outside Base58 (`0`, `O`, `I`, and `l` are excluded). This is checked before the P2SH rule, so `t30` is an alphabet error |
| `t1zuzu`, `t1i...` | the third character can only be `HJKLMNPQRSTUVWXYZabcdefgh` |
| longer than 35 characters | longer than a P2PKH address |
| 14 or more constrained characters, when the estimate does not fit | too rare for the attempt counter |
| a full valid 35-character address | one key out of 2^160 |

## Secret storage

The wallet file holds ciphertext of the 32 raw scalar bytes. It does not hold a WIF string. Ciphertext length is 48 bytes: 32 bytes of key plus a 16-byte Poly1305 tag. Format version 1 accepts only the production KDF. `open_and_verify` returns a format error before Argon2 runs when the file asks for any other parameters, including the cheap parameters used by unit tests. The binary has no flag that selects a weaker KDF. In-crate tests use a private writer with a small Argon2 setup and still reject parameters outside fixed caps: memory at most 1,048,576 KiB, iterations 1..=100, parallelism 1..=16, and at least 8 KiB per lane.

- KDF: Argon2id, version 19 (`0x13`), memory 65536 KiB, 3 iterations, parallelism 4, 16-byte salt, 32-byte output. This is RFC 9106 section 4, second recommended option.
- AEAD: ChaCha20-Poly1305. The nonce is 12 bytes from the OS CSPRNG.
- Associated data is `zcash-vanity-wallet-v1`, a NUL, the public address, then `\0p2pkh\0compressed\0mainnet`. Changing the stored address, address type, compression flag, or network name fails authentication.

The JSON object uses `deny_unknown_fields` and a trailing newline. Fields:

```text
format_version: 1
network: "mainnet"
address_type: "p2pkh"
public_address: "t1..."
public_key_compression: "compressed"
kdf: "argon2id"
kdf_parameters: { version: 19, memory_kib, iterations, parallelism }
salt: base64, 16 bytes
cipher: "chacha20poly1305"
nonce: base64, 12 bytes
ciphertext: base64, 48 bytes
```

The salt is a top-level field. It is not repeated inside `kdf_parameters`. The public address stays in plaintext. Files larger than 1 MiB are rejected.

`confirm_match` runs inside the writer before the ciphertext is written. A mismatch does not create a file. If a mismatch were discovered only after a file already existed, the file would have to be treated as saved and unusable. This writer does not take that path.

The file is created as a temporary name in the same directory with `O_CREAT|O_EXCL` and mode `0600`. If the created mode has any group or other permission bits, the write fails and the temporary file is removed. The temp file is `fsync`ed and then hard-linked onto the destination. The link fails if the destination already exists, including when the name appears while Argon2 is running. The public writer also refuses an existing path before Argon2 starts. The temp name is removed afterward. The parent directory is `fsync`ed. If that sync fails, the wallet file is left in place, the command returns an error, and the address is not printed. Run `verify` on the file to read the public address.

Create that directory with `mkdir -m 700`. A wallet mode of `0600` does not stop another user who can write the parent directory from removing or replacing the file after `generate` has printed the public address. The command warns when the parent is group- or world-writable. It does not refuse the directory, because some shared filesystems use those modes on purpose.

A read opens the path once with the Linux `O_NOFOLLOW` flag (`0x20000`) and takes the size and the bytes from that file descriptor. A symbolic link is rejected. `ELOOP` is errno 40. That flag is Linux-specific. This program targets Fedora. `O_NOFOLLOW` is passed through `OpenOptions::custom_flags`.

Decrypting a production wallet uses about 64 MiB of RAM for a few iterations. Plan for that on the machine that runs `verify` or `export`.

### Zeroization

`SecretBytes` and `SecretString` wrap the `zeroize` crate. `Debug` prints `[redacted]`. The Argon2 output and the AEAD key are `Zeroizing`. The Argon2 working memory, about 64 MiB for a production wallet, is a `Zeroizing` boxed slice of blocks passed into `hash_password_into_with_memory`. `argon2` is built with its `zeroize` feature. Direct `generic-array` 0.14.7 is pinned with the `zeroize` feature because argon2 0.5.3 calls `GenericArray::zeroize` without enabling that feature itself.

WIF encode keeps the 34-byte payload in a `Zeroizing` buffer. Base58 encode and decode keep their working bytes in `Zeroizing` buffers, including the decoded WIF payload and the canonical re-encode used to reject a second spelling of the same bytes. Public address text is an ordinary `String`. The secret copy that remains after encoding a WIF is the `SecretString` returned to the caller. `verify` drops the decrypted key before it prints the public address. `export` drops the passphrase after decryption and the raw key after WIF encoding. The WIF string stays until the `WIF:` line. `generate` drops the passphrase and the raw key after the wallet is saved, before it prints the public address.

That is best-effort on a general-purpose Fedora workstation. It does not cover:

- copies the allocator, the compiler, or registers already made
- swap, hibernation, and crash dumps
- compiler copies, registers, and copies inside libsecp256k1 public-key generation. `SecretKey` is `Copy`. A private guard borrows that one value and calls `non_secure_erase` on drop, which overwrites it with libsecp256k1's erase pattern (`[1u8; 32]`), not with zeros. The guard does not construct a second `SecretKey`
- compiler, register, and temporary copies around `k256::SecretKey`. That type zeroizes its scalar on drop. `k256` 0.13 has no `zeroize` Cargo feature
- the per-lane address and input blocks `argon2` keeps on its own stack during key derivation
- terminal scrollback after `export`
- a process killed with `SIGKILL`, which does not run destructors

The program does not install a process-wide panic hook. Error text does not include a key, a WIF, a passphrase, or ciphertext. Disable crash dumps and swap, or encrypt swap, on a machine that will hold a key in memory. `export` is the operation that deliberately puts the WIF on the screen.

## Threat model and limitations

Assumed: the OS CSPRNG, the CPU, and the machine you build and run on are not already hostile. These break the program, and tests do not detect them:

- a compromised Fedora installation, including malware and a keylogger
- a compromised Rust compiler or toolchain
- a malicious Cargo dependency or other supply-chain substitution
- an OS CSPRNG that returns predictable bytes
- memory scraping, swap, and core dumps
- plaintext copies of the key outside this process, including a backup of the wallet file together with the passphrase
- a weak encryption passphrase, including one that passes the 12-character check
- an implementation error, including a wrong version byte or a wrong checksum
- a verifier that is not actually independent of the generator

In scope, and what the tests are aimed at: the compressed public key, HASH160, the `0x1CB8` version bytes, Base58Check, a key that does not match the stored address, a wallet file left world-readable, a passphrase on the command line, a search that continues after the first hit, and a damaged or substituted ciphertext.

Out of scope, and not solved here: malware on the host, someone reading the terminal during `export`, physical access, side channels, and bugs inside libsecp256k1, `k256`, `zcash_address`, `argon2`, or `chacha20poly1305`. Each libsecp256k1 context is randomized from `getrandom` before public-key generation. That is the library's recommended hardening for secret-key operations. Side channels stay out of scope.

Further limits:

- The tool never asks the network if the address is already in use. This program does not check.
- There is no signing path. Spending from the address still needs a separate, reviewed wallet.
- Successful tests do not make this software appropriate for storing significant funds.
- Workers stop on the first match. Another worker can have drawn a key it then discards. That buffer is zeroized when the `Zeroizing` value drops. A killed process does not run that drop.
- If any worker panics or the RNG fails, a match from another worker is discarded and no wallet is written.
- A hit that races with Ctrl-C is discarded.
- Attempt counters stop with an error before a `u64` would wrap.
- `generate` and `write_encrypted_wallet` reject a new passphrase shorter than 12 Unicode scalar values. Argon2id does not rescue a guessable passphrase.
- Public wallet reads and writes accept only the production Argon2 parameters.
- Workers do not split the key space. Each draw is a fresh 32-byte OS read. There is no counter used as a key and no per-worker seed.

## Assumptions that were not executed

- zcashd and `zcash-cli` were not built or run. The version bytes, the `t1`/`t3` split, and the WIF layout were read from the protocol PDF and from the archived zcashd sources and test JSON.
- `t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs` and `t1KNQxUEWUSsDrSw9oFSHdzT4a2HYhRteqc` were not printed by zcashd. Each is the protocol applied to a known scalar, then accepted because libsecp256k1 and `k256`/`zcash_address` produced the same address.
- The testnet WIF discrepancy (`0xEF` in zcashd's test generator versus the protocol's "same as Bitcoin" sentence) was not resolved. This tool does not generate testnet keys.
- The difficulty figure is a model. It is not a proof that HASH160 is uniform, and it is not a completion-time guarantee.
- `nmcli networking off` was not run. `unshare -n` returned `Operation not permitted`.
- No live `t1ZuZu` search was run, and no generated wallet was funded.
- `perf` is not installed here, so there is no sampled profile. The miss path in this crate does not call Base58 and does not build an address `String`. That does not prove libsecp256k1 avoids internal allocation.

## Benchmarks

Correctness is the constraint. The hot loop was measured after the known-answer tests passed. A miss is one `getrandom` of 32 bytes, one libsecp256k1 compressed public key, HASH160, the 4-byte checksum, and a 26-byte compare. Base58 runs only after the payload is inside the prefix bounds.

The fixed key in `miss_without_base58` is the secp256k1 generator (private key 1). Its address is `t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs`, which does not start with `t1ZuZu`, so the compare takes the miss path. The bench does not print that address. `getrandom_and_miss` draws a fresh key each iteration and zeroizes the buffer.

Two runs on this 16-thread machine disagreed. Criterion's "regressed" line on the second run is that comparison. The source did not change between them.

| Bench | 10 samples, ~2 s | 20 samples, ~4 s |
| --- | --- | --- |
| `miss_without_base58` | 28.41 µs (21.60–37.98), two high outliers | 83.96 µs (63.89–105.94), two low outliers |
| `getrandom_and_miss` | 21.47 µs (21.29–21.76) | not remeasured |

At 21.5 µs a single core is on the order of 46,000 candidates per second. At 84 µs it is on the order of 12,000. Do not treat either row as the machine's capacity, and do not turn it into a promised completion time. `t1ZuZu` expects about 4,553,521 attempts under the model above. Cores do not have to scale linearly, `getrandom` can contend, and the machine can be busy. Repeat the measurement with:

```bash
cargo bench --bench derive
```

## Dependency and security review

Direct dependencies, from the resolved `Cargo.lock`:

| Crate | Version | Role |
| --- | --- | --- |
| argon2 | 0.5.3 | Argon2id, `zeroize` feature on |
| generic-array | 0.14.7 | Enables `GenericArray::zeroize` for argon2 0.5.3 |
| base64 | 0.22.1 | Wallet encoding |
| bitcoin_hashes | 0.16.0 | Independent HASH160 |
| chacha20poly1305 | 0.10.1 | AEAD |
| clap | 4.6.7 | CLI |
| ctrlc | 3.5.2 | Ctrl-C flag |
| getrandom | 0.2.17 | OS CSPRNG. One 32-byte draw per candidate, plus one 32-byte context seed per libsecp256k1 engine |
| k256 | 0.13.4 | Independent secp256k1. No `zeroize` Cargo feature. `SecretKey` still zeroizes its scalar on drop |
| ripemd | 0.1.3 | Search-path RIPEMD-160 |
| rpassword | 7.5.4 | Passphrase prompt |
| secp256k1 | 0.30.0 | Search-path libsecp256k1. `rand` is not enabled. Each context is seeded with `getrandom` through `seeded_randomize` |
| serde / serde_json | 1.0.229 / 1.0.151 | Wallet JSON |
| sha2 | 0.10.9 | Search-path SHA-256 |
| thiserror | 2.0.21 | Errors |
| zcash_address | 0.13.0 | Independent `t1` encoder |
| zcash_protocol | 0.10.6 | `NetworkType::Main` |
| zeroize | 1.9.1 | Secret wipe |
| criterion | 0.5.1 | Benchmarks only |

`zcash_address` 0.13.0 brings `bech32` 0.11.1 and `bs58` 0.5.1. This crate does not call `bs58`. The search Base58Check is the code in `src/zcash/base58.rs`. `blake2` 0.10.6 is pulled in by `argon2`.

`Cargo.lock` also records `bitcoin_hashes` 0.14.101 and `rand` as optional dependencies of `secp256k1` 0.30.0. `cargo tree -p secp256k1@0.30.0` shows only `secp256k1-sys` and its build dependency `cc`. `cargo tree -i rand` is empty. Those optional crates are not in the compiled graph. The `rand` feature of `secp256k1` stays off. Candidate scalars and the 32-byte context seed both come from `getrandom`. Context blinding uses `seeded_randomize`, which does not need the `rand` feature.

`argon2` 0.5.3's `zeroize` feature calls `GenericArray::zeroize` but does not enable that impl. The direct `generic-array` dependency turns it on for the copy already required by `blake2`. It is not a second hash implementation.

`cargo audit` 0.22.2 loaded 1294 RustSec advisories and scanned 166 crate dependencies. Exit code 0. No vulnerability text was printed.

`cargo deny` 0.20.2 with `deny.toml`: advisories ok, bans ok, licenses ok, sources ok (crates.io only). Exit code 0. It warned that `BSD-1-Clause` and `ISC` are on the allow-list and were not encountered. This lockfile has no crate under those two licenses. The allowance is unused.

The license allow-list is MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-3-Clause, BSD-1-Clause, ISC, Unicode-3.0, CC0-1.0, Unlicense, and Zlib.

`cargo-geiger` was not installed. This crate's library, binary, integration tests, and benchmark set `#![forbid(unsafe_code)]`. libsecp256k1, `k256`, and other dependencies contain unsafe code inside their own crates.

Recorded local gates, after the source in this tree was in place:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all` (55 tests)
- `cargo audit`
- `cargo deny check`
- `cargo build --release`
- `./target/release/zcash-vanity self-test`
- release `generate` of `t3ZuZu`, `ZuZu`, and `t1zuzu`, each with no wallet file created

## Layout

```text
Cargo.toml
Cargo.lock
deny.toml
.gitignore          /target and *-wallet.json
LICENSE-APACHE
LICENSE-MIT
README.md
src/lib.rs            crate root, no unsafe
src/main.rs           CLI
src/error.rs
src/secret.rs         zeroizing wrappers
src/hexutil.rs
src/self_test.rs      known answers, run before a search
src/independent.rs    k256, bitcoin_hashes, zcash_address
src/verify.rs         both stacks must agree
src/search.rs         threads, cancellation, one getrandom per candidate
src/wallet.rs         Argon2id, ChaCha20-Poly1305, and wallet tests
src/zcash/base58.rs   Base58Check
src/zcash/hash.rs     SHA-256, RIPEMD-160, HASH160
src/zcash/keys.rs     libsecp256k1 compressed P2PKH payload
src/zcash/prefix.rs   version-byte range and the attempt estimate
src/zcash/uint.rs     256-bit arithmetic for prefix setup only
src/zcash/wif.rs      compressed mainnet WIF
tests/vectors.rs
tests/prefix.rs
tests/search.rs
tests/cli.rs
tests/pty_ctrlc.rs
tests/pty_ctrlc.py
benches/derive.rs
```

## Tests

`cargo test --all` covers secp256k1 rejection of zero and of the curve order, the generator and `2G` compressed points, HASH160, the `0x1CB8` version bytes, the Base58 alphabet, Base58Check, the zcashd WIF and address vectors, the full `t1` strings above, prefix rejection, the `t1ZuZu` estimate, multithreaded cancellation, a `t1` search that stops every worker, encrypted round trip, mode `0600`, wrong passphrase, tampered ciphertext, tampered address, truncated JSON, unknown fields, hostile KDF parameters, non-production KDF rejection, symlink rejection, overwrite refusal, WIF import back to the same address, and an independent-check mismatch. One test runs `python3` on a PTY: Ctrl-C at the `verify`, `export`, and `generate` passphrase prompts must restore echo, cancel, print no WIF, and print no address before a wallet exists. The same test plants a file at the output path during the `generate` passphrase prompt and checks that the command fails with no `FOUND` line and no `Address:` line. That test fails if `python3` is not installed. The passphrase in that test is a fixture, not a secret to reuse.

Integration tests find the binary via `CARGO_BIN_EXE` when cargo provides it, and otherwise via `target/debug` or `target/release`. A custom `CARGO_TARGET_DIR` can break that fallback.

## License

Copyright (c) 2026 ZuZu Wallet.

Licensed under either of

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.

`publish = false` in `Cargo.toml`. This GitHub repository is the release. The crate is not published to crates.io.
