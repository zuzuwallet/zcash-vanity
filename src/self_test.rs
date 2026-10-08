// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Known-answer tests. A failure aborts before any search or wallet write.
//!
//! Vectors:
//! - NIST FIPS 180-4 empty-string SHA-256, and RIPEMD-160("abc")
//! - SEC 1 generator, private key 1, compressed public key
//! - HASH160 of that point, the value published for Bitcoin P2PKH
//! - Zcash address of key 1, checked against `zcash_address` as a whole string
//! - zcashd `base58_keys_valid.json` compressed WIF and its 32-byte secret
//! - zcashd address `t1T8yaLVhNqxA5KJcmiqqFN88e8DNp2PBfF` for a published HASH160
//! - the same published secret taken through both derivation stacks
//!
//! The address `t1KNQxUEWUSsDrSw9oFSHdzT4a2HYhRteqc` is not a line zcashd
//! printed. It is that published secret under the protocol rules, accepted
//! only when libsecp256k1 and `k256`/`zcash_address` agree.

use crate::error::Error;
use crate::independent::{bitcoin_hash160, independent_address, reference_p2pkh};
use crate::verify::confirm_match;
use crate::zcash::{address_from_hash, decode_wif, encode_wif, validate_prefix, KeyEngine};

const GENERATOR_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const GENERATOR_HASH: &str = "751e76e8199196d454941c45d1b3a323f1433bd6";
const GENERATOR_ADDRESS: &str = "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs";

/// zcashd `base58_keys_valid.json`, mainnet compressed secret.
const PUBLISHED_WIF: &str = "Kz6UJmQACJmLtaQj5A3JAge4kVTNQ8gbvXuwbmCj7bsaabudb3RD";
const PUBLISHED_KEY: &str = "55c9bccb9ed68446d1b75273bbce89d7fe013a8acd1625514420fb2aca1a21c4";
const PUBLISHED_PUBKEY: &str = "02157bc6dc9dc7a25d537f36d4714c0cfc11c882f017a989e16956cc1aa8cce20a";
const PUBLISHED_HASH: &str = "106af710d5b9a4b23e8113469dda9c7088d60ff1";
const PUBLISHED_ADDRESS: &str = "t1KNQxUEWUSsDrSw9oFSHdzT4a2HYhRteqc";

/// zcashd `base58_keys_valid.json`, mainnet P2PKH script hash, not paired with the WIF above.
const VECTOR_HASH: &str = "65a16059864a2fdbc7c99a4723a8395bc6f188eb";
const VECTOR_ADDRESS: &str = "t1T8yaLVhNqxA5KJcmiqqFN88e8DNp2PBfF";

const UNCOMPRESSED_WIF: &str = "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr";

pub fn run_self_tests() -> Result<(), Error> {
    check_hashes()?;
    check_generator()?;
    check_published_secret()?;
    check_published_address_vector()?;
    check_prefix_targets()?;
    Ok(())
}

fn check_hashes() -> Result<(), Error> {
    let empty = crate::zcash::hash::sha256(b"");
    if empty
        != [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ]
    {
        return Err(Error::SelfTest("SHA-256 empty-string vector mismatch"));
    }
    let abc = crate::zcash::hash::ripemd160(b"abc");
    if abc
        != [
            0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04, 0x4a, 0x8e, 0x98, 0xc6,
            0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc,
        ]
    {
        return Err(Error::SelfTest("RIPEMD-160 abc vector mismatch"));
    }
    Ok(())
}

fn randomized_engine() -> Result<KeyEngine, Error> {
    KeyEngine::new().map_err(|_| Error::SelfTest("could not randomize the libsecp256k1 context"))
}

fn check_generator() -> Result<(), Error> {
    let mut key = [0u8; 32];
    key[31] = 1;
    let candidate = randomized_engine()?
        .candidate(&key)
        .map_err(|_| Error::SelfTest("generator scalar was rejected"))?;
    if hex(&candidate.public_key) != GENERATOR_PUBKEY {
        return Err(Error::SelfTest("generator public key mismatch"));
    }
    if hex(&candidate.hash160) != GENERATOR_HASH {
        return Err(Error::SelfTest("generator HASH160 mismatch"));
    }
    if bitcoin_hash160(&candidate.public_key) != candidate.hash160 {
        return Err(Error::SelfTest(
            "bitcoin_hashes disagreed on the generator HASH160",
        ));
    }
    let address = address_from_hash(&candidate.hash160);
    if address != GENERATOR_ADDRESS {
        return Err(Error::SelfTest("generator address mismatch"));
    }
    if reference_p2pkh(&candidate.hash160)? != GENERATOR_ADDRESS {
        return Err(Error::SelfTest(
            "zcash_address disagreed on the generator address",
        ));
    }
    confirm_match(&key, GENERATOR_ADDRESS)?;
    Ok(())
}

fn check_published_secret() -> Result<(), Error> {
    let key =
        decode_wif(PUBLISHED_WIF).map_err(|_| Error::SelfTest("published WIF was rejected"))?;
    if hex(key.as_bytes()) != PUBLISHED_KEY {
        return Err(Error::SelfTest(
            "published WIF decoded to a different secret",
        ));
    }
    if encode_wif(key.as_bytes()).as_str() != PUBLISHED_WIF {
        return Err(Error::SelfTest("published WIF did not re-encode"));
    }
    if decode_wif(UNCOMPRESSED_WIF).is_ok() {
        return Err(Error::SelfTest("uncompressed WIF was accepted"));
    }
    let candidate = randomized_engine()?
        .candidate(key.as_bytes())
        .map_err(|_| Error::SelfTest("published secret was rejected"))?;
    if hex(&candidate.public_key) != PUBLISHED_PUBKEY {
        return Err(Error::SelfTest("published secret public key mismatch"));
    }
    if hex(&candidate.hash160) != PUBLISHED_HASH {
        return Err(Error::SelfTest("published secret HASH160 mismatch"));
    }
    let address = address_from_hash(&candidate.hash160);
    if address != PUBLISHED_ADDRESS {
        return Err(Error::SelfTest("published secret address mismatch"));
    }
    let (public_key, hash, independent) = independent_address(key.as_bytes())?;
    if public_key != candidate.public_key || hash != candidate.hash160 || independent != address {
        return Err(Error::SelfTest(
            "independent stack disagreed on the published secret",
        ));
    }
    confirm_match(key.as_bytes(), PUBLISHED_ADDRESS)?;
    Ok(())
}

fn check_published_address_vector() -> Result<(), Error> {
    let hash = parse_hex20(VECTOR_HASH)?;
    if address_from_hash(&hash) != VECTOR_ADDRESS {
        return Err(Error::SelfTest("published HASH160 address mismatch"));
    }
    if reference_p2pkh(&hash)? != VECTOR_ADDRESS {
        return Err(Error::SelfTest(
            "zcash_address disagreed on the published HASH160 address",
        ));
    }
    Ok(())
}

fn check_prefix_targets() -> Result<(), Error> {
    let estimate = validate_prefix("t1ZuZu")?;
    if estimate.expected != 4_553_521 || estimate.median != 3_156_260 {
        return Err(Error::SelfTest("t1ZuZu difficulty changed"));
    }
    if estimate.vanity_portion() != "ZuZu" {
        return Err(Error::SelfTest("t1ZuZu vanity portion changed"));
    }
    for prefix in ["ZuZu", "t3ZuZu", "t3", "t1zuzu", "t30"] {
        if validate_prefix(prefix).is_ok() {
            return Err(Error::SelfTest("an impossible prefix was accepted"));
        }
    }
    Ok(())
}

fn parse_hex20(text: &str) -> Result<[u8; 20], Error> {
    let bytes = parse_hex(text)?;
    bytes
        .try_into()
        .map_err(|_| Error::SelfTest("HASH160 vector has the wrong length"))
}

fn parse_hex(text: &str) -> Result<Vec<u8>, Error> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::SelfTest("hex vector has an odd length"));
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16)
                .map_err(|_| Error::SelfTest("hex vector is not hexadecimal"))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::run_self_tests;

    #[test]
    fn known_answers_pass() {
        run_self_tests().unwrap();
    }
}
