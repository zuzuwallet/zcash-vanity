//! secp256k1 compressed public keys and mainnet P2PKH payloads.
//!
//! The search uses libsecp256k1. `k256` is only used by the independent check.
//! `SecretKey::from_slice` rejects 0 and scalars at or above the curve order.
//! This crate does not reduce a candidate modulo the order.

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::zcash::base58::base58check_encode;
use crate::zcash::hash::{checksum4, hash160};

/// Mainnet P2PKH version bytes from protocol section 5.6.1.1.
pub const P2PKH_VERSION: [u8; 2] = [0x1c, 0xb8];
pub const ADDRESS_TEXT_LEN: usize = 35;
pub const PAYLOAD_LEN: usize = 26;
pub(crate) const HASH_LEN: usize = 20;

/// One worker's libsecp256k1 context.
///
/// The `rand` feature stays off. `new` draws 32 bytes from `getrandom` and
/// passes them to `seeded_randomize`. That is libsecp256k1's recommended
/// blinding for secret-key operations, including public-key generation. The
/// seed buffer is wiped after the call. The context keeps the blinding state.
pub struct KeyEngine {
    secp: Secp256k1<secp256k1::SignOnly>,
}

/// Borrows the one `SecretKey` and overwrites it on drop.
///
/// `SecretKey` is `Copy`, so a wrapper that owned another `SecretKey` would
/// copy the scalar and leave the first value in place. This guard only holds
/// a reference. `non_secure_erase` writes `[1u8; 32]`, not zeros. Compiler
/// copies, registers, and copies inside public-key generation can remain.
struct EraseGuard<'a>(&'a mut SecretKey);

impl Drop for EraseGuard<'_> {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

impl KeyEngine {
    pub fn new() -> Result<Self, Error> {
        let mut secp = Secp256k1::signing_only();
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut_slice()).map_err(|_| Error::Rng)?;
        secp.seeded_randomize(&seed);
        Ok(Self { secp })
    }

    pub fn candidate(&self, key: &[u8; 32]) -> Result<Candidate, Error> {
        let mut secret = SecretKey::from_slice(key).map_err(|_| Error::InvalidKey)?;
        let guard = EraseGuard(&mut secret);
        let public = PublicKey::from_secret_key(&self.secp, guard.0);
        drop(guard);
        let compressed = public.serialize();
        if compressed.len() != 33 || (compressed[0] != 0x02 && compressed[0] != 0x03) {
            return Err(Error::InvalidKey);
        }
        let hash = hash160(&compressed);
        Ok(Candidate {
            public_key: compressed,
            hash160: hash,
            payload: payload_from_hash(&hash),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub public_key: [u8; 33],
    pub hash160: [u8; 20],
    pub payload: [u8; PAYLOAD_LEN],
}

pub fn payload_from_hash(hash: &[u8; HASH_LEN]) -> [u8; PAYLOAD_LEN] {
    let mut body = [0u8; 22];
    body[..2].copy_from_slice(&P2PKH_VERSION);
    body[2..].copy_from_slice(hash);
    let sum = checksum4(&body);
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..22].copy_from_slice(&body);
    payload[22..].copy_from_slice(&sum);
    payload
}

pub fn encode_payload(payload: &[u8; PAYLOAD_LEN]) -> String {
    base58check_encode(&payload[..22])
}

/// Address text for a 20-byte validating-key hash. Used by tests and the
/// independent check's comparison, not as a second derivation of the winner.
pub fn address_from_hash(hash: &[u8; HASH_LEN]) -> String {
    encode_payload(&payload_from_hash(hash))
}

#[cfg(test)]
mod tests {
    use super::{address_from_hash, KeyEngine, P2PKH_VERSION};

    #[test]
    fn version_bytes_are_mainnet_p2pkh() {
        assert_eq!(P2PKH_VERSION, [0x1c, 0xb8]);
    }

    #[test]
    fn generator_key_matches_the_published_point_and_zcash_address() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let candidate = KeyEngine::new().unwrap().candidate(&key).unwrap();
        assert_eq!(
            candidate.public_key,
            hex33("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        );
        assert_eq!(
            candidate.hash160,
            hex20("751e76e8199196d454941c45d1b3a323f1433bd6")
        );
        assert_eq!(
            address_from_hash(&candidate.hash160),
            "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs"
        );
        assert_eq!(candidate.payload[0], 0x1c);
        assert_eq!(candidate.payload[1], 0xb8);
    }

    #[test]
    fn two_times_the_generator_is_the_sec2_point() {
        let mut key = [0u8; 32];
        key[31] = 2;
        let candidate = KeyEngine::new().unwrap().candidate(&key).unwrap();
        assert_eq!(
            candidate.public_key,
            hex33("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
        );
    }

    #[test]
    fn published_zcashd_secret_matches_the_computed_address() {
        let key = hex32("55c9bccb9ed68446d1b75273bbce89d7fe013a8acd1625514420fb2aca1a21c4");
        let candidate = KeyEngine::new().unwrap().candidate(&key).unwrap();
        assert_eq!(
            candidate.public_key,
            hex33("02157bc6dc9dc7a25d537f36d4714c0cfc11c882f017a989e16956cc1aa8cce20a")
        );
        assert_eq!(
            candidate.hash160,
            hex20("106af710d5b9a4b23e8113469dda9c7088d60ff1")
        );
        assert_eq!(
            address_from_hash(&candidate.hash160),
            "t1KNQxUEWUSsDrSw9oFSHdzT4a2HYhRteqc"
        );
    }

    #[test]
    fn published_hash_matches_the_zcashd_address_vector() {
        let hash = hex20("65a16059864a2fdbc7c99a4723a8395bc6f188eb");
        assert_eq!(
            address_from_hash(&hash),
            "t1T8yaLVhNqxA5KJcmiqqFN88e8DNp2PBfF"
        );
    }

    #[test]
    fn zero_and_the_curve_order_are_rejected() {
        let engine = KeyEngine::new().unwrap();
        assert!(engine.candidate(&[0u8; 32]).is_err());
        let order = hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        assert!(engine.candidate(&order).is_err());
    }

    fn hex33(text: &str) -> [u8; 33] {
        hex(text).try_into().unwrap()
    }

    fn hex32(text: &str) -> [u8; 32] {
        hex(text).try_into().unwrap()
    }

    fn hex20(text: &str) -> [u8; 20] {
        hex(text).try_into().unwrap()
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}
