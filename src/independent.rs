//! Independent transparent-address derivation.
//!
//! `k256` derives the compressed secp256k1 point. `bitcoin_hashes` computes
//! HASH160. `zcash_address` 0.13 encodes a mainnet P2PKH address. None of
//! those steps call this crate's Base58Check or libsecp256k1.
//!
//! `k256::SecretKey` zeroizes its scalar on drop. Compiler, register, and
//! internal temporary copies can remain. The caller's `SecretBytes` is the
//! buffer this crate wipes.

use bitcoin_hashes::{Ripemd160, Sha256};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use zcash_address::{ToAddress, ZcashAddress};
use zcash_protocol::consensus::NetworkType;

use crate::error::Error;
use crate::zcash::ADDRESS_TEXT_LEN;

/// Compressed SEC1 public key from `k256`.
pub fn k256_compressed(key: &[u8; 32]) -> Result<[u8; 33], Error> {
    let secret = k256::SecretKey::from_slice(key).map_err(|_| Error::VerificationFailed)?;
    let point = secret.public_key().to_encoded_point(true);
    let bytes = point.as_bytes();
    if bytes.len() != 33 || (bytes[0] != 0x02 && bytes[0] != 0x03) {
        return Err(Error::VerificationFailed);
    }
    let mut public_key = [0u8; 33];
    public_key.copy_from_slice(bytes);
    drop(secret);
    Ok(public_key)
}

/// RIPEMD-160(SHA-256(data)) from `bitcoin_hashes`.
pub fn bitcoin_hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::hash(data);
    let ripe = Ripemd160::hash(sha.as_byte_array());
    *ripe.as_byte_array()
}

/// Mainnet P2PKH text from `zcash_address` 0.13.
pub fn reference_p2pkh(hash: &[u8; 20]) -> Result<String, Error> {
    let address = ZcashAddress::from_transparent_p2pkh(NetworkType::Main, *hash);
    let text = address.to_string();
    if text.len() != ADDRESS_TEXT_LEN || !text.starts_with("t1") {
        return Err(Error::VerificationFailed);
    }
    Ok(text)
}

/// Public key, HASH160, and address, all from the independent stack.
pub fn independent_address(key: &[u8; 32]) -> Result<([u8; 33], [u8; 20], String), Error> {
    let public_key = k256_compressed(key)?;
    let hash = bitcoin_hash160(&public_key);
    let address = reference_p2pkh(&hash)?;
    Ok((public_key, hash, address))
}
