//! Compressed mainnet WIF.
//!
//! Protocol section 5.6.1.2 points at Bitcoin Base58Check. zcashd
//! `EncodeSecret` uses version `0x80`, the 32-byte key, and a trailing `0x01`
//! when the public key is compressed. This tool only emits that compressed form.

use zeroize::Zeroizing;

use crate::error::Error;
use crate::secret::{SecretBytes, SecretString};
use crate::zcash::base58::{base58check_decode, base58check_encode};

const SECRET_VERSION: u8 = 0x80;
const COMPRESSED_FLAG: u8 = 0x01;

pub fn encode_wif(key: &[u8; 32]) -> SecretString {
    let mut payload = Zeroizing::new([0u8; 34]);
    payload[0] = SECRET_VERSION;
    payload[1..33].copy_from_slice(key);
    payload[33] = COMPRESSED_FLAG;
    SecretString::new(base58check_encode(payload.as_slice()))
}

pub fn decode_wif(text: &str) -> Result<SecretBytes<32>, Error> {
    let payload = base58check_decode(text)?;
    if payload.len() != 34 || payload[0] != SECRET_VERSION || payload[33] != COMPRESSED_FLAG {
        return Err(Error::Base58);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&payload[1..33]);
    let again = encode_wif(&key);
    if again.as_str() != text {
        return Err(Error::Base58);
    }
    Ok(SecretBytes::from_zeroizing(key))
}

#[cfg(test)]
mod tests {
    use super::decode_wif;

    #[test]
    fn published_compressed_wif_round_trips() {
        let text = "Kz6UJmQACJmLtaQj5A3JAge4kVTNQ8gbvXuwbmCj7bsaabudb3RD";
        let key = decode_wif(text).unwrap();
        assert_eq!(
            key.as_bytes(),
            &hex32("55c9bccb9ed68446d1b75273bbce89d7fe013a8acd1625514420fb2aca1a21c4")
        );
        let debug = format!("{key:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("55c9bccb"));
    }

    #[test]
    fn published_uncompressed_wif_is_rejected() {
        let text = "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr";
        assert!(decode_wif(text).is_err());
    }

    fn hex32(text: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }
}
