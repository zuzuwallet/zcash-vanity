//! Prefix checks for mainnet transparent P2PKH addresses.
//!
//! Every such address is the Base58 encoding of a 26-byte payload:
//! `[0x1C, 0xB8] || HASH160 || checksum`. That payload is an integer in
//! `[0x1CB8 << 192, 0x1CB8 << 192 + 2^192)`. Both ends encode to 35 characters,
//! and the only characters shared by the whole interval are `t1`.
//!
//! The third character is not uniform. Only 25 Base58 symbols occur there.
//! A requested prefix is converted to the same integer interval, intersected
//! with the version-byte interval, and compared as 26-byte big-endian bounds.
//! The checksum stays inside those bounds. Base58 text is produced only after
//! a payload lands in the interval.
//!
//! `expected` is `round(2^192 / overlap)` under a model that treats every
//! 26-byte payload with the version prefix as equally likely. It is not a
//! proof that HASH160 is uniform, and it is not a promise of wall-clock time.

use crate::error::Error;
use crate::zcash::base58::{alphabet_index, base58_decode};
use crate::zcash::keys::{ADDRESS_TEXT_LEN, P2PKH_VERSION, PAYLOAD_LEN};
use crate::zcash::uint::U256;

pub(crate) const SEARCH_COUNTER_HEADROOM: u64 = 1_048_576;
pub const CONFIRMATION_THRESHOLD: u64 = 1_000_000_000;
pub const MAX_PREFIX_LEN: usize = ADDRESS_TEXT_LEN;

const ERR_EMPTY: &str = "prefix is empty";
const ERR_T1: &str = "this mode generates mainnet P2PKH addresses, which start with t1";
const ERR_P2SH: &str = "t3 is a mainnet P2SH address, and this mode generates P2PKH";
const ERR_ALPHABET: &str = "prefix uses a character outside Base58 (0, O, I, and l are excluded)";
const ERR_THIRD: &str = "no mainnet P2PKH address has this prefix; the third character can only be HJKLMNPQRSTUVWXYZabcdefgh";
const ERR_IMPOSSIBLE: &str = "no mainnet P2PKH address has this prefix";
const ERR_LONG: &str = "prefix is longer than a 35-character P2PKH address";
const ERR_RANGE: &str = "prefix is too rare for the attempt counter";
const ERR_FULL: &str =
    "a full 35-character address is one key out of 2^160 and does not fit the attempt counter";

/// Third characters that occur in the version-byte interval. Lowercase `i` is
/// in the Base58 alphabet and is not in this set.
const LEGAL_THIRD: &[u8] = b"HJKLMNPQRSTUVWXYZabcdefgh";

/// A prefix that can occur, plus the inclusive 26-byte payload bounds.
#[derive(Clone, PartialEq, Eq)]
pub struct PrefixEstimate {
    prefix: String,
    pub expected: u64,
    pub median: u64,
    low: [u8; PAYLOAD_LEN],
    high: [u8; PAYLOAD_LEN],
}

impl PrefixEstimate {
    pub fn as_str(&self) -> &str {
        &self.prefix
    }

    /// Characters after the fixed `t1`. Empty when the prefix is `t` or `t1`.
    pub fn vanity_portion(&self) -> &str {
        self.prefix.strip_prefix("t1").unwrap_or("")
    }

    pub fn display_vanity(&self) -> &str {
        let vanity = self.vanity_portion();
        if vanity.is_empty() {
            "(none)"
        } else {
            vanity
        }
    }

    pub fn needs_large_search_confirmation(&self) -> bool {
        self.expected >= CONFIRMATION_THRESHOLD
    }

    /// Inclusive bounds. Fixed width makes byte order the same as integer order.
    pub fn contains_payload(&self, payload: &[u8; PAYLOAD_LEN]) -> bool {
        payload.as_slice() >= self.low.as_slice() && payload.as_slice() <= self.high.as_slice()
    }

    pub fn display_attempts(&self) -> String {
        group_digits(&self.expected.to_string())
    }

    pub fn display_median(&self) -> String {
        group_digits(&self.median.to_string())
    }
}

impl std::fmt::Debug for PrefixEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefixEstimate")
            .field("prefix", &self.prefix)
            .field("expected", &self.expected)
            .field("median", &self.median)
            .finish()
    }
}

pub fn validate_prefix(prefix: &str) -> Result<PrefixEstimate, Error> {
    if prefix.is_empty() {
        return Err(Error::Prefix(ERR_EMPTY));
    }
    if prefix.len() > MAX_PREFIX_LEN {
        return Err(Error::Prefix(ERR_LONG));
    }
    if prefix.bytes().any(|byte| alphabet_index(byte).is_none()) {
        return Err(Error::Prefix(ERR_ALPHABET));
    }
    if !prefix.starts_with('t') {
        return Err(Error::Prefix(ERR_T1));
    }
    if prefix.len() >= 2 {
        match prefix.as_bytes()[1] {
            b'1' => {}
            b'3' => return Err(Error::Prefix(ERR_P2SH)),
            _ => return Err(Error::Prefix(ERR_T1)),
        }
    }
    if prefix.len() >= 3 && !LEGAL_THIRD.contains(&prefix.as_bytes()[2]) {
        return Err(Error::Prefix(ERR_THIRD));
    }
    if prefix.len() == ADDRESS_TEXT_LEN {
        return reject_full_address(prefix);
    }

    let (text_low, text_high) = prefix_integer_span(prefix)?;
    let (version_low, version_high) = version_bounds();
    let low = text_low.max(version_low);
    let high = text_high.min(version_high);
    if low > high {
        return Err(Error::Prefix(ERR_IMPOSSIBLE));
    }
    let overlap = high
        .sub(low)
        .checked_add(U256::ONE)
        .ok_or(Error::Prefix(ERR_RANGE))?;
    let expected = U256::pow2(192)
        .div_round_u64(overlap)
        .ok_or(Error::Prefix(ERR_RANGE))?;
    if expected == 0 || expected > u64::MAX - SEARCH_COUNTER_HEADROOM {
        return Err(Error::Prefix(ERR_RANGE));
    }
    let low_bytes = low
        .to_payload_bytes()
        .ok_or(Error::Prefix(ERR_IMPOSSIBLE))?;
    let high_bytes = high
        .to_payload_bytes()
        .ok_or(Error::Prefix(ERR_IMPOSSIBLE))?;
    Ok(PrefixEstimate {
        prefix: prefix.to_owned(),
        expected,
        median: median_attempts(expected),
        low: low_bytes,
        high: high_bytes,
    })
}

/// `ln(2) * expected`, rounded to the nearest integer.
///
/// Values through `2^63` are exact in `f64` well enough for the displayed
/// median. The product is not an exact rational.
pub fn median_attempts(expected: u64) -> u64 {
    if expected <= 1 {
        return expected;
    }
    let median = (expected as f64) * std::f64::consts::LN_2;
    median.round() as u64
}

pub fn group_digits(digits: &str) -> String {
    if digits.is_empty() {
        return String::new();
    }
    if digits.len() > 15 {
        let exponent = digits.len() - 1;
        let mut mantissa = String::new();
        mantissa.push(digits.as_bytes()[0] as char);
        mantissa.push('.');
        let fraction: String = digits.chars().skip(1).take(3).collect();
        mantissa.push_str(&fraction);
        return format!("{mantissa}e{exponent}");
    }
    let mut grouped = String::new();
    for (index, ch) in digits.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    grouped.chars().rev().collect()
}

fn reject_full_address(prefix: &str) -> Result<PrefixEstimate, Error> {
    let payload = crate::zcash::base58::base58check_decode(prefix)
        .map_err(|_| Error::Prefix(ERR_IMPOSSIBLE))?;
    if payload.len() == 22 && payload[0] == P2PKH_VERSION[0] && payload[1] == P2PKH_VERSION[1] {
        Err(Error::Prefix(ERR_FULL))
    } else {
        Err(Error::Prefix(ERR_IMPOSSIBLE))
    }
}

fn prefix_integer_span(prefix: &str) -> Result<(U256, U256), Error> {
    let pad = ADDRESS_TEXT_LEN - prefix.len();
    let mut low_text = String::with_capacity(ADDRESS_TEXT_LEN);
    let mut high_text = String::with_capacity(ADDRESS_TEXT_LEN);
    low_text.push_str(prefix);
    high_text.push_str(prefix);
    low_text.extend(std::iter::repeat_n('1', pad));
    high_text.extend(std::iter::repeat_n('z', pad));
    let low = decode_u256(&low_text)?;
    let high = decode_u256(&high_text)?;
    if low > high {
        return Err(Error::Prefix(ERR_IMPOSSIBLE));
    }
    Ok((low, high))
}

fn version_bounds() -> (U256, U256) {
    let low = U256::from_be_bytes(&P2PKH_VERSION)
        .expect("version bytes fit")
        .shl(192)
        .expect("version prefix fits in 256 bits");
    let high = low
        .checked_add(U256::pow2(192))
        .expect("version max fits")
        .sub(U256::ONE);
    (low, high)
}

fn decode_u256(text: &str) -> Result<U256, Error> {
    let bytes = base58_decode(text).map_err(|_| Error::Prefix(ERR_IMPOSSIBLE))?;
    U256::from_be_bytes(bytes.as_slice()).ok_or(Error::Prefix(ERR_IMPOSSIBLE))
}

#[cfg(test)]
mod tests {
    use super::{
        group_digits, median_attempts, validate_prefix, version_bounds, ERR_ALPHABET, ERR_FULL,
        ERR_IMPOSSIBLE, ERR_LONG, ERR_P2SH, ERR_RANGE, ERR_T1, ERR_THIRD, LEGAL_THIRD,
    };
    use crate::error::Error;
    use crate::zcash::base58::{base58_encode, ALPHABET};
    use crate::zcash::keys::{address_from_hash, KeyEngine, ADDRESS_TEXT_LEN};
    use crate::zcash::uint::U256;

    #[test]
    fn version_text_covers_exactly_t1() {
        let (low, high) = version_bounds();
        let low_text = base58_encode(&low.to_payload_bytes().unwrap());
        let high_text = base58_encode(&high.to_payload_bytes().unwrap());
        assert_eq!(low_text, "t1Hsc1LR8yKnbbe3twRp88p6vFfC5nodWNB");
        assert_eq!(high_text, "t1hDCzSiRgWFUR5Byxr9ScwNhtAT2W3DLgW");
        assert_eq!(low_text.len(), ADDRESS_TEXT_LEN);
        assert_eq!(high_text.len(), ADDRESS_TEXT_LEN);
        assert_eq!(high.sub(low).checked_add(U256::ONE), Some(U256::pow2(192)));
    }

    #[test]
    fn t1zuzu_uses_the_version_range_not_58_to_the_4() {
        let estimate = validate_prefix("t1ZuZu").unwrap();
        assert_eq!(estimate.vanity_portion(), "ZuZu");
        assert_eq!(estimate.display_vanity(), "ZuZu");
        assert_eq!(estimate.expected, 4_553_521);
        assert_eq!(estimate.median, 3_156_260);
        assert_eq!(estimate.display_attempts(), "4,553,521");
        assert_eq!(estimate.display_median(), "3,156,260");
        assert_ne!(estimate.expected, 11_316_496);
        assert!(!estimate.needs_large_search_confirmation());
        assert_eq!(median_attempts(4_553_521), 3_156_260);
    }

    #[test]
    fn fixed_t1_prefix_matches_every_address() {
        for prefix in ["t", "t1"] {
            let estimate = validate_prefix(prefix).unwrap();
            assert_eq!(estimate.expected, 1);
            assert_eq!(estimate.median, 1);
            assert_eq!(estimate.display_vanity(), "(none)");
            assert!(!estimate.needs_large_search_confirmation());
        }
    }

    #[test]
    fn edge_and_interior_lengths_match_the_counter_limit() {
        let edge = validate_prefix("t1H").unwrap();
        assert_eq!(edge.expected, 183);
        let high = validate_prefix("t1h").unwrap();
        assert_eq!(high.expected, 111);
        let interior = validate_prefix("t1VVVVVVVVVVV").unwrap();
        assert_eq!(interior.expected, 10_054_102_514_374_869_639);
        assert!(interior.expected <= u64::MAX - super::SEARCH_COUNTER_HEADROOM);
        assert_eq!(
            validate_prefix("t1VVVVVVVVVVVV").unwrap_err(),
            Error::Prefix(ERR_RANGE)
        );
    }

    #[test]
    fn third_character_acceptance_matches_the_version_interval() {
        for byte in ALPHABET {
            let prefix = format!("t1{}", *byte as char);
            let result = validate_prefix(&prefix);
            if LEGAL_THIRD.contains(byte) {
                assert!(result.is_ok(), "{}", *byte as char);
            } else {
                assert_eq!(result.unwrap_err(), Error::Prefix(ERR_THIRD));
            }
        }
    }

    #[test]
    fn impossible_prefixes_name_the_reason() {
        assert_eq!(
            validate_prefix("").unwrap_err(),
            Error::Prefix(super::ERR_EMPTY)
        );
        assert_eq!(validate_prefix("ZuZu").unwrap_err(), Error::Prefix(ERR_T1));
        assert_eq!(
            validate_prefix("T1ZuZu").unwrap_err(),
            Error::Prefix(ERR_T1)
        );
        assert_eq!(
            validate_prefix("t2ZuZu").unwrap_err(),
            Error::Prefix(ERR_T1)
        );
        assert_eq!(validate_prefix("t3").unwrap_err(), Error::Prefix(ERR_P2SH));
        assert_eq!(
            validate_prefix("t3ZuZu").unwrap_err(),
            Error::Prefix(ERR_P2SH)
        );
        assert_eq!(
            validate_prefix("t30").unwrap_err(),
            Error::Prefix(ERR_ALPHABET)
        );
        assert_eq!(
            validate_prefix("t1ZuZu0").unwrap_err(),
            Error::Prefix(ERR_ALPHABET)
        );
        assert_eq!(
            validate_prefix("t1zuzu").unwrap_err(),
            Error::Prefix(ERR_THIRD)
        );
        assert_eq!(
            validate_prefix("t1iZZZ").unwrap_err(),
            Error::Prefix(ERR_THIRD)
        );
        assert!(validate_prefix("t1zuzu")
            .unwrap_err()
            .to_string()
            .contains("HJKLMNPQRSTUVWXYZabcdefgh"));
        assert_eq!(
            validate_prefix(&"t1".repeat(20)).unwrap_err(),
            Error::Prefix(ERR_LONG)
        );
    }

    #[test]
    fn generator_prefixes_agree_with_base58_text() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let candidate = KeyEngine::new().unwrap().candidate(&key).unwrap();
        let address = address_from_hash(&candidate.hash160);
        assert_eq!(address, "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs");
        for length in 1..=13 {
            let estimate = validate_prefix(&address[..length]).unwrap();
            assert!(
                estimate.contains_payload(&candidate.payload),
                "length {length}"
            );
        }
        assert_eq!(
            validate_prefix(&address[..14]).unwrap_err(),
            Error::Prefix(ERR_RANGE)
        );
        assert_eq!(
            validate_prefix(&address).unwrap_err(),
            Error::Prefix(ERR_FULL)
        );
        let mut damaged = address.clone();
        damaged.pop();
        damaged.push('t');
        assert_eq!(
            validate_prefix(&damaged).unwrap_err(),
            Error::Prefix(ERR_IMPOSSIBLE)
        );
        let other = validate_prefix("t1ZuZu").unwrap();
        assert!(!other.contains_payload(&candidate.payload));
        assert!(!address.starts_with(other.as_str()));
    }

    #[test]
    fn grouped_digits_stop_at_fifteen() {
        assert_eq!(group_digits("4553521"), "4,553,521");
        assert_eq!(group_digits("10054102514374869639"), "1.005e19");
    }
}
