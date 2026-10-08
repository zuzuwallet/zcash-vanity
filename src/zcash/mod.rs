// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mainnet transparent P2PKH derivation.
//!
//! The search path is libsecp256k1, `sha2`, `ripemd`, and this crate's
//! Base58Check. The independent check does not use those encoders.

mod base58;
pub(crate) mod hash;
mod keys;
mod prefix;
mod uint;
mod wif;

pub(crate) use keys::encode_payload;
pub use keys::{address_from_hash, Candidate, KeyEngine, ADDRESS_TEXT_LEN, PAYLOAD_LEN};
pub(crate) use prefix::SEARCH_COUNTER_HEADROOM;
pub use prefix::{
    group_digits, median_attempts, validate_prefix, PrefixEstimate, CONFIRMATION_THRESHOLD,
    MAX_PREFIX_LEN,
};
pub use wif::{decode_wif, encode_wif};
