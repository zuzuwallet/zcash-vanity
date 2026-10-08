// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline Zcash mainnet transparent P2PKH vanity generator.
//!
//! This crate does not use `unsafe`. The search derives compressed secp256k1
//! keys with libsecp256k1. The independent check uses `k256`, `bitcoin_hashes`,
//! and `zcash_address` 0.13. The hand-written pieces are Base58Check and the
//! wallet wiring.
//!
//! A `t1` address is transparent. Nothing in this crate creates a Sapling,
//! Orchard, or Unified Address.

#![forbid(unsafe_code)]

pub mod error;
mod hexutil;
pub mod independent;
pub mod search;
pub mod secret;
pub mod self_test;
pub mod verify;
pub mod wallet;
pub mod zcash;

pub use error::Error;
pub use search::{counter_would_overflow, search, SearchHit, COUNTER_HEADROOM, MAX_THREADS};
pub use secret::{SecretBytes, SecretString};
pub use self_test::run_self_tests;
pub use verify::confirm_match;
pub use wallet::{
    check_new_passphrase, check_passphrase, open_and_verify, write_encrypted_wallet, KdfParams,
    OpenedWallet, MIN_NEW_PASSPHRASE_CHARS,
};
pub use zcash::{
    address_from_hash, decode_wif, encode_wif, group_digits, validate_prefix, KeyEngine,
    PrefixEstimate, CONFIRMATION_THRESHOLD, MAX_PREFIX_LEN,
};
