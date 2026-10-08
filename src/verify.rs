//! Checks that agree before a wallet is treated as valid.
//!
//! The independent path starts from the raw scalar. `k256` derives the
//! compressed public key, `bitcoin_hashes` hashes it, and `zcash_address`
//! encodes the `t1` address. A mismatch is fatal. This function does not print
//! the key.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::error::Error;
use crate::independent::independent_address;
use crate::zcash::{encode_payload, KeyEngine};

/// Require this crate and the independent stack to agree on `address`.
pub fn confirm_match(key: &[u8; 32], address: &str) -> Result<(), Error> {
    let outcome = catch_unwind(AssertUnwindSafe(|| confirm_match_inner(key, address)));
    match outcome {
        Ok(result) => result,
        Err(_) => Err(Error::VerificationFailed),
    }
}

fn confirm_match_inner(key: &[u8; 32], address: &str) -> Result<(), Error> {
    let engine = KeyEngine::new()?;
    let candidate = engine
        .candidate(key)
        .map_err(|_| Error::VerificationFailed)?;
    let ours = encode_payload(&candidate.payload);
    if ours != address {
        return Err(Error::VerificationFailed);
    }
    let (public_key, hash, independent) = independent_address(key)?;
    if public_key != candidate.public_key
        || hash != candidate.hash160
        || independent != address
        || independent != ours
    {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}
