// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use zcash_vanity::run_self_tests;

#[test]
fn known_answer_gate_passes() {
    run_self_tests().unwrap();
}
