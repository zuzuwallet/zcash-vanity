// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

#![forbid(unsafe_code)]

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use zeroize::Zeroize;

use zcash_vanity::{validate_prefix, KeyEngine};

fn bench_derive(c: &mut Criterion) {
    // SEC generator. Its address is t1UYsZ..., so t1ZuZu is the miss path.
    let mut key = [0u8; 32];
    key[31] = 1;
    let estimate = validate_prefix("t1ZuZu").unwrap();
    let engine = KeyEngine::new().expect("libsecp256k1 context seed");
    c.bench_function("miss_without_base58", |b| {
        b.iter(|| {
            let candidate = engine.candidate(black_box(&key)).unwrap();
            let matched = estimate.contains_payload(black_box(&candidate.payload));
            black_box(matched);
        });
    });
    c.bench_function("getrandom_and_miss", |b| {
        b.iter(|| {
            let mut entropy = [0u8; 32];
            getrandom::getrandom(&mut entropy).unwrap();
            let candidate = engine.candidate(black_box(&entropy));
            let matched = candidate
                .as_ref()
                .map(|item| estimate.contains_payload(&item.payload))
                .unwrap_or(false);
            black_box(matched);
            entropy.zeroize();
        });
    });
}

criterion_group!(benches, bench_derive);
criterion_main!(benches);
