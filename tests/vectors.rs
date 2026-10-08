#![forbid(unsafe_code)]

use zcash_vanity::run_self_tests;

#[test]
fn known_answer_gate_passes() {
    run_self_tests().unwrap();
}
