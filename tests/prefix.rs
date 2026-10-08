#![forbid(unsafe_code)]

use zcash_vanity::{validate_prefix, Error};

#[test]
fn t1zuzu_is_the_documented_target() {
    let estimate = validate_prefix("t1ZuZu").unwrap();
    assert_eq!(estimate.as_str(), "t1ZuZu");
    assert_eq!(estimate.vanity_portion(), "ZuZu");
    assert_eq!(estimate.expected, 4_553_521);
    assert_eq!(estimate.median, 3_156_260);
}

#[test]
fn rejected_prefixes_explain_themselves() {
    let cases = [
        ("ZuZu", "start with t1"),
        ("t3ZuZu", "P2SH"),
        ("t3", "P2SH"),
        ("t30", "Base58"),
        ("t1zuzu", "HJKLMNPQRSTUVWXYZabcdefgh"),
        ("t1ZuZuZuZuZuZuZuZuZuZuZuZuZuZuZuZuZuZu", "35-character"),
    ];
    for (prefix, needle) in cases {
        let err = validate_prefix(prefix).unwrap_err();
        assert!(matches!(err, Error::Prefix(_)), "{prefix}: {err}");
        assert!(err.to_string().contains(needle), "{prefix}: {err}");
    }
}
