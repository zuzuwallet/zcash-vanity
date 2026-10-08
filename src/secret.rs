use std::fmt;

use zeroize::Zeroizing;

/// Fixed-length secret. `Debug` does not print the bytes.
pub struct SecretBytes<const N: usize> {
    bytes: Zeroizing<[u8; N]>,
}

impl<const N: usize> SecretBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Move an already-wiped buffer in. This does not copy the array again.
    pub fn from_zeroizing(bytes: Zeroizing<[u8; N]>) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>([redacted])")
    }
}

/// Secret text such as a WIF string or a passphrase.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([redacted])")
    }
}
