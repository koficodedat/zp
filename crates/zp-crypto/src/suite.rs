//! Cipher suite definitions per zp specification v1.0.

/// Cipher suites defined in spec §4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CipherSuite {
    /// X25519 + ML-KEM-768 + ChaCha20-Poly1305 + HKDF-SHA256
    /// Default suite, mandatory to implement.
    ZpHybrid1 = 0x0001,

    /// X25519 + ML-KEM-1024 + ChaCha20-Poly1305 + HKDF-SHA256
    /// Higher post-quantum security parameter.
    ZpHybrid2 = 0x0002,

    /// X25519 + ML-KEM-768 + AES-256-GCM + HKDF-SHA256
    /// For environments preferring AES.
    ZpHybrid3 = 0x0003,

    /// ECDH-P256 + AES-256-GCM + HKDF-SHA256
    /// FIPS-compliant mode, no post-quantum component.
    ZpClassical2 = 0x0005,
}

impl CipherSuite {
    /// Convert from wire format (u16).
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::ZpHybrid1),
            0x0002 => Some(Self::ZpHybrid2),
            0x0003 => Some(Self::ZpHybrid3),
            0x0005 => Some(Self::ZpClassical2),
            _ => None,
        }
    }

    /// Convert to wire format (u16).
    pub fn to_u16(self) -> u16 {
        self as u16
    }

    /// Check if this suite includes a post-quantum component.
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Self::ZpHybrid1 | Self::ZpHybrid2 | Self::ZpHybrid3)
    }

    /// Check if this suite is FIPS-compliant.
    pub fn is_fips(&self) -> bool {
        matches!(self, Self::ZpClassical2)
    }

    /// Get the ML-KEM variant for this suite, if any.
    pub fn ml_kem_variant(&self) -> Option<MlKemVariant> {
        match self {
            Self::ZpHybrid1 | Self::ZpHybrid3 => Some(MlKemVariant::MlKem768),
            Self::ZpHybrid2 => Some(MlKemVariant::MlKem1024),
            Self::ZpClassical2 => None,
        }
    }

    /// Get the AEAD algorithm for this suite.
    pub fn aead_algorithm(&self) -> AeadAlgorithm {
        match self {
            Self::ZpHybrid1 | Self::ZpHybrid2 => AeadAlgorithm::ChaCha20Poly1305,
            Self::ZpHybrid3 | Self::ZpClassical2 => AeadAlgorithm::Aes256Gcm,
        }
    }
}

/// ML-KEM variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    /// ML-KEM-768 (NIST security level 3).
    MlKem768,
    /// ML-KEM-1024 (NIST security level 5).
    MlKem1024,
}

/// AEAD algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// ChaCha20-Poly1305 (RFC 8439).
    ChaCha20Poly1305,
    /// AES-256-GCM (NIST SP 800-38D).
    Aes256Gcm,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_roundtrip() {
        for suite in [
            CipherSuite::ZpHybrid1,
            CipherSuite::ZpHybrid2,
            CipherSuite::ZpHybrid3,
            CipherSuite::ZpClassical2,
        ] {
            assert_eq!(CipherSuite::from_u16(suite.to_u16()), Some(suite));
        }
    }

    #[test]
    fn test_post_quantum_detection() {
        assert!(CipherSuite::ZpHybrid1.is_post_quantum());
        assert!(CipherSuite::ZpHybrid2.is_post_quantum());
        assert!(CipherSuite::ZpHybrid3.is_post_quantum());
        assert!(!CipherSuite::ZpClassical2.is_post_quantum());
    }

    #[test]
    fn test_fips_detection() {
        assert!(!CipherSuite::ZpHybrid1.is_fips());
        assert!(!CipherSuite::ZpHybrid2.is_fips());
        assert!(!CipherSuite::ZpHybrid3.is_fips());
        assert!(CipherSuite::ZpClassical2.is_fips());
    }
}
