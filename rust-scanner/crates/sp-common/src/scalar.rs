//! ScalarField newtype: big-endian 32-byte scalar with unsigned mod r arithmetic.
//!
//! All protocol scalar values (input_hash, output_tweak, label_scalar) use
//! UNSIGNED interpretation mod GROUP_ORDER. This differs from Chia's
//! `mod_by_group_order` which uses SIGNED interpretation (correct only for
//! synthetic key offsets).

use num_bigint::BigUint;

/// BLS12-381 subgroup order r (big-endian bytes).
pub const GROUP_ORDER: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
    0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// A scalar field element: 32 big-endian bytes representing a value in [0, r).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScalarField([u8; 32]);

impl ScalarField {
    /// Reduce a 32-byte big-endian value mod r using UNSIGNED interpretation.
    ///
    /// This is the correct operation for protocol scalars (input_hash,
    /// output_tweak, label_scalar). Do NOT use Chia's `mod_by_group_order`
    /// which interprets the bytes as SIGNED.
    pub fn from_bytes_unsigned(bytes: [u8; 32]) -> Self {
        let n = BigUint::from_bytes_be(&bytes);
        let r = BigUint::from_bytes_be(&GROUP_ORDER);
        let result = n % &r;
        let be = result.to_bytes_be();
        let mut out = [0u8; 32];
        if !be.is_empty() {
            out[32 - be.len()..].copy_from_slice(&be);
        }
        ScalarField(out)
    }

    /// Wrap raw bytes without reduction. Use only for values already in range
    /// (e.g., secret key bytes known to be < r).
    pub fn from_bytes_raw(bytes: [u8; 32]) -> Self {
        ScalarField(bytes)
    }

    /// Multiply two scalars mod r: (a * b) % GROUP_ORDER.
    pub fn mul(&self, other: &Self) -> Self {
        let a = BigUint::from_bytes_be(&self.0);
        let b = BigUint::from_bytes_be(&other.0);
        let r = BigUint::from_bytes_be(&GROUP_ORDER);
        let result = (a * b) % &r;
        let be = result.to_bytes_be();
        let mut out = [0u8; 32];
        if !be.is_empty() {
            out[32 - be.len()..].copy_from_slice(&be);
        }
        ScalarField(out)
    }

    /// Add two scalars mod r: (a + b) % GROUP_ORDER.
    pub fn add(&self, other: &Self) -> Self {
        let a = BigUint::from_bytes_be(&self.0);
        let b = BigUint::from_bytes_be(&other.0);
        let r = BigUint::from_bytes_be(&GROUP_ORDER);
        let result = (a + b) % &r;
        let be = result.to_bytes_be();
        let mut out = [0u8; 32];
        if !be.is_empty() {
            out[32 - be.len()..].copy_from_slice(&be);
        }
        ScalarField(out)
    }

    /// Returns a reference to the inner 32 big-endian bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns a copy of the inner 32 big-endian bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Returns true if the scalar is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes_unsigned_identity() {
        // Value smaller than r should pass through unchanged
        let mut bytes = [0u8; 32];
        bytes[31] = 42;
        let s = ScalarField::from_bytes_unsigned(bytes);
        assert_eq!(s.to_bytes(), bytes);
    }

    #[test]
    fn test_from_bytes_unsigned_reduces() {
        // 0xff..ff is larger than r, so it should be reduced mod r
        let bytes = [0xff; 32];
        let s = ScalarField::from_bytes_unsigned(bytes);
        // 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff % r
        // = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - r
        // Since 0xff..ff > r, the result should be < r
        let n = BigUint::from_bytes_be(&bytes);
        let r = BigUint::from_bytes_be(&GROUP_ORDER);
        let expected = n % &r;
        let expected_be = expected.to_bytes_be();
        let mut expected_bytes = [0u8; 32];
        expected_bytes[32 - expected_be.len()..].copy_from_slice(&expected_be);
        assert_eq!(s.to_bytes(), expected_bytes);
        // The result should NOT equal the input
        assert_ne!(s.to_bytes(), bytes);
    }

    #[test]
    fn test_mul_mod_r() {
        // Use known values: 2 * 3 = 6
        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 2;
        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 3;
        let a = ScalarField::from_bytes_unsigned(a_bytes);
        let b = ScalarField::from_bytes_unsigned(b_bytes);
        let c = a.mul(&b);
        let mut expected = [0u8; 32];
        expected[31] = 6;
        assert_eq!(c.to_bytes(), expected);
    }

    #[test]
    fn test_add_mod_r() {
        // Use known values: r-1 + 1 = 0 (wraps around)
        let mut r_minus_1 = GROUP_ORDER;
        // Subtract 1 from the last byte
        r_minus_1[31] = GROUP_ORDER[31] - 1; // 0x01 - 1 = 0x00
        let a = ScalarField::from_bytes_raw(r_minus_1);
        let mut one = [0u8; 32];
        one[31] = 1;
        let b = ScalarField::from_bytes_raw(one);
        let c = a.add(&b);
        // (r-1) + 1 = r = 0 mod r
        assert!(c.is_zero());
    }

    #[test]
    fn test_zero() {
        let bytes = [0u8; 32];
        let s = ScalarField::from_bytes_unsigned(bytes);
        assert!(s.is_zero());
    }

    #[test]
    fn test_add_simple() {
        // 10 + 20 = 30
        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 10;
        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 20;
        let a = ScalarField::from_bytes_unsigned(a_bytes);
        let b = ScalarField::from_bytes_unsigned(b_bytes);
        let c = a.add(&b);
        let mut expected = [0u8; 32];
        expected[31] = 30;
        assert_eq!(c.to_bytes(), expected);
    }
}
