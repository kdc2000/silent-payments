//! BIP-340-style tagged hash with Chia_SP/* domain tags.
//!
//! tagged_hash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)

use sha2::{Sha256, Digest};

/// Compute a BIP-340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash: [u8; 32] = Sha256::digest(tag.as_bytes()).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_hash_known_value() {
        // SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge") || b"")
        // The tag_hash = SHA256("BIP0340/challenge") is a known value.
        // We verify the function produces consistent and correct output.
        let result = tagged_hash("BIP0340/challenge", b"");
        // Pre-computed: SHA256(SHA256("BIP0340/challenge") || SHA256("BIP0340/challenge") || "")
        let expected = hex::decode(
            "c216d352f5818b7b4beacd4ae0a26fe888080823d2a598856661bcd54f1b3713"
        ).unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_tagged_hash_deterministic() {
        let a = tagged_hash("test-tag", b"some data");
        let b = tagged_hash("test-tag", b"some data");
        assert_eq!(a, b);
    }

    #[test]
    fn test_tagged_hash_different_tags() {
        let a = tagged_hash("tag1", b"data");
        let b = tagged_hash("tag2", b"data");
        assert_ne!(a, b);
    }
}
