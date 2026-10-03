//! Key derivation from BIP-39 mnemonic to scan/spend keys.
//!
//! Derivation paths (CHIP-0057 "Key Derivation"):
//! - Wallet: m/12381/8444/2/<index>  — standard Chia wallet, unhardened
//! - Scan:   m/12381n/8444n/12n/0n   — silent payment scan key, hardened
//! - Spend:  m/12381n/8444n/13n/0n   — silent payment spend key, hardened
//!
//! The `n` suffix is Chia's notation for an EIP-2333 hardened (non-observer)
//! step. The silent payment keys MUST NOT be derived with Chia's unhardened
//! derivation: an unhardened child secret key together with the parent public
//! key reveals the parent secret key, so a leaked scan key plus the wallet's
//! master public key would expose every key in the wallet.

use chia_bls::{SecretKey, DerivableKey};

/// Convert a BIP-39 mnemonic phrase to a BLS master secret key.
///
/// Uses empty passphrase ("") which matches Python's
/// `pbkdf2_hmac("sha512", mnemonic, b"mnemonic", 2048)` because the
/// bip39 crate automatically prepends "mnemonic" to the passphrase as salt.
pub fn mnemonic_to_master_sk(mnemonic: &str) -> SecretKey {
    let m: bip39::Mnemonic = mnemonic.parse().expect("invalid mnemonic");
    let seed = m.to_seed("");
    let mut seed_bytes = [0u8; 64];
    seed_bytes.copy_from_slice(&seed);
    SecretKey::from_seed(&seed_bytes)
}

/// Derive wallet secret key at m/12381/8444/2/<index> (all unhardened).
pub fn master_to_wallet_sk(master: &SecretKey, index: u32) -> SecretKey {
    master
        .derive_unhardened(12381)
        .derive_unhardened(8444)
        .derive_unhardened(2)
        .derive_unhardened(index)
}

/// Derive the scan secret key at m/12381n/8444n/12n/0n.
///
/// Every level is an EIP-2333 hardened step, as CHIP-0057 requires.
pub fn master_to_scan_sk(master: &SecretKey) -> SecretKey {
    master
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(12)
        .derive_hardened(0)
}

/// Derive the spend secret key at m/12381n/8444n/13n/0n.
///
/// Every level is an EIP-2333 hardened step, as CHIP-0057 requires.
pub fn master_to_spend_sk(master: &SecretKey) -> SecretKey {
    master
        .derive_hardened(12381)
        .derive_hardened(8444)
        .derive_hardened(13)
        .derive_hardened(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_wallet_sk_derivation() {
        let master = mnemonic_to_master_sk(TEST_MNEMONIC);
        let wallet_sk = master_to_wallet_sk(&master, 0);
        let hex_str = hex::encode(wallet_sk.to_bytes());
        assert_eq!(
            hex_str,
            "6c8d1a9f97413f8d8e8c158f5bc875b58b498de05c9109b4dc240280d32e2a31"
        );
    }

    /// Unhardened derivation at m/12381/8444/<purpose>/0.
    ///
    /// TEST ONLY. This is the derivation silent payment addresses used before
    /// the CHIP required hardened steps. It is kept here to pin down two facts: the
    /// "given" recipient keys of CHIP Test Vectors 1-7 are these legacy keys,
    /// and the production functions no longer produce them.
    fn legacy_unhardened_sp_sk(master: &SecretKey, purpose: u32) -> SecretKey {
        master
            .derive_unhardened(12381)
            .derive_unhardened(8444)
            .derive_unhardened(purpose)
            .derive_unhardened(0)
    }

    // --- CHIP Test Vector 8: hardened key derivation -------------------------

    #[test]
    fn test_tv8_master_key() {
        let master = mnemonic_to_master_sk(TEST_MNEMONIC);
        assert_eq!(
            hex::encode(master.to_bytes()),
            "11da8b4a2874a49dc42984b6aa127b68ef73adddc333319c36fd0446705204a9"
        );
        assert_eq!(
            hex::encode(master.public_key().to_bytes()),
            "82ae65efe846b15a92c51b7ad6c32589fd79d38263d3cbefbeeba08be8e90d8bc335a1e2fcc66a10b8c817c06232285a"
        );
    }

    #[test]
    fn test_tv8_scan_key_hardened() {
        let master = mnemonic_to_master_sk(TEST_MNEMONIC);
        let scan_sk = master_to_scan_sk(&master);
        assert_eq!(
            hex::encode(scan_sk.to_bytes()),
            "0c474f92e8945069c200bb09302d1e569a9b52f59cc04a27874b1bca2adeca9f"
        );
        assert_eq!(
            hex::encode(scan_sk.public_key().to_bytes()),
            "8bf2be64f401ccc10d3495503ac9e5b675c2e2b08b073917935beed951b70b8ccd01f60c406c4ee7e79237e2eb5affd9"
        );
    }

    #[test]
    fn test_tv8_spend_key_hardened() {
        let master = mnemonic_to_master_sk(TEST_MNEMONIC);
        let spend_sk = master_to_spend_sk(&master);
        assert_eq!(
            hex::encode(spend_sk.to_bytes()),
            "4f8acf271744cf7050197623569e1603b0193f84b958b5d5f1ce8fd18c908e7b"
        );
        assert_eq!(
            hex::encode(spend_sk.public_key().to_bytes()),
            "ad0c7b65a3392b62782b8c0784b10c64b0f4dc8fc2d46d2d3c7c0e1b899bf183f76996226ddf9145789d6b0bf3499219"
        );
    }

    // --- Legacy (unhardened) keys = the "given" keys of TV1-7 ----------------

    #[test]
    fn test_legacy_unhardened_scan_key_is_tv1_given_key() {
        let master = mnemonic_to_master_sk(TEST_MNEMONIC);
        let scan_sk = legacy_unhardened_sp_sk(&master, 12);
        assert_eq!(
            hex::encode(scan_sk.to_bytes()),
            "132567e4dec19a4f50d9e9a549f16283dfb5aa4ad1ffdb6a505fcfcc56a690f6"
        );
        assert_eq!(
            hex::encode(scan_sk.public_key().to_bytes()),
            "a04f404bfbfdc9311736899fe32d2275bb007814510c3523529487ad7573607573ade20d31c75107b40331fff79ac896"
        );
    }

    #[test]
    fn test_legacy_unhardened_spend_key_is_tv1_given_key() {
        let master = mnemonic_to_master_sk(TEST_MNEMONIC);
        let spend_sk = legacy_unhardened_sp_sk(&master, 13);
        assert_eq!(
            hex::encode(spend_sk.to_bytes()),
            "53d140b312a0e16316314274eb6398e15706d100fe8a754990540febd931b087"
        );
        assert_eq!(
            hex::encode(spend_sk.public_key().to_bytes()),
            "8afc580192f44fab624f613369f792eff3220ea3ca822eb839ab2c9309e527dbf6f31e22e0831ba5088c952625a75c74"
        );
    }

    #[test]
    fn test_production_derivation_is_not_the_legacy_derivation() {
        let master = mnemonic_to_master_sk(TEST_MNEMONIC);
        assert_ne!(
            master_to_scan_sk(&master).to_bytes(),
            legacy_unhardened_sp_sk(&master, 12).to_bytes()
        );
        assert_ne!(
            master_to_spend_sk(&master).to_bytes(),
            legacy_unhardened_sp_sk(&master, 13).to_bytes()
        );
    }
}
