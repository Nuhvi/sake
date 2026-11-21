//! Safe BIP-340 verification of messages with any length.
//!
//! BIP-348 passes the raw message to the signature check, so the message can
//! be empty or longer than 32 bytes. This module uses the safe API of the
//! direct secp256k1 dependency. The transitive secp256k1 0.29 of
//! rust-bitcoin 0.32 always passes a 32-byte length to libsecp256k1.
//!
//! Remove this module and the direct dependency after rust-bitcoin uses
//! secp256k1 0.30 or later.

use secp256k1::{XOnlyPublicKey, schnorr};

/// Verifies a BIP-340 signature over a message of any length.
pub(crate) fn verify(signature: [u8; 64], message: &[u8], public_key: [u8; 32]) -> bool {
    let Ok(public_key) = XOnlyPublicKey::from_byte_array(public_key) else {
        return false;
    };
    let signature = schnorr::Signature::from_byte_array(signature);
    schnorr::verify(&signature, message, &public_key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_invalid_public_key() {
        assert!(!verify([0u8; 64], b"message", [0xffu8; 32]));
    }
}
