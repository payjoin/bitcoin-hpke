//! Adapter that backs the RustCrypto `aead` traits with rust-bitcoin's ChaCha20-Poly1305

use aead::{
    AeadCore, AeadInPlace, Error as AeadError, Key as AeadKey, KeyInit, KeySizeUser, Nonce, Tag,
};
use generic_array::{
    typenum::{U0, U12, U16, U32},
    GenericArray,
};
use zeroize::Zeroize;

// The rust-bitcoin cipher binds the key and nonce at construction and is consumed per
// operation, so we hold the key and build a fresh cipher for each seal/open.

/// ChaCha20-Poly1305 backed by the rust-bitcoin `chacha20-poly1305` crate.
#[derive(Clone)]
pub struct ChaCha20Poly1305Cipher {
    key: [u8; 32],
}

// Zero out the key on drop. This only covers our copy: the rust-bitcoin cipher's key
// and nonce types are `Copy` with no `Drop`, so the copies made per operation are
// left to the compiler. That is a deliberate rust-bitcoin position, since moves and
// optimizer spills scatter secrets that zeroize can't reach anyway
// (rust-bitcoin/rust-secp256k1#553).
impl Drop for ChaCha20Poly1305Cipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl AeadCore for ChaCha20Poly1305Cipher {
    type NonceSize = U12;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl KeySizeUser for ChaCha20Poly1305Cipher {
    type KeySize = U32;
}

impl KeyInit for ChaCha20Poly1305Cipher {
    fn new(key: &AeadKey<Self>) -> Self {
        let mut k = [0u8; 32];
        k.copy_from_slice(key.as_slice());
        Self { key: k }
    }
}

// RFC 8439 §2.8: a message is at most 2^32 - 1 blocks of 64 bytes. The rust-bitcoin
// cipher does not check its `u32` block counter, so an oversized buffer would wrap it
// and reuse keystream.
fn check_message_len(buffer: &[u8]) -> Result<(), AeadError> {
    if buffer.len() / 64 >= u32::MAX as usize {
        return Err(AeadError);
    }
    Ok(())
}

impl AeadInPlace for ChaCha20Poly1305Cipher {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>, AeadError> {
        check_message_len(buffer)?;
        let mut n = [0u8; 12];
        n.copy_from_slice(nonce.as_slice());
        let cipher = chacha20_poly1305::ChaCha20Poly1305::new(
            chacha20_poly1305::Key::new(self.key),
            chacha20_poly1305::Nonce::new(n),
        );
        let tag = cipher.encrypt(buffer, Some(associated_data));
        Ok(GenericArray::clone_from_slice(&tag))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<(), AeadError> {
        check_message_len(buffer)?;
        let mut n = [0u8; 12];
        n.copy_from_slice(nonce.as_slice());
        let mut t = [0u8; 16];
        t.copy_from_slice(tag.as_slice());
        let cipher = chacha20_poly1305::ChaCha20Poly1305::new(
            chacha20_poly1305::Key::new(self.key),
            chacha20_poly1305::Nonce::new(n),
        );
        cipher
            .decrypt(buffer, t, Some(associated_data))
            .map_err(|_| AeadError)
    }
}

#[cfg(test)]
mod tests {
    use aead::{AeadInPlace, KeyInit};
    use generic_array::GenericArray;

    use super::ChaCha20Poly1305Cipher;

    // Empty AAD is what OHTTP (and so BIP 77) uses, and no KAT vector covers it
    #[test]
    fn aead_empty_aad_roundtrip_and_tamper() {
        let cipher =
            <ChaCha20Poly1305Cipher as KeyInit>::new(&GenericArray::clone_from_slice(&[0x42; 32]));
        let nonce = GenericArray::clone_from_slice(&[0x24; 12]);

        let mut buf = *b"bip77 payjoin";
        let tag = cipher
            .encrypt_in_place_detached(&nonce, b"", &mut buf)
            .unwrap();
        assert_ne!(&buf[..], b"bip77 payjoin");
        cipher
            .decrypt_in_place_detached(&nonce, b"", &mut buf, &tag)
            .unwrap();
        assert_eq!(&buf[..], b"bip77 payjoin");

        let mut buf = *b"bip77 payjoin";
        let tag = cipher
            .encrypt_in_place_detached(&nonce, b"", &mut buf)
            .unwrap();
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(cipher
            .decrypt_in_place_detached(&nonce, b"", &mut buf, &bad)
            .is_err());
    }
}
