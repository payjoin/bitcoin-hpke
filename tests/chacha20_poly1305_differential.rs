//! Tests the ChaCha20-Poly1305 `Aead::AeadImpl` against the RustCrypto `chacha20poly1305` crate it
//! replaced.

use aead::{generic_array::GenericArray, AeadInPlace, KeyInit};
use bitcoin_hpke::aead::{Aead, ChaCha20Poly1305};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

type OurAead = <ChaCha20Poly1305 as Aead>::AeadImpl;
type TheirAead = chacha20poly1305::ChaCha20Poly1305;

// Lengths around the 64-byte ChaCha20 block and the 16-byte Poly1305 block
const LENS: &[usize] = &[
    0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 4096, 65537,
];

fn random_bytes(rng: &mut StdRng, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

#[test]
fn matches_rustcrypto() {
    let mut rng = StdRng::seed_from_u64(0x5eed_0bad_cafe_f00d);
    let mut lens = LENS.to_vec();
    lens.extend((0..200).map(|_| rng.gen_range(0..2048)));

    for len in lens {
        for alen in [0usize, 1, 15, 16, 17, 63, 64, 65, 300] {
            let key = random_bytes(&mut rng, 32);
            let nonce = random_bytes(&mut rng, 12);
            let aad = random_bytes(&mut rng, alen);
            let pt = random_bytes(&mut rng, len);
            let ours = OurAead::new(GenericArray::from_slice(&key));
            let theirs = TheirAead::new(GenericArray::from_slice(&key));
            let n = GenericArray::from_slice(&nonce);

            let mut ct = pt.clone();
            let tag = ours.encrypt_in_place_detached(n, &aad, &mut ct).unwrap();
            let mut their_ct = pt.clone();
            let their_tag = theirs
                .encrypt_in_place_detached(n, &aad, &mut their_ct)
                .unwrap();
            assert_eq!(ct, their_ct, "ciphertext, len {len} aad {alen}");
            assert_eq!(tag, their_tag, "tag, len {len} aad {alen}");

            let mut buf = ct.clone();
            theirs
                .decrypt_in_place_detached(n, &aad, &mut buf, &tag)
                .unwrap();
            assert_eq!(buf, pt);
            let mut buf = ct.clone();
            ours.decrypt_in_place_detached(n, &aad, &mut buf, &their_tag)
                .unwrap();
            assert_eq!(buf, pt);

            // A tampered input must fail and leave the buffer unchanged, so no plaintext is released
            let reject = |nonce: &[u8], aad: &[u8], ct: &[u8], tag: &[u8]| {
                let mut buf = ct.to_vec();
                let res = ours.decrypt_in_place_detached(
                    GenericArray::from_slice(nonce),
                    aad,
                    &mut buf,
                    GenericArray::from_slice(tag),
                );
                assert!(
                    res.is_err(),
                    "tampered input accepted, len {len} aad {alen}"
                );
                assert_eq!(
                    buf, ct,
                    "buffer modified on auth failure, len {len} aad {alen}"
                );
            };
            if len > 0 {
                let mut bad = ct.clone();
                bad[rng.gen_range(0..len)] ^= 1 << rng.gen_range(0..8);
                reject(&nonce, &aad, &bad, &tag);
            }
            let mut bad = tag;
            bad[rng.gen_range(0..16)] ^= 1 << rng.gen_range(0..8);
            reject(&nonce, &aad, &ct, &bad);
            let mut bad = aad.clone();
            bad.push(0);
            reject(&nonce, &bad, &ct, &tag);
            let mut bad = nonce.clone();
            bad[rng.gen_range(0..12)] ^= 0x80;
            reject(&bad, &aad, &ct, &tag);
        }
    }
}
