//! Tests the ChaCha20-Poly1305 `Aead::AeadImpl` against the Wycheproof vectors and tampered inputs.

use aead::{generic_array::GenericArray, AeadInPlace, KeyInit};
use bitcoin_hpke::aead::{Aead, ChaCha20Poly1305};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};

type Cipher = <ChaCha20Poly1305 as Aead>::AeadImpl;

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
fn round_trip_and_tamper() {
    let mut rng = StdRng::seed_from_u64(0x5eed_0bad_cafe_f00d);
    let mut lens = LENS.to_vec();
    lens.extend((0..200).map(|_| rng.gen_range(0..2048)));

    for len in lens {
        for alen in [0usize, 1, 15, 16, 17, 63, 64, 65, 300] {
            let key = random_bytes(&mut rng, 32);
            let nonce = random_bytes(&mut rng, 12);
            let aad = random_bytes(&mut rng, alen);
            let pt = random_bytes(&mut rng, len);
            let cipher = Cipher::new(GenericArray::from_slice(&key));
            let n = GenericArray::from_slice(&nonce);

            let mut ct = pt.clone();
            let tag = cipher.encrypt_in_place_detached(n, &aad, &mut ct).unwrap();
            assert!(len == 0 || ct != pt, "len {len} aad {alen}");

            let mut buf = ct.clone();
            cipher
                .decrypt_in_place_detached(n, &aad, &mut buf, &tag)
                .unwrap();
            assert_eq!(buf, pt, "len {len} aad {alen}");

            // A tampered input must fail and leave the buffer unchanged, so no plaintext is released
            let reject = |nonce: &[u8], aad: &[u8], ct: &[u8], tag: &[u8]| {
                let mut buf = ct.to_vec();
                let res = cipher.decrypt_in_place_detached(
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

// Wycheproof's ChaCha20-Poly1305 suite, from https://github.com/C2SP/wycheproof (testvectors_v1)
#[cfg(feature = "std")]
#[test]
fn wycheproof() {
    let file = std::fs::File::open("test-vectors-wycheproof-chacha20-poly1305.json").unwrap();
    let suite: serde_json::Value = serde_json::from_reader(file).unwrap();
    assert_eq!(suite["algorithm"], "CHACHA20-POLY1305");

    let (mut ran, mut skipped) = (0, 0);
    for group in suite["testGroups"].as_array().unwrap() {
        let tests = group["tests"].as_array().unwrap();
        // The nonce type is fixed at 96 bits; the other IV sizes are all `invalid` cases
        if group["ivSize"] != 96 || group["keySize"] != 256 || group["tagSize"] != 128 {
            skipped += tests.len();
            continue;
        }
        for t in tests {
            let h = |k: &str| hex::decode(t[k].as_str().unwrap()).unwrap();
            let (key, iv, aad, msg, ct, tag) =
                (h("key"), h("iv"), h("aad"), h("msg"), h("ct"), h("tag"));
            let id = t["tcId"].as_u64().unwrap();
            let valid = match t["result"].as_str().unwrap() {
                "valid" => true,
                "invalid" => false,
                other => panic!("tcId {id}: unexpected result {other}"),
            };
            let cipher = Cipher::new(GenericArray::from_slice(&key));
            let n = GenericArray::from_slice(&iv);

            let mut buf = ct.clone();
            let res =
                cipher.decrypt_in_place_detached(n, &aad, &mut buf, GenericArray::from_slice(&tag));
            assert_eq!(res.is_ok(), valid, "tcId {id} ({})", t["comment"]);
            if valid {
                assert_eq!(buf, msg, "tcId {id}: plaintext");
                let mut buf = msg.clone();
                let got = cipher.encrypt_in_place_detached(n, &aad, &mut buf).unwrap();
                assert_eq!(buf, ct, "tcId {id}: ciphertext");
                assert_eq!(got.as_slice(), &tag[..], "tcId {id}: tag");
            }
            ran += 1;
        }
    }
    assert_eq!(
        ran + skipped,
        suite["numberOfTests"].as_u64().unwrap() as usize
    );
    eprintln!("wycheproof chacha20-poly1305: ran {ran}, skipped {skipped}");
    assert!(ran >= 300, "ran {ran}, skipped {skipped}");
}
