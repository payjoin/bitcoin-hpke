//! Traits and structs for key derivation functions

use crate::{util::write_u16_be, HpkeError};

use bitcoin_hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use generic_array::{
    typenum::{Unsigned, U32},
    ArrayLength, GenericArray,
};
use zeroize::Zeroize;

const VERSION_LABEL: &[u8] = b"HPKE-v1";

// This is the maximum value of Nh in RFC 9180 §7.2, achieved by HKDF-SHA512. It sizes the fixed
// key-schedule buffers in `setup`, and `Kdf` is a public trait, so it stays at the spec-wide bound
// rather than the 32 bytes of the one KDF implemented here. `assert_output_size` enforces it.
pub(crate) const MAX_DIGEST_SIZE: usize = 64;

/// Represents key derivation functionality
pub trait Kdf {
    /// The underlying hash function
    #[doc(hidden)]
    type HashImpl: Hash;

    /// The output length of `HashImpl` in bytes as a type-level integer. This is Nh in RFC 9180
    /// §7.2.
    #[doc(hidden)]
    type OutputSize: ArrayLength<u8>;

    /// The algorithm identifier for a KDF implementation
    const KDF_ID: u16;
}

// We use Kdf as a type parameter, so this is to avoid ambiguity.
use Kdf as KdfTrait;

pub(crate) type DigestArray<Kdf> = GenericArray<u8, <Kdf as KdfTrait>::OutputSize>;

/// The implementation of HKDF-SHA256
pub struct HkdfSha256 {}

impl KdfTrait for HkdfSha256 {
    #[doc(hidden)]
    type HashImpl = sha256::Hash;
    #[doc(hidden)]
    type OutputSize = U32;

    // RFC 9180 §7.2: HKDF-SHA256
    const KDF_ID: u16 = 0x0001;
}

// `Kdf::OutputSize` and `HashImpl::LEN` name the same length but nothing ties them together at
// the type level, and the copies into `DigestArray` below would panic on a mismatch. A digest
// wider than `MAX_DIGEST_SIZE` would likewise overflow the key-schedule buffers in `setup`.
// Checking at monomorphization turns a wrong `Kdf` impl into a compile error instead.
const fn assert_output_size<Kdf: KdfTrait>() {
    assert!(<Kdf::OutputSize as Unsigned>::USIZE == <Kdf::HashImpl as Hash>::LEN);
    assert!(<Kdf::OutputSize as Unsigned>::USIZE <= MAX_DIGEST_SIZE);
}

// RFC 5869 §2.2
// PRK = HMAC-Hash(salt, IKM)
//
// An empty salt stands in for the HashLen zero bytes the RFC prescribes, since HMAC zero-pads any
// key shorter than the block size. The IKM is taken in pieces so callers can prepend labels
// without concatenating into a buffer.
fn hkdf_extract<Kdf: KdfTrait>(salt: &[u8], ikm: &[&[u8]]) -> DigestArray<Kdf> {
    const { assert_output_size::<Kdf>() }
    let mut engine = HmacEngine::<Kdf::HashImpl>::new(salt);
    for part in ikm {
        engine.input(part);
    }
    let prk = Hmac::<Kdf::HashImpl>::from_engine(engine);
    GenericArray::clone_from_slice(&prk[..])
}

// RFC 5869 §2.3
// N = ceil(L/HashLen)
// T(0) = empty string (zero length)
// T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
// OKM = first L octets of T(1) | T(2) | ... | T(N)
fn hkdf_expand<Kdf: KdfTrait>(prk: &[u8], info: &[&[u8]], okm: &mut [u8]) -> Result<(), HpkeError> {
    const { assert_output_size::<Kdf>() }
    let hash_len = <Kdf::HashImpl as Hash>::LEN;
    // The block counter is a single octet, so at most 255 blocks can be produced
    if okm.len() > 255 * hash_len {
        return Err(HpkeError::KdfOutputTooLong);
    }

    let mut prev = DigestArray::<Kdf>::default();
    for (i, chunk) in okm.chunks_mut(hash_len).enumerate() {
        let mut engine = HmacEngine::<Kdf::HashImpl>::new(prk);
        if i > 0 {
            engine.input(&prev);
        }
        for part in info {
            engine.input(part);
        }
        engine.input(&[(i + 1) as u8]);
        prev.copy_from_slice(&Hmac::<Kdf::HashImpl>::from_engine(engine)[..]);
        chunk.copy_from_slice(&prev[..chunk.len()]);
    }
    prev.zeroize();

    Ok(())
}

// RFC 9180 §4.1
// def ExtractAndExpand(dh, kem_context):
//   eae_prk = LabeledExtract("", "eae_prk", dh)
//   shared_secret = LabeledExpand(eae_prk, "shared_secret",
//                                 kem_context, Nsecret)
//   return shared_secret

/// Uses the given IKM to extract a secret, and then uses that secret, plus the given suite ID and
/// info string, to expand to the output buffer
#[doc(hidden)]
pub fn extract_and_expand<Kdf: KdfTrait>(
    ikm: &[u8],
    suite_id: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), HpkeError> {
    let mut prk = labeled_extract::<Kdf>(&[], suite_id, b"eae_prk", ikm);
    let res = labeled_expand::<Kdf>(&prk, suite_id, b"shared_secret", info, out);
    prk.zeroize();
    res
}

// RFC 9180 §4
// def LabeledExtract(salt, label, ikm):
//   labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
//   return Extract(salt, labeled_ikm)

/// Returns the PRK derived from `(salt=salt, ikm="HPKE-v1"||suite_id||label||ikm)`
#[doc(hidden)]
pub fn labeled_extract<Kdf: KdfTrait>(
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> DigestArray<Kdf> {
    hkdf_extract::<Kdf>(salt, &[VERSION_LABEL, suite_id, label, ikm])
}

// RFC 9180 §4
// def LabeledExpand(prk, label, info, L):
//   labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
//                         label, info)
//   return Expand(prk, labeled_info, L)

/// Fills `out` with the `LabeledExpand` of the given PRK. If `out.len()` is more than 255x the
/// digest size (in bytes) of the underlying hash function, returns an
/// `Err(HpkeError::KdfOutputTooLong)`.
#[doc(hidden)]
pub fn labeled_expand<Kdf: KdfTrait>(
    prk: &[u8],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), HpkeError> {
    // We need to write the length as a u16, so that's the de-facto upper bound on length
    if out.len() > u16::MAX as usize {
        return Err(HpkeError::KdfOutputTooLong);
    }

    let mut len_buf = [0u8; 2];
    write_u16_be(&mut len_buf, out.len() as u16);

    hkdf_expand::<Kdf>(prk, &[&len_buf, VERSION_LABEL, suite_id, label, info], out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin_hashes::sha512;
    use generic_array::typenum::U64;

    // Test-only HKDF-SHA512. Not exported, since no Bitcoin HPKE deployment uses it, but it runs
    // the generic Extract and Expand code at a second block and digest size.
    struct HkdfSha512 {}

    impl KdfTrait for HkdfSha512 {
        type HashImpl = sha512::Hash;
        type OutputSize = U64;
        const KDF_ID: u16 = 0x0003;
    }

    use hex_literal::hex;

    // RFC 5869 Appendix A, cases 1-3 (SHA-256). Case 2 needs three output blocks, case 3 has an
    // empty salt and info.
    #[test]
    fn rfc5869_sha256() {
        fn check(ikm: &[u8], salt: &[u8], info: &[u8], prk: &[u8], okm: &[u8]) {
            let got_prk = hkdf_extract::<HkdfSha256>(salt, &[ikm]);
            assert_eq!(got_prk.as_slice(), prk);
            let mut got_okm = [0u8; 82];
            let got_okm = &mut got_okm[..okm.len()];
            hkdf_expand::<HkdfSha256>(&got_prk, &[info], got_okm).unwrap();
            assert_eq!(got_okm, okm);
        }

        check(
            &hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            &hex!("000102030405060708090a0b0c"),
            &hex!("f0f1f2f3f4f5f6f7f8f9"),
            &hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
            &hex!(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865"
            ),
        );
        check(
            &hex!(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                "404142434445464748494a4b4c4d4e4f"
            ),
            &hex!(
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
            ),
            &hex!(
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            ),
            &hex!("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
            &hex!(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                "cc30c58179ec3e87c14c01d5c1f3434f1d87"
            ),
        );
        check(
            &hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            &[],
            &[],
            &hex!("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
            &hex!(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                "9d201395faa4b61a96c8"
            ),
        );
    }

    // HKDF-Extract is one HMAC, so RFC 4231 cases 2 and 6 pin it directly. The data is fed in
    // two pieces, as `labeled_extract` does, which neither RFC 5869 nor Wycheproof exercise.
    // `HkdfSha512` keeps the generic Extract and Expand code honest at a second block and
    // digest size, since every shipped `Kdf` is 32 bytes wide.
    #[test]
    fn extract_is_hmac_rfc4231() {
        fn check<Kdf: KdfTrait>(key: &[u8], data: &[u8], expected: &[u8]) {
            let (head, tail) = data.split_at(5);
            let prk = hkdf_extract::<Kdf>(key, &[head, tail]);
            assert_eq!(prk.as_slice(), expected);
        }

        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        check::<HkdfSha256>(
            key,
            data,
            &hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        );

        check::<HkdfSha512>(
            key,
            data,
            &hex!(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            ),
        );

        // RFC 4231 case 6: the key exceeds SHA-512's 128-byte block, so HMAC hashes it first
        let key = [0xaa_u8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        check::<HkdfSha256>(
            &key,
            data,
            &hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        );
        check::<HkdfSha512>(
            &key,
            data,
            &hex!(
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
                "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
            ),
        );
    }

    #[test]
    fn expand_rejects_more_than_255_blocks() {
        fn check<Kdf: KdfTrait>() {
            let hash_len = <Kdf::HashImpl as Hash>::LEN;
            let prk = [0u8; MAX_DIGEST_SIZE];
            let mut okm = [0u8; 255 * MAX_DIGEST_SIZE + 1];
            let (prk, okm) = (&prk[..hash_len], &mut okm[..255 * hash_len + 1]);
            assert!(hkdf_expand::<Kdf>(prk, &[b"info"], &mut okm[..255 * hash_len]).is_ok());
            assert_eq!(
                hkdf_expand::<Kdf>(prk, &[b"info"], okm),
                Err(HpkeError::KdfOutputTooLong)
            );
        }
        check::<HkdfSha256>();
        check::<HkdfSha512>();
    }

    // Wycheproof's HKDF-SHA-256 suite, from https://github.com/C2SP/wycheproof (testvectors_v1).
    // It covers empty salts and infos, the 255-block maximum, and over-long requests.
    #[cfg(feature = "std")]
    mod wycheproof {
        use super::*;

        use std::{fs::File, string::String, vec::Vec};

        #[derive(serde::Deserialize)]
        struct TestFile {
            #[serde(rename = "numberOfTests")]
            number_of_tests: usize,
            #[serde(rename = "testGroups")]
            test_groups: Vec<TestGroup>,
        }

        #[derive(serde::Deserialize)]
        struct TestGroup {
            tests: Vec<TestCase>,
        }

        #[derive(serde::Deserialize)]
        struct TestCase {
            #[serde(rename = "tcId")]
            tc_id: u32,
            ikm: String,
            salt: String,
            info: String,
            size: usize,
            okm: String,
            result: String,
        }

        fn run<Kdf: KdfTrait>(path: &str) {
            let file: TestFile = serde_json::from_reader(File::open(path).unwrap()).unwrap();

            let mut n = 0;
            for tc in file.test_groups.iter().flat_map(|g| g.tests.iter()) {
                let ikm = hex::decode(&tc.ikm).unwrap();
                let salt = hex::decode(&tc.salt).unwrap();
                let info = hex::decode(&tc.info).unwrap();
                let expected = hex::decode(&tc.okm).unwrap();

                let prk = hkdf_extract::<Kdf>(&salt, &[&ikm]);
                let mut okm = vec![0u8; tc.size];
                let res = hkdf_expand::<Kdf>(&prk, &[&info], &mut okm);

                match tc.result.as_str() {
                    "valid" | "acceptable" => {
                        assert_eq!(res, Ok(()), "tcId {}", tc.tc_id);
                        assert_eq!(okm, expected, "tcId {}", tc.tc_id);
                    }
                    "invalid" => {
                        assert_eq!(res, Err(HpkeError::KdfOutputTooLong), "tcId {}", tc.tc_id)
                    }
                    other => panic!("tcId {}: unknown result {}", tc.tc_id, other),
                }
                n += 1;
            }
            assert_eq!(n, file.number_of_tests);
        }

        #[test]
        fn hkdf_sha256() {
            run::<HkdfSha256>("test-vectors-wycheproof-hkdf-sha256.json");
        }
    }
}
