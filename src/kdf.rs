//! Traits and structs for key derivation functions

use crate::{util::write_u16_be, HpkeError};

use bitcoin_hashes::{sha256, sha384, sha512, Hash, HashEngine, Hmac, HmacEngine};
use generic_array::{
    typenum::{Unsigned, U32, U48, U64},
    ArrayLength, GenericArray,
};
use zeroize::Zeroize;

const VERSION_LABEL: &[u8] = b"HPKE-v1";

// This is the maximum value of Nh. It is achieved by HKDF-SHA512 in RFC 9180 §7.2.
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

/// The implementation of HKDF-SHA384
pub struct HkdfSha384 {}

impl KdfTrait for HkdfSha384 {
    #[doc(hidden)]
    type HashImpl = sha384::Hash;
    #[doc(hidden)]
    type OutputSize = U48;

    // RFC 9180 §7.2: HKDF-SHA384
    const KDF_ID: u16 = 0x0002;
}

/// The implementation of HKDF-SHA512
pub struct HkdfSha512 {}

impl KdfTrait for HkdfSha512 {
    #[doc(hidden)]
    type HashImpl = sha512::Hash;
    #[doc(hidden)]
    type OutputSize = U64;

    // RFC 9180 §7.2: HKDF-SHA512
    const KDF_ID: u16 = 0x0003;
}

// `Kdf::OutputSize` and `HashImpl::LEN` name the same length but nothing ties them together at
// the type level, and the copies into `DigestArray` below would panic on a mismatch. Checking at
// monomorphization turns a wrong `Kdf` impl into a compile error instead.
const fn assert_output_size<Kdf: KdfTrait>() {
    assert!(<Kdf::OutputSize as Unsigned>::USIZE == <Kdf::HashImpl as Hash>::LEN);
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

    // HKDF-Extract is one HMAC, so RFC 4231 cases 2 and 6 pin it for SHA-384 and SHA-512 too,
    // which RFC 5869 and the RFC 9180 known-answer tests never reach. The data is fed in two
    // pieces, as `labeled_extract` does.
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
        check::<HkdfSha384>(
            key,
            data,
            &hex!(
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47"
                "e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
            ),
        );
        check::<HkdfSha512>(
            key,
            data,
            &hex!(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            ),
        );

        // Key longer than every block size, so HMAC hashes it first
        let key = [0xaa_u8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        check::<HkdfSha256>(
            &key,
            data,
            &hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        );
        check::<HkdfSha384>(
            &key,
            data,
            &hex!(
                "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f"
                "3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
            ),
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
        let prk = [0u8; 32];
        let mut okm = [0u8; 255 * 32 + 1];
        assert!(hkdf_expand::<HkdfSha256>(&prk, &[b"info"], &mut okm[..255 * 32]).is_ok());
        assert_eq!(
            hkdf_expand::<HkdfSha256>(&prk, &[b"info"], &mut okm),
            Err(HpkeError::KdfOutputTooLong)
        );
    }
}
