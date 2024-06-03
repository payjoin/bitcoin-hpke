use crate::{
    dhkex::{DhError, DhKeyExchange},
    kdf::{labeled_extract, Kdf as KdfTrait, LabeledExpand},
    util::{enforce_equal_len, enforce_outbuf_len, KemSuiteId},
    Deserializable, HpkeError, Serializable,
};

use generic_array::typenum::{self, Unsigned};
use subtle::{Choice, ConstantTimeEq};

// We wrap the types in order to abstract away the secps56k1 dep

/// A secp256k1 public key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(bitcoin::secp256k1::PublicKey);

/// A secp256k1 private key
#[derive(Clone)]
pub struct PrivateKey(bitcoin::secp256k1::SecretKey);

impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.secret_bytes().ct_eq(&other.0.secret_bytes())
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl Eq for PrivateKey {}

/// A bare DH computation result
pub struct KexResult([u8; 64]);

impl Serializable for PublicKey {
    // IANA HPKE KEM Identifiers: Npk of DHKEM(Secp256k1, HKDF-SHA256) is 65
    type OutputSize = typenum::U65;

    // secp256k1 lets us serialize uncompressed pubkeys to [u8; 65]
    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        buf.copy_from_slice(&self.0.serialize_uncompressed());
    }
}

impl Deserializable for PublicKey {
    // secp256k1 lets us convert [u8; 65] to pubkeys. Assuming the input length is correct, this
    // conversion is infallible, so no ValidationErrors are raised.
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // TODO can I get rid of equal len since bitcoin::secp256k1 already does this?
        // Pubkeys must be 65 bytes
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Copy to a fixed-size array
        let mut arr = [0u8; bitcoin::secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
        arr.copy_from_slice(encoded);
        Ok(PublicKey(
            bitcoin::secp256k1::PublicKey::from_slice(&arr)
                .map_err(|_| HpkeError::ValidationError)?,
        ))
    }
}

impl Serializable for PrivateKey {
    // IANA HPKE KEM Identifiers:Nsk of DHKEM(Secp256k1, HKDF-SHA256) is 32
    type OutputSize = typenum::U32;

    // secp256k1 lets us convert scalars to [u8; 32]
    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        buf.copy_from_slice(&self.0.secret_bytes());
    }
}
impl Deserializable for PrivateKey {
    // Secp256k1 lets us convert [u8; 32] to scalars. Assuming the input length is correct, this
    // conversion is infallible, so no ValidationErrors are raised.
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        // Privkeys must be 32 bytes
        enforce_equal_len(Self::OutputSize::to_usize(), encoded.len())?;

        // Copy to a fixed-size array
        let mut arr = [0u8; bitcoin::secp256k1::constants::SECRET_KEY_SIZE];
        arr.copy_from_slice(encoded);

        // * Invariant: PrivateKey is in [1,p). This is preserved here.
        // * SecretKey::from_slice() directly checks that the value isn't zero. And
        //   its submethod,
        // * ffi::secp256k1_ec_seckey_verify() checks that the value doesn't exceed the
        //   curve order.
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&arr)
            .map_err(|_| HpkeError::ValidationError)?;
        Ok(PrivateKey(sk))
    }
}

impl Serializable for KexResult {
    // RFC 9180 §4.1: For Secp256k1, the size Ndh is equal to 32
    type OutputSize = typenum::U32;

    // secp256k1's point representation is our DH result. We don't have to do anything special.
    fn write_exact(&self, buf: &mut [u8]) {
        // Check the length is correct and panic if not
        enforce_outbuf_len::<Self>(buf);

        // Dalek lets us convert shared secrets to to [u8; 32]
        buf.copy_from_slice(&self.0[..bitcoin::secp256k1::constants::SECRET_KEY_SIZE]);
    }
}

/// Represents ECDH functionality over the Secp256k1 group
pub struct Secp256k1 {}

impl DhKeyExchange for Secp256k1 {
    #[doc(hidden)]
    type PublicKey = PublicKey;
    #[doc(hidden)]
    type PrivateKey = PrivateKey;
    #[doc(hidden)]
    type KexResult = KexResult;

    /// Converts an Secp256k1 private key to a public key
    #[doc(hidden)]
    fn sk_to_pk(sk: &PrivateKey) -> PublicKey {
        PublicKey(bitcoin::secp256k1::PublicKey::from_secret_key_global(&sk.0))
    }

    /// Does the DH operation. Returns an error if and only if the DH result was all zeros. This is
    /// required by the HPKE spec. The error is converted into the appropriate higher-level error
    /// by the caller, i.e., `HpkeError::EncapError` or `HpkeError::DecapError`.
    #[doc(hidden)]
    fn dh(sk: &PrivateKey, pk: &PublicKey) -> Result<KexResult, DhError> {
        use bitcoin::secp256k1::constants::SECRET_KEY_SIZE;
        let res = bitcoin::secp256k1::ecdh::shared_secret_point(&pk.0, &sk.0);
        // "Senders and recipients MUST check whether the shared secret is the all-zero value
        // and abort if so"
        if res[..SECRET_KEY_SIZE].ct_eq(&[0u8; SECRET_KEY_SIZE]).into() {
            Err(DhError)
        } else {
            Ok(KexResult(res))
        }
    }

    // RFC 9180 §7.1.3
    // def DeriveKeyPair(ikm):
    //   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
    //   sk = LabeledExpand(dkp_prk, "sk", "", Nsk)
    //   return (sk, pk(sk))

    /// Deterministically derives a keypair from the given input keying material and ciphersuite
    /// ID. The keying material SHOULD have as many bits of entropy as the bit length of a secret
    /// key, i.e., 256.
    #[doc(hidden)]
    fn derive_keypair<Kdf: KdfTrait>(suite_id: &KemSuiteId, ikm: &[u8]) -> (PrivateKey, PublicKey) {
        // Write the label into a byte buffer and extract from the IKM
        let (_, hkdf_ctx) = labeled_extract::<Kdf>(&[], suite_id, b"dkp_prk", ikm);
        // The buffer we hold the candidate scalar bytes in. This is the size of a private key.
        let mut buf = [0u8; 32];
        hkdf_ctx
            .labeled_expand(suite_id, b"sk", &[], &mut buf)
            .unwrap();

        let sk = bitcoin::secp256k1::SecretKey::from_slice(&buf).expect("clamped private key");
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key_global(&sk);
        (PrivateKey(sk), PublicKey(pk))
    }
}

#[cfg(test)]
mod tests {
    use crate::dhkex::{secp256k1::Secp256k1, Deserializable, DhKeyExchange, Serializable};
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn just_test_secp_roundtrip() {
        use secp256k1::{generate_keypair, PublicKey, SecretKey};
        let (sk1, pk1) = generate_keypair(&mut rand_core::OsRng);
        assert_eq!(SecretKey::from_slice(&sk1[..]), Ok(sk1));
        assert_eq!(PublicKey::from_slice(&pk1.serialize()[..]), Ok(pk1));
        assert_eq!(
            PublicKey::from_slice(&pk1.serialize_uncompressed()[..]),
            Ok(pk1)
        );
    }

    use crate::test_util::dhkex_gen_keypair;

    use hex_literal::hex;

    //
    // Test vectors come from the draft's AES-128-GCM first base test case.
    // https://www.ietf.org/archive/id/draft-wahby-cfrg-hpke-kem-secp256k1-01.html#name-dhkemsecp256k1-hkdf-sha256-
    //

    #[cfg(feature = "secp")]
    const K256_PRIVKEYS: &[&[u8]] = &[
        &hex!("30FBC0D4 1CD01885 333211FF 53B9ED29 BCBDCCC3 FF13625A 82DB61A7 BB8EAE19"),
        &hex!("A795C287 C132154A 8B96DC81 DC8B4E2F 02BBBAD7 8DAB0567 B59DB1D1 540751F6"),
    ];

    // The public keys corresponding to the above private keys, in order
    #[cfg(feature = "secp")]
    const K256_PUBKEYS: &[&[u8]] = &[
        &hex!(
            "04"                                                                      // Uncompressed
            "59177516 8F328A2A DBCB887A CD287D55 A1025D7D 2B15E193 7278A5EF D1D48B19" // x-coordinate
            "C00CF075 59320E6D 278A71C9 E58BAE5D 9AB041D7 905C6629 1F4D0845 9C946E18" // y-coordinate
        ),
        &hex!(
            "04"                                                                      // Uncompressed
            "3EE73144 07753D1B A296DE29 F07B2CD5 505CA94B 614F127E 71F3C19F C7845DAF" // x-coordinate
            "49C9BB4B F4D00D3B 5411C8EB 86D59A2D CADC5A13 115FA9FE F44D1E0B 7EF11CAB" // y-coordinate
        ),
    ];

    // The result of DH(privkey0, pubkey1) or equivalently, DH(privkey1, pubkey0)
    #[cfg(feature = "secp")]
    const K256_DH_RES_XCOORD: &[u8] =
        &hex!("3ADDFBC2 B30E3D1B 1DF262A4 D6CECF73 A11DF8BD 93E0EB21 FC11847C 6F3DDBE2");

    /// Tests the ECDH op against a known answer
    #[allow(dead_code)]
    fn test_vector_ecdh<Kex: DhKeyExchange>(
        sk_recip_bytes: &[u8],
        pk_sender_bytes: &[u8],
        dh_res_xcoord_bytes: &[u8],
    ) {
        // Deserialize the pubkey and privkey and do a DH operation
        let sk_recip = Kex::PrivateKey::from_bytes(&sk_recip_bytes).unwrap();
        let pk_sender = Kex::PublicKey::from_bytes(&pk_sender_bytes).unwrap();
        let derived_dh = Kex::dh(&sk_recip, &pk_sender).unwrap();

        // Assert that the derived DH result matches the test vector. Recall that the HPKE DH
        // result is just the x-coordinate, so that's all we can compare
        assert_eq!(derived_dh.to_bytes().as_slice(), dh_res_xcoord_bytes,);
    }

    /// Tests that an deserialize-serialize round-trip ends up at the same pubkey
    #[allow(dead_code)]
    fn test_pubkey_serialize_correctness<Kex: DhKeyExchange>() {
        let mut csprng = StdRng::from_entropy();

        // We can't do the same thing as in the X25519 tests, since a completely random point
        // is not likely to lie on the curve. Instead, we just generate a random point,
        // serialize it, deserialize it, and test whether it's the same using impl Eq for
        // AffinePoint

        let (_, pubkey) = dhkex_gen_keypair::<Kex, _>(&mut csprng);
        let pubkey_bytes = pubkey.to_bytes();
        let rederived_pubkey =
            <Kex as DhKeyExchange>::PublicKey::from_bytes(&pubkey_bytes).unwrap();

        // See if the re-serialized bytes are the same as the input
        assert_eq!(pubkey, rederived_pubkey);
    }

    /// Tests the `sk_to_pk` function against known answers
    #[allow(dead_code)]
    fn test_vector_corresponding_pubkey<Kex: DhKeyExchange>(sks: &[&[u8]], pks: &[&[u8]]) {
        for (sk_bytes, pk_bytes) in sks.iter().zip(pks.iter()) {
            // Deserialize the hex values
            let sk = Kex::PrivateKey::from_bytes(sk_bytes).unwrap();
            let pk = Kex::PublicKey::from_bytes(pk_bytes).unwrap();

            // Derive the secret key's corresponding pubkey and check that it matches the given
            // pubkey
            let derived_pk = Kex::sk_to_pk(&sk);
            assert_eq!(derived_pk, pk);
        }
    }

    /// Tests that an deserialize-serialize round-trip on a DH keypair ends up at the same values
    #[allow(dead_code)]
    fn test_dh_serialize_correctness<Kex: DhKeyExchange>()
    where
        Kex::PrivateKey: PartialEq,
    {
        let mut csprng = StdRng::from_entropy();

        // Make a random keypair and serialize it
        let (sk, pk) = dhkex_gen_keypair::<Kex, _>(&mut csprng);
        let (sk_bytes, pk_bytes) = (sk.to_bytes(), pk.to_bytes());

        // Now deserialize those bytes
        let new_sk = Kex::PrivateKey::from_bytes(&sk_bytes).unwrap();
        let new_pk = Kex::PublicKey::from_bytes(&pk_bytes).unwrap();

        // See if the deserialized values are the same as the initial ones
        assert!(new_sk == sk, "private key doesn't serialize correctly");
        assert!(new_pk == pk, "public key doesn't serialize correctly");
    }

    #[cfg(feature = "secp")]
    #[test]
    fn test_vector_ecdh_k256() {
        test_vector_ecdh::<Secp256k1>(&K256_PRIVKEYS[0], &K256_PUBKEYS[1], &K256_DH_RES_XCOORD);
    }

    #[cfg(feature = "secp")]
    #[test]
    fn test_vector_corresponding_pubkey_k256() {
        test_vector_corresponding_pubkey::<Secp256k1>(K256_PRIVKEYS, K256_PUBKEYS);
    }

    #[cfg(feature = "secp")]
    #[test]
    fn test_pubkey_serialize_correctness_k256() {
        test_pubkey_serialize_correctness::<Secp256k1>();
    }

    #[cfg(feature = "secp")]
    #[test]
    fn test_dh_serialize_correctness_k256() {
        use super::Secp256k1;

        test_dh_serialize_correctness::<Secp256k1>();
    }
}
