//! Adapters that back the RustCrypto `digest` traits with rust-bitcoin primitives

use digest::{
    core_api::BlockSizeUser, FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser,
    Reset, Update,
};
use generic_array::typenum::{U128, U32, U48, U64};

use bitcoin_hashes::{sha256, sha384, sha512, Hash, HashEngine};

// Wrapping the bitcoin_hashes engines gives them the blanket `impl Digest` that
// `SimpleHmac`/`Hkdf` require. The engines buffer partial blocks and pad on finalize
// themselves, so the adapter only forwards bytes.
macro_rules! impl_sha {
    ($(#[$doc:meta])* $name:ident, $engine:ty, $hash:ty, $out:ty, $block:ty) => {
        $(#[$doc])*
        #[derive(Clone, Default)]
        pub struct $name($engine);

        impl HashMarker for $name {}

        impl OutputSizeUser for $name {
            type OutputSize = $out;
        }

        impl BlockSizeUser for $name {
            type BlockSize = $block;
        }

        impl Update for $name {
            fn update(&mut self, data: &[u8]) {
                self.0.input(data);
            }
        }

        impl FixedOutput for $name {
            fn finalize_into(self, out: &mut Output<Self>) {
                let hash = <$hash>::from_engine(self.0);
                out.copy_from_slice(hash.as_byte_array());
            }
        }

        impl Reset for $name {
            fn reset(&mut self) {
                self.0 = <$engine>::default();
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                let engine = core::mem::take(&mut self.0);
                let hash = <$hash>::from_engine(engine);
                out.copy_from_slice(hash.as_byte_array());
            }
        }
    };
}

impl_sha!(
    /// SHA-256 backed by `bitcoin_hashes::sha256`.
    Sha256, sha256::HashEngine, sha256::Hash, U32, U64
);
impl_sha!(
    /// SHA-384 backed by `bitcoin_hashes::sha384`.
    Sha384, sha384::HashEngine, sha384::Hash, U48, U128
);
impl_sha!(
    /// SHA-512 backed by `bitcoin_hashes::sha512`.
    Sha512, sha512::HashEngine, sha512::Hash, U64, U128
);

#[cfg(test)]
mod tests {
    use digest::Digest;
    use hex_literal::hex;
    use hmac::{Mac, SimpleHmac};

    use super::{Sha256, Sha384, Sha512};

    // NIST "abc" vectors. The RFC 9180 KATs only exercise SHA-256.
    #[test]
    fn sha2_abc_vectors() {
        assert_eq!(
            Sha256::digest(b"abc").as_slice(),
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            Sha384::digest(b"abc").as_slice(),
            hex!(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
                "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
            )
        );
        assert_eq!(
            Sha512::digest(b"abc").as_slice(),
            hex!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    // Run an HMAC vector through `SimpleHmac<D>`, the same path `kdf::SimpleHkdf` takes
    macro_rules! assert_hmac {
        ($hash:ty, $key:expr, $data:expr, $expected:expr) => {{
            let mut mac = <SimpleHmac<$hash> as Mac>::new_from_slice($key).unwrap();
            mac.update($data);
            assert_eq!(mac.finalize().into_bytes().as_slice(), $expected);
        }};
    }

    // RFC 4231 cases 2 and 6. HMAC pads a short key to the block size and hashes an
    // over-long one, so these fail if an adapter's `BlockSize` is wrong.
    #[test]
    fn hmac_rfc4231_pins_block_size() {
        let (key, data) = (
            b"Jefe".as_slice(),
            b"what do ya want for nothing?".as_slice(),
        );
        assert_hmac!(
            Sha256,
            key,
            data,
            hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        assert_hmac!(
            Sha384,
            key,
            data,
            hex!(
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47"
                "e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
            )
        );
        assert_hmac!(
            Sha512,
            key,
            data,
            hex!(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            )
        );

        // Key longer than every block size, so it is hashed first
        let key = [0xaa_u8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First".as_slice();
        assert_hmac!(
            Sha256,
            &key,
            data,
            hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
        assert_hmac!(
            Sha384,
            &key,
            data,
            hex!(
                "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f"
                "3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
            )
        );
        assert_hmac!(
            Sha512,
            &key,
            data,
            hex!(
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
                "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
            )
        );
    }
}
