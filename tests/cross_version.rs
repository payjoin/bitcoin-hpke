//! Interoperability with the published bitcoin-hpke 0.13.0 for DHKEM(secp256k1, HKDF-SHA256),
//! HKDF-SHA256 and ChaCha20-Poly1305, the suite payjoin uses.
#![cfg(feature = "secp")]

use bitcoin_hpke as new;
use bitcoin_hpke_0_13 as old;
use rand::{rngs::StdRng, SeedableRng};

use new::{Deserializable as _, Kem as _, Serializable as _};
use old::{Deserializable as _, Kem as _, Serializable as _};

type NewKem = new::kem::SecpK256HkdfSha256;
type NewKdf = new::kdf::HkdfSha256;
type NewAead = new::aead::ChaCha20Poly1305;
type OldKem = old::kem::SecpK256HkdfSha256;
type OldKdf = old::kdf::HkdfSha256;
type OldAead = old::aead::ChaCha20Poly1305;

const IKM_RECIP: &[u8] = b"cross-version recipient ikm";
const IKM_SENDER: &[u8] = b"cross-version sender ikm";
const INFO: &[u8] = b"cross-version info";
const PSK: &[u8] = b"cross-version preshared key 32b!";
const PSK_ID: &[u8] = b"cross-version psk id";
const EXPORTER_CTX: &[u8] = b"cross-version exporter";

#[derive(Clone, Copy, Debug)]
enum Mode {
    Base,
    Psk,
    Auth,
    AuthPsk,
}

const MODES: [Mode; 4] = [Mode::Base, Mode::Psk, Mode::Auth, Mode::AuthPsk];

fn to_new<T: old::Serializable, U: new::Deserializable>(x: &T) -> U {
    U::from_bytes(&x.to_bytes()).unwrap()
}

fn to_old<T: new::Serializable, U: old::Deserializable>(x: &T) -> U {
    U::from_bytes(&x.to_bytes()).unwrap()
}

fn rng() -> StdRng {
    StdRng::seed_from_u64(0x0013_0020)
}

#[test]
fn derived_keys_match_and_parse_across_versions() {
    for ikm in [IKM_RECIP, IKM_SENDER, &[0u8; 32][..]] {
        let (new_sk, new_pk) = NewKem::derive_keypair(ikm);
        let (old_sk, old_pk) = OldKem::derive_keypair(ikm);
        assert_eq!(new_pk.to_bytes().as_slice(), old_pk.to_bytes().as_slice());
        assert_eq!(new_sk.to_bytes().as_slice(), old_sk.to_bytes().as_slice());

        let pk: <OldKem as old::Kem>::PublicKey = to_old(&new_pk);
        let sk: <OldKem as old::Kem>::PrivateKey = to_old(&new_sk);
        assert_eq!(pk.to_bytes(), old_pk.to_bytes());
        assert_eq!(sk.to_bytes(), old_sk.to_bytes());
        let pk: <NewKem as new::Kem>::PublicKey = to_new(&old_pk);
        let sk: <NewKem as new::Kem>::PrivateKey = to_new(&old_sk);
        assert_eq!(pk.to_bytes(), new_pk.to_bytes());
        assert_eq!(sk.to_bytes(), new_sk.to_bytes());
    }
}

#[test]
fn encapped_keys_decap_across_versions() {
    let mut rng = rng();
    let (new_sk_r, new_pk_r) = NewKem::derive_keypair(IKM_RECIP);
    let (old_sk_r, old_pk_r) = OldKem::derive_keypair(IKM_RECIP);
    let (new_sk_s, new_pk_s) = NewKem::derive_keypair(IKM_SENDER);
    let (old_sk_s, old_pk_s) = OldKem::derive_keypair(IKM_SENDER);

    for auth in [false, true] {
        let old_id = auth.then_some((&old_sk_s, &old_pk_s));
        let new_id = auth.then_some((&new_sk_s, &new_pk_s));

        let (ss, enc) = OldKem::encap(&old_pk_r, old_id, &mut rng).unwrap();
        let got = NewKem::decap(&new_sk_r, new_id.map(|id| id.1), &to_new(&enc)).unwrap();
        assert_eq!(ss.0.as_slice(), got.0.as_slice(), "0.13 encap, auth {auth}");

        let (ss, enc) = NewKem::encap(&new_pk_r, new_id, &mut rng).unwrap();
        let got = OldKem::decap(&old_sk_r, old_id.map(|id| id.1), &to_old(&enc)).unwrap();
        assert_eq!(ss.0.as_slice(), got.0.as_slice(), "0.20 encap, auth {auth}");
    }
}

// Seals with one version's context and opens with the other's. A failed open leaves the
// receiver's sequence number alone, so each tampered attempt is followed by the honest one.
fn check_channel(
    mode: Mode,
    mut seal: impl FnMut(&mut [u8], &[u8]) -> Vec<u8>,
    mut open: impl FnMut(&mut [u8], &[u8], &[u8]) -> bool,
) {
    for (i, aad) in [&b""[..], b"aad", b"", b"longer associated data"]
        .into_iter()
        .enumerate()
    {
        let msg = format!("message {i} in {mode:?} mode").into_bytes();
        let mut ct = msg.clone();
        let tag = seal(&mut ct, aad);

        let mut bad = ct.clone();
        bad[i] ^= 1;
        assert!(
            !open(&mut bad, aad, &tag),
            "tampered ciphertext {i} in {mode:?}"
        );

        assert!(open(&mut ct, aad, &tag), "message {i} in {mode:?}");
        assert_eq!(ct, msg);
    }
}

fn old_sender_new_receiver(mode: Mode) {
    let (sk_r, pk_r) = NewKem::derive_keypair(IKM_RECIP);
    let (sk_s, pk_s) = OldKem::derive_keypair(IKM_SENDER);
    let psk = old::PskBundle {
        psk: PSK,
        psk_id: PSK_ID,
    };
    let new_psk = new::PskBundle {
        psk: PSK,
        psk_id: PSK_ID,
    };
    let (mode_s, mode_r) = match mode {
        Mode::Base => (old::OpModeS::Base, new::OpModeR::Base),
        Mode::Psk => (old::OpModeS::Psk(psk), new::OpModeR::Psk(new_psk)),
        Mode::Auth => (
            old::OpModeS::Auth((sk_s, pk_s.clone())),
            new::OpModeR::Auth(to_new(&pk_s)),
        ),
        Mode::AuthPsk => (
            old::OpModeS::AuthPsk((sk_s, pk_s.clone()), psk),
            new::OpModeR::AuthPsk(to_new(&pk_s), new_psk),
        ),
    };

    let (enc, mut ctx_s) =
        old::setup_sender::<OldAead, OldKdf, OldKem, _>(&mode_s, &to_old(&pk_r), INFO, &mut rng())
            .unwrap();
    let mut ctx_r =
        new::setup_receiver::<NewAead, NewKdf, NewKem>(&mode_r, &sk_r, &to_new(&enc), INFO)
            .unwrap();

    let (mut out_s, mut out_r) = ([0u8; 64], [0u8; 64]);
    ctx_s.export(EXPORTER_CTX, &mut out_s).unwrap();
    ctx_r.export(EXPORTER_CTX, &mut out_r).unwrap();
    assert_eq!(out_s, out_r, "export in {mode:?}");

    check_channel(
        mode,
        |buf, aad| {
            ctx_s
                .seal_in_place_detached(buf, aad)
                .unwrap()
                .to_bytes()
                .to_vec()
        },
        |buf, aad, tag| {
            let tag = new::aead::AeadTag::from_bytes(tag).unwrap();
            ctx_r.open_in_place_detached(buf, aad, &tag).is_ok()
        },
    );
}

fn new_sender_old_receiver(mode: Mode) {
    let (sk_r, pk_r) = OldKem::derive_keypair(IKM_RECIP);
    let (sk_s, pk_s) = NewKem::derive_keypair(IKM_SENDER);
    let psk = new::PskBundle {
        psk: PSK,
        psk_id: PSK_ID,
    };
    let old_psk = old::PskBundle {
        psk: PSK,
        psk_id: PSK_ID,
    };
    let (mode_s, mode_r) = match mode {
        Mode::Base => (new::OpModeS::Base, old::OpModeR::Base),
        Mode::Psk => (new::OpModeS::Psk(psk), old::OpModeR::Psk(old_psk)),
        Mode::Auth => (
            new::OpModeS::Auth((sk_s, pk_s.clone())),
            old::OpModeR::Auth(to_old(&pk_s)),
        ),
        Mode::AuthPsk => (
            new::OpModeS::AuthPsk((sk_s, pk_s.clone()), psk),
            old::OpModeR::AuthPsk(to_old(&pk_s), old_psk),
        ),
    };

    let (enc, mut ctx_s) =
        new::setup_sender::<NewAead, NewKdf, NewKem, _>(&mode_s, &to_new(&pk_r), INFO, &mut rng())
            .unwrap();
    let mut ctx_r =
        old::setup_receiver::<OldAead, OldKdf, OldKem>(&mode_r, &sk_r, &to_old(&enc), INFO)
            .unwrap();

    let (mut out_s, mut out_r) = ([0u8; 64], [0u8; 64]);
    ctx_s.export(EXPORTER_CTX, &mut out_s).unwrap();
    ctx_r.export(EXPORTER_CTX, &mut out_r).unwrap();
    assert_eq!(out_s, out_r, "export in {mode:?}");

    check_channel(
        mode,
        |buf, aad| {
            ctx_s
                .seal_in_place_detached(buf, aad)
                .unwrap()
                .to_bytes()
                .to_vec()
        },
        |buf, aad, tag| {
            let tag = old::aead::AeadTag::from_bytes(tag).unwrap();
            ctx_r.open_in_place_detached(buf, aad, &tag).is_ok()
        },
    );
}

#[test]
fn old_sender_to_new_receiver() {
    MODES.into_iter().for_each(old_sender_new_receiver);
}

#[test]
fn new_sender_to_old_receiver() {
    MODES.into_iter().for_each(new_sender_old_receiver);
}
