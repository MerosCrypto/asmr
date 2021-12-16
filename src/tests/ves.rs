use digest::Digest;
use blake2::Blake2b;

use rand::rngs::OsRng;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use secp256kfun::{marker::*, g, G};

use bitcoin::secp256k1::{self, Secp256k1};

use crate::crypto::{secp256k1 as Secp256k1Engine, ed25519};

#[test]
fn secp256k1() {
  let _ = env_logger::builder().is_test(true).try_init();
  lazy_static::lazy_static! {
    pub static ref SECP: Secp256k1<secp256k1::All> = Secp256k1::new();
  }

  let signing_key = secp256kfun::Scalar::random(&mut OsRng);
  let pub_signing_key = g!(signing_key * G).mark::<Normal>();
  let encryption_key = secp256kfun::Scalar::random(&mut OsRng);
  let pub_encryption_key = g!(encryption_key * G).mark::<Normal>();
  let message: [u8; 32] = sha2::Sha256::digest(b"hello world").into();

  let enc_sig = Secp256k1Engine::encrypted_sign(&signing_key, &pub_encryption_key, &message)
    .expect("Failed to create encrypted signature");
  Secp256k1Engine::encrypted_verify(&pub_signing_key, &pub_encryption_key, &enc_sig, &message)
    .expect("Failed to verify encrypted signature");
  let dec_sig = Secp256k1Engine::decrypt_signature(&enc_sig, &encryption_key)
    .expect("Failed to decrypt signature");

  let sig_bytes = dec_sig.serialize();
  let pubkey_bytes = pub_signing_key.to_bytes();
  let no_fun_message = secp256k1::Message::from_slice(&message).unwrap();
  let no_fun_sig = secp256k1::Signature::from_compact(&sig_bytes).unwrap();
  let no_fun_pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes).unwrap();
  SECP.verify(&no_fun_message, &no_fun_sig, &no_fun_pubkey).expect("Decrypted invalid signature");

  let recreated_encryption_key = Secp256k1Engine::recover_key(&pub_encryption_key, &enc_sig, &dec_sig)
    .expect("Failed to recover signature encryption key");
  assert_eq!(&encryption_key, &recreated_encryption_key);
}

#[test]
fn ed25519() {
  let _ = env_logger::builder().is_test(true).try_init();

  let signing_key = ed25519::random_scalar();
  let pub_signing_key = &signing_key * &ED25519_BASEPOINT_TABLE;
  let encryption_key = ed25519::random_scalar();
  let pub_encryption_key = &encryption_key * &ED25519_BASEPOINT_TABLE;
  let message: [u8; 32] = sha2::Sha256::digest(b"hello world").into();

  let enc_sig = ed25519::encrypted_sign::<Blake2b>(&signing_key, &pub_encryption_key, &message)
    .expect("Failed to create encrypted signature");
  ed25519::encrypted_verify::<Blake2b>(&pub_signing_key, &pub_encryption_key, &enc_sig, &message)
    .expect("Failed to verify encrypted signature");
  let dec_sig = ed25519::decrypt_signature(&enc_sig, &encryption_key)
    .expect("Failed to decrypt signature");

  // Reuse encrypted verification with a zero encryption key to verify the decrypted signature
  ed25519::encrypted_verify::<Blake2b>(&pub_signing_key, &curve25519_dalek::traits::Identity::identity(), &dec_sig, &message).unwrap();

  let recreated_encryption_key = ed25519::recover_key(&pub_encryption_key, &enc_sig, &dec_sig)
    .expect("Failed to recover signature encryption key");
  assert_eq!(&encryption_key, &recreated_encryption_key);
}
