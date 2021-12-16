use digest::Digest;
use sha2::Sha256;

use rand::rngs::OsRng;

use secp256kfun::{marker::*, Scalar, g, G};

use crate::crypto::secp256k1;

#[test]
fn secp256k1_encrypted_signature_serialization() {
  let _ = env_logger::builder().is_test(true).try_init();

  let encryption_private_key = Scalar::random(&mut OsRng);
  let encryption_public_key = g!(encryption_private_key * G).mark::<Normal>();
  let message: [u8; 32] = Sha256::digest(b"hello world").into();
  let enc_sig = secp256k1::encrypted_sign(&encryption_private_key, &encryption_public_key, &message).unwrap();
  assert_eq!(secp256k1::EncryptedSignature::deserialize(&enc_sig.serialize()).unwrap(), enc_sig);
}
