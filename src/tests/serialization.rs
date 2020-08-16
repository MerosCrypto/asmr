use digest::Digest;
use sha2::{Sha256, Sha512};

use crate::crypt_engines::{
  CryptEngine,
  ed25519_engine::Ed25519Engine, secp256k1_engine::Secp256k1Engine
};

fn test_serialize_deserialize<Engine: CryptEngine>() {
  let private_key = Engine::new_private_key();
  let private_key_bytes = Engine::private_key_to_bytes(&private_key);
  assert!(Engine::bytes_to_private_key(private_key_bytes).unwrap() == private_key);
  let public_key = Engine::to_public_key(&private_key);
  let public_key_bytes = Engine::public_key_to_bytes(&public_key);
  assert!(Engine::bytes_to_public_key(&public_key_bytes).unwrap() == public_key);
  let message: [u8; 32] = Sha256::digest(b"hello world").into();
  let encryption_private_key = Engine::new_private_key();
  let encryption_public_key = Engine::to_public_key(&encryption_private_key);
  let enc_signature = Engine::encrypted_sign(&private_key, &encryption_public_key, &message).unwrap();
  let enc_signature_bytes = Engine::encrypted_signature_to_bytes(&enc_signature);
  assert!(Engine::bytes_to_encrypted_signature(&enc_signature_bytes).unwrap() == enc_signature);
  let dec_signature = Engine::decrypt_signature(&enc_signature, &encryption_private_key).unwrap();
  let dec_signature_bytes = Engine::signature_to_bytes(&dec_signature);
  assert!(Engine::bytes_to_signature(&dec_signature_bytes).unwrap() == dec_signature);
}

#[test]
fn ed25519() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_serialize_deserialize::<Ed25519Engine<Sha512>>();
}

#[test]
fn secp256k1() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_serialize_deserialize::<Secp256k1Engine>();
}
