use digest::Digest;
use bitcoin::secp256k1::{self, Secp256k1};

use crate::{
  crypt_engines::{
    CryptEngine,
    ed25519_engine::Ed25519Sha, secp256k1_engine::Secp256k1Engine
  }
};

fn test_crypt_engine_ves<
  Engine: CryptEngine,
  F
>(verify_signature: F) where F: Fn(
  &Engine::Signature,
  &Engine::PublicKey, &[u8]
) -> anyhow::Result<()> {
  let signing_key = Engine::new_private_key();
  let pub_signing_key = Engine::to_public_key(&signing_key);
  let encryption_key = Engine::new_private_key();
  let pub_encryption_key = Engine::to_public_key(&encryption_key);
  let message: [u8; 32] = sha2::Sha256::digest(b"hello world").into();
  let enc_sig = Engine::encrypted_sign(&signing_key, &pub_encryption_key, &message)
    .expect("Failed to create encrypted signature");
  Engine::encrypted_verify(&pub_signing_key, &pub_encryption_key, &enc_sig, &message)
    .expect("Failed to verify encrypted signature");
  let dec_sig = Engine::decrypt_signature(&enc_sig, &encryption_key)
    .expect("Failed to decrypt signature");
  verify_signature(&dec_sig, &pub_signing_key, &message)
    .expect("Failed to verify decrypted signature");
  let recreated_encryption_key = Engine::recover_key(&pub_encryption_key, &enc_sig, &dec_sig)
    .expect("Failed to recover signature encryption key");
  assert_eq!(hex::encode(Engine::private_key_to_bytes(&encryption_key)), hex::encode(Engine::private_key_to_bytes(&recreated_encryption_key)));
}

#[test]
fn ed25519() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_crypt_engine_ves::<Ed25519Sha, _>(|sig, pubkey, message| {
    // Reuse encrypted verification with a zero encryption key to verify the decrypted signature
    Ed25519Sha::encrypted_verify(pubkey, &curve25519_dalek::traits::Identity::identity(), &sig, message)
  });
}

#[test]
fn secp256k1() {
  let _ = env_logger::builder().is_test(true).try_init();
  lazy_static::lazy_static! {
    pub static ref SECP: Secp256k1<secp256k1::All> = Secp256k1::new();
  }

  test_crypt_engine_ves::<Secp256k1Engine, _>(|sig, pubkey, message| {
    let sig_bytes = Secp256k1Engine::signature_to_bytes(sig);
    let pubkey_bytes = Secp256k1Engine::public_key_to_bytes(pubkey);
    let no_fun_message = secp256k1::Message::from_slice(message)?;
    let no_fun_sig = secp256k1::Signature::from_compact(&sig_bytes)?;
    let no_fun_pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes)?;
    SECP.verify(&no_fun_message, &no_fun_sig, &no_fun_pubkey)?;
    Ok(())
  });
}
