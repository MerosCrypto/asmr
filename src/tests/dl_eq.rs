use crate::{
  crypt_engines::CryptEngine,
  crypt_engines::{
    ed25519_engine::Ed25519Sha,
    secp256k1_engine::Secp256k1Engine,
    jubjub_engine::JubjubEngine
  },
  dl_eq::DlEqProof
};

fn test_dl_eq_with_engines<EngineA: CryptEngine, EngineB: CryptEngine>() {
  let _ = env_logger::builder().is_test(true).try_init();
  let (proof, skey_a, skey_b) = DlEqProof::<EngineA, EngineB>::new();
  let (pkey_a, pkey_b) = proof.verify().expect("DlEq proof verification failed");
  assert_eq!(hex::encode(EngineA::public_key_to_bytes(&pkey_a)), hex::encode(EngineA::public_key_to_bytes(&EngineA::to_public_key(&skey_a))));
  assert_eq!(hex::encode(EngineB::public_key_to_bytes(&pkey_b)), hex::encode(EngineB::public_key_to_bytes(&EngineB::to_public_key(&skey_b))));
}

#[test]
fn dl_eq_ed25519_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_dl_eq_with_engines::<Ed25519Sha, Ed25519Sha>();
}

#[test]
fn dl_eq_secp256k1_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_dl_eq_with_engines::<Secp256k1Engine, Secp256k1Engine>();
}

#[test]
fn dl_eq_jubjub_with_self() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_dl_eq_with_engines::<JubjubEngine, JubjubEngine>();
}

#[test]
fn dl_eq_secp256k1_with_ed25519() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_dl_eq_with_engines::<Secp256k1Engine, Ed25519Sha>();
  test_dl_eq_with_engines::<Ed25519Sha, Secp256k1Engine>();
}

#[test]
fn dl_eq_secp256k1_with_jubjub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_dl_eq_with_engines::<Secp256k1Engine, JubjubEngine>();
  test_dl_eq_with_engines::<JubjubEngine, Secp256k1Engine>();
}

#[test]
fn dl_eq_ed25519_with_jubjub() {
  let _ = env_logger::builder().is_test(true).try_init();
  test_dl_eq_with_engines::<Ed25519Sha, JubjubEngine>();
  test_dl_eq_with_engines::<JubjubEngine, Ed25519Sha>();
}

#[test]
fn test_max_key_wrapping() {
  let _ = env_logger::builder().is_test(true).try_init();
  let mut key = [0xffu8; 32];
  assert_eq!(crate::dl_eq::SHARED_KEY_BITS, 251); // Change the following line if this changes
  key[31] = 0b0000_0111;
  let mut key_rev = key;
  key_rev.reverse();
  assert_eq!(Ed25519Sha::private_key_to_bytes(&Ed25519Sha::little_endian_bytes_to_private_key(key).unwrap()), key);
  assert_eq!(Secp256k1Engine::private_key_to_bytes(&Secp256k1Engine::little_endian_bytes_to_private_key(key).unwrap()), key_rev);
  assert_eq!(JubjubEngine::private_key_to_bytes(&JubjubEngine::little_endian_bytes_to_private_key(key).unwrap()), key);
}
