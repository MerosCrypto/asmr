use crate::crypt_engines::{CryptEngine, jubjub_engine::JubjubEngine};

#[test]
fn test_jubjub_signature() {
  let _ = env_logger::builder().is_test(true).try_init();
  let key = JubjubEngine::new_private_key();
  let sig = JubjubEngine::sign(&key, &vec![1]).expect("Couldn't call send");
  JubjubEngine::verify_signature(&JubjubEngine::to_public_key(&key), &vec![1], &sig).expect("Signature verification failed");
}
