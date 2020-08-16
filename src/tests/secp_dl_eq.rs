use rand::rngs::OsRng;
use secp256kfun::{marker::*, Scalar, G, g};

use crate::crypt_engines::secp256k1_engine::SecpDleqProof;

#[test]
fn test_secp_dl_eq() {
  let _ = env_logger::builder().is_test(true).try_init();
  let key = Scalar::random(&mut OsRng);
  let other_base_scalar = Scalar::random(&mut OsRng);
  let other_base = g!(other_base_scalar * G).mark::<Normal>();
  let proof = SecpDleqProof::new(&key, &other_base);
  let key1 = g!(key * G).mark::<Normal>();
  let key2 = g!(key * other_base).mark::<Normal>();
  proof.verify(&key1, &other_base, &key2)
    .expect("Failed to verify secp dleq proof");
}
