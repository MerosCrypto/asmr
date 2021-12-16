use lazy_static::lazy_static;
use hex_literal::hex;

#[cfg(test)]
use log::{trace, warn};

use rand::{RngCore, rngs::OsRng};
use digest::{Digest, generic_array::typenum::U64};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  edwards::{EdwardsPoint, CompressedEdwardsY}
};

lazy_static! {
  // Taken from Monero: https://github.com/monero-project/monero/blob/9414194b1e47730843e4dbbd4214bf72d3540cf9/src/ringct/rctTypes.h#L454
  static ref ALT_BASEPOINT: EdwardsPoint = {
    CompressedEdwardsY(hex!("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")).decompress().unwrap()
  };
}

#[derive(Clone, PartialEq)]
#[allow(non_snake_case)]
pub struct Signature {
  R: EdwardsPoint,
  s: Scalar
}

impl Signature {
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = self.R.compress().to_bytes().to_vec();
    res.extend(self.s.to_bytes());
    res.to_vec()
  }
}

pub fn random_scalar() -> Scalar {
  let mut r = [0; 64];
  OsRng.fill_bytes(&mut r);
  Scalar::from_bytes_mod_order_wide(&r)
}

#[allow(non_snake_case)]
pub fn sign<D: Digest<OutputSize = U64>>(key: &Scalar, message: &[u8]) -> Signature {
  let r = random_scalar();
  let R = &r * &ED25519_BASEPOINT_TABLE;
  let A = key * &ED25519_BASEPOINT_TABLE;
  let mut hram = [0u8; 64];
  let hash = D::new()
    .chain(&R.compress().as_bytes())
    .chain(&A.compress().as_bytes())
    .chain(message)
    .finalize();
  hram.copy_from_slice(&hash);
  let c = Scalar::from_bytes_mod_order_wide(&hram);
  let s = r + c * key;
  Signature { R, s }
}

// Only cfg test until someone uses these in a coin
#[cfg(test)]
pub fn encrypted_sign<D: Digest<OutputSize = U64>>(
  signing_key: &Scalar,
  encryption_key: &EdwardsPoint,
  message: &[u8]
) -> anyhow::Result<Signature> {
  let nonce = random_scalar();
  let pub_nonce = &nonce * &ED25519_BASEPOINT_TABLE;
  let challenge_nonce = &pub_nonce + encryption_key;
  let pub_signing_key = signing_key * &ED25519_BASEPOINT_TABLE;
  let mut hram = [0u8; 64];
  let hash = D::new()
    .chain(challenge_nonce.compress().as_bytes())
    .chain(pub_signing_key.compress().as_bytes())
    .chain(message)
    .finalize();
  hram.copy_from_slice(&hash);
  let challenge = Scalar::from_bytes_mod_order_wide(&hram);
  let sig = Signature {
    s: nonce + challenge * signing_key,
    R: pub_nonce,
  };
  trace!(
    "Generated ed25519 encrypted signature for signing key {}, encryption key {}, and message {}: {}",
    hex::encode(pub_signing_key.compress().as_bytes()),
    hex::encode(encryption_key.compress().as_bytes()),
    hex::encode(message),
    hex::encode(&sig.serialize())
  );
  Ok(sig)
}

#[cfg(test)]
pub fn encrypted_verify<D: Digest<OutputSize = U64>>(
  signing_key: &EdwardsPoint,
  encryption_key: &EdwardsPoint,
  ciphertext: &Signature,
  message: &[u8]
) -> anyhow::Result<()> {
  trace!(
    "Verifying encrypted signature for signing key {}, encryption key {}, and message {}: {}",
    hex::encode(signing_key.compress().as_bytes()),
    hex::encode(encryption_key.compress().as_bytes()),
    hex::encode(message),
    hex::encode(&ciphertext.serialize())
  );
  if !signing_key.is_torsion_free() ||
    !encryption_key.is_torsion_free() ||
    !ciphertext.R.is_torsion_free()
  {
    anyhow::bail!("Encrypted signature point(s) have torsion");
  }
  let challenge_nonce = &ciphertext.R + encryption_key;
  let mut hram = [0u8; 64];
  let hash = D::new()
    .chain(challenge_nonce.compress().as_bytes())
    .chain(signing_key.compress().as_bytes())
    .chain(message)
    .finalize();
  hram.copy_from_slice(&hash);
  let challenge = Scalar::from_bytes_mod_order_wide(&hram);
  #[allow(non_snake_case)]
  let expected_sB = ciphertext.R + challenge * signing_key;
  if expected_sB != &ciphertext.s * &ED25519_BASEPOINT_TABLE {
    anyhow::bail!("Invalid encrypted signature");
  }
  Ok(())
}

#[cfg(test)]
pub fn decrypt_signature(sig: &Signature, key: &Scalar) -> anyhow::Result<Signature> {
  // update s and R to match challenge_nonce
  let sig = Signature {
    s: sig.s + key,
    R: sig.R + key * &ED25519_BASEPOINT_TABLE,
  };
  trace!(
    "Decrypting signature with encryption pubkey {}: {} -> {}",
    hex::encode((key * &ED25519_BASEPOINT_TABLE).compress().as_bytes()),
    hex::encode(&sig.serialize()),
    hex::encode(&sig.serialize())
  );
  Ok(sig)
}

#[cfg(test)]
pub fn recover_key(expected_key: &EdwardsPoint, ciphertext: &Signature, sig: &Signature) -> anyhow::Result<Scalar> {
  trace!(
    "Recovering encryption key {} from encrypted signature {} , decrypted signature {}",
    hex::encode(expected_key.compress().as_bytes()),
    hex::encode(&ciphertext.serialize()),
    hex::encode(&sig.serialize())
  );
  if &(sig.R - ciphertext.R) != expected_key {
    if sig.R.is_torsion_free() {
      warn!("Attempting to recover key from signatures without matching R values. This will likely fail.");
    } else {
      // TODO confirm that key recovery works as expected with torsion
      warn!("Torsion present in published signature. An adversary may be present.");
    }
  }
  let key = sig.s - ciphertext.s;
  if &(&key * &ED25519_BASEPOINT_TABLE) != expected_key {
    anyhow::bail!("Recovered VES key didn't match expected key");
  }
  Ok(key)
}
