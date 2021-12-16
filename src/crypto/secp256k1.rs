use log::trace;

use rand::rngs::OsRng;
use digest::Digest;
use sha2::Sha256;

use secp256kfun::{marker::*, Scalar, Point, G, g, s};

use serde::{Serialize, Deserialize};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SecpDLEqProof {
  s: Scalar,
  c: Scalar
}

impl SecpDLEqProof {
  #[allow(non_snake_case)]
  pub fn new(key: &Scalar, other_base: &Point) -> Self {
    let r = Scalar::random(&mut OsRng);
    let R1 = g!(r * G);
    let R2 = g!(r * other_base);
    let c: [u8; 32] = Sha256::new()
      .chain(R1.mark::<Normal>().to_bytes())
      .chain(R2.mark::<Normal>().to_bytes())
      .chain(g!(key * G).mark::<Normal>().to_bytes())
      .chain(g!(key * other_base).mark::<Normal>().to_bytes())
      .finalize()
      .into();
    let c = Scalar::from_bytes_mod_order(c);
    let s = s!(r + c * key);
    Self {
      s: s.mark::<NonZero>().expect("Generated zero s value"),
      c: c.mark::<NonZero>().expect("Generated zero c value"),
    }
  }

  #[allow(non_snake_case)]
  pub fn verify(&self, key1: &Point, other_base: &Point, key2: &Point) -> anyhow::Result<()> {
    let SecpDLEqProof { s, c } = self;
    let R1 = g!(s * G - c * key1);
    let R1 = R1.mark::<Normal>().mark::<NonZero>()
      .ok_or_else(|| anyhow::anyhow!("Generated zero R1 while validating secp256k1 dleq proof"))?;
    let R2 = g!(s * other_base - c * key2);
    let R2 = R2.mark::<Normal>().mark::<NonZero>()
      .ok_or_else(|| anyhow::anyhow!("Generated zero R2 while validating secp256k1 dleq proof"))?;
    let expected_c: [u8; 32] = Sha256::new()
      .chain(R1.to_bytes())
      .chain(R2.to_bytes())
      .chain(key1.to_bytes())
      .chain(key2.to_bytes())
      .finalize()
      .into();
    let expected_c = Scalar::from_bytes_mod_order(expected_c);
    if c != &expected_c {
      anyhow::bail!("Secp256k1 dleq proof validation failed");
    }
    Ok(())
  }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Signature {
  r: [u8; 32],
  s: Scalar::<Public, Zero>
}

impl Signature {
  pub fn serialize(&self) -> Vec<u8> {
    let mut result = self.r.to_vec();
    result.extend(&self.s.to_bytes());
    result
  }

  pub fn deserialize(bytes: &[u8]) -> anyhow::Result<Signature> {
    if bytes.len() != 64 {
      anyhow::bail!("Expected secp256k1 signature to be 64 bytes long");
    }
    let mut r = [0; 32];
    let mut s = [0; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    Ok(Signature {
      r,
      s: Scalar::from_bytes(s).ok_or(anyhow::anyhow!("Invalid s scalar"))?.mark::<Public>(),
    })
  }
}

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EncryptedSignature {
  R: Point,
  R_offset: Point,
  s_offset: Scalar::<Public>,
  dleq_proof: SecpDLEqProof
}

impl EncryptedSignature {
  pub fn serialize(&self) -> Vec<u8> {
    bincode::serialize(self).expect("Couldn't serialize an encrypted signature")
  }

  pub fn deserialize(bytes: &[u8]) -> anyhow::Result<EncryptedSignature> {
    bincode::deserialize(bytes).map_err(|_| anyhow::anyhow!("Invalid encrypted signature"))
  }
}

#[allow(non_snake_case)]
pub fn encrypted_sign(
  signing_key: &Scalar,
  encryption_key: &Point,
  message: &[u8]
) -> anyhow::Result<EncryptedSignature> {
  if message.len() != 32 {
    anyhow::bail!("Expected message for encrypted_sign to be 32 byte hash");
  }
  let mut message_bytes = [0u8; 32];
  message_bytes.copy_from_slice(message);
  let message = Scalar::from_bytes_mod_order(message_bytes)
    .mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Cannot sign zero message"))?;
  let r = Scalar::random(&mut OsRng);
  let R = g!(r * encryption_key).mark::<Normal>();
  let R_offset = g!(r * G);
  let dleq_proof = SecpDLEqProof::new(&r, &encryption_key);
  let R_x = Scalar::from_bytes_mod_order(R.coordinates().0);
  let r_inverse = r.invert();
  let s_offset = s!(r_inverse * (message + R_x * signing_key));
  let s_offset = s_offset.mark::<Public>().mark::<NonZero>()
    .ok_or_else(|| anyhow::anyhow!("Generated zero s value"))?;
  let sig = EncryptedSignature {
    R,
    R_offset: R_offset.mark::<Normal>(),
    s_offset,
    dleq_proof
  };
  trace!(
    "Generated ed25519 encrypted signature for signing key {}, encryption key {}, and message {}: {}",
    hex::encode(g!(signing_key * G).mark::<Normal>().to_bytes()),
    hex::encode(encryption_key.to_bytes()),
    hex::encode(message_bytes),
    hex::encode(&sig.serialize())
  );
  Ok(sig)
}

#[allow(non_snake_case)]
pub fn encrypted_verify(
  signing_key: &Point,
  encryption_key: &Point,
  ciphertext: &EncryptedSignature,
  message: &[u8]
) -> anyhow::Result<()> {
  trace!(
    "Verifying encrypted signature for signing key {}, encryption key {}, and message {}: {}",
    hex::encode(signing_key.to_bytes()),
    hex::encode(encryption_key.to_bytes()),
    hex::encode(message),
    hex::encode(&ciphertext.serialize())
  );
  if message.len() != 32 {
    anyhow::bail!("Expected message for encrypted_verify to be 32 byte hash");
  }
  let mut message_bytes = [0u8; 32];
  message_bytes.copy_from_slice(message);
  let message = Scalar::from_bytes_mod_order(message_bytes)
    .mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Cannot verify signature of zero message"))?;
  let EncryptedSignature { R, R_offset, s_offset, dleq_proof } = ciphertext;
  dleq_proof.verify(R_offset, encryption_key, &R)?;
  let R_x = Scalar::from_bytes_mod_order(R.clone().coordinates().0)
    .mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Encrypted signature R had zero x coordinate"))?;
  let s_offset_inverse = s_offset.invert();
  let expected_R_offset = g!(s_offset_inverse * (message * G + R_x * signing_key));
  if &expected_R_offset != R_offset {
    anyhow::bail!("Invalid encrypted signature");
  }
  Ok(())
}

#[allow(non_snake_case)]
pub fn decrypt_signature(enc_sig: &EncryptedSignature, key: &Scalar) -> anyhow::Result<Signature> {
  let key_inverse = key.invert();
  let mut s = s!(enc_sig.s_offset * key_inverse).mark::<Public>();
  s.conditional_negate(s.is_high());
  let sig = Signature {
    r: enc_sig.R.coordinates().0,
    s: s.mark::<Zero>(),
  };
  trace!(
    "Decrypting signature with encryption pubkey {}: {} -> {}",
    hex::encode(g!(key * G).mark::<Normal>().to_bytes()),
    hex::encode(&enc_sig.serialize()),
    hex::encode(&sig.serialize())
  );
  Ok(sig)
}

pub fn recover_key(encryption_key: &Point, ciphertext: &EncryptedSignature, sig: &Signature) -> anyhow::Result<Scalar> {
  trace!(
    "Recovering encryption key {} from encrypted signature {} , decrypted signature {}",
    hex::encode(encryption_key.to_bytes()),
    hex::encode(&ciphertext.serialize()),
    hex::encode(&sig.serialize())
  );
  let s_inverse = sig
    .s
    .clone()
    .mark::<NonZero>()
    .ok_or_else(|| anyhow::anyhow!("Decrypted signature has zero s value"))?
    .invert();
  let s_offset = &ciphertext.s_offset;
  let hopefully_key = s!(s_inverse * s_offset);
  let hopefully_key_pub = g!(hopefully_key * G);
  if &hopefully_key_pub == encryption_key {
    Ok(hopefully_key)
  } else if hopefully_key_pub == -encryption_key {
    Ok(-hopefully_key)
  } else {
    anyhow::bail!("Failed to recover encryption key");
  }
}
