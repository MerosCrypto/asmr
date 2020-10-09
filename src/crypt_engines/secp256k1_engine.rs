use std::convert::TryInto;

use lazy_static::lazy_static;
use hex_literal::hex;

use log::{debug, trace};

use rand::rngs::OsRng;
use digest::Digest;
use sha2::Sha256;

use secp256kfun::{marker::*, Scalar, Point, G, g, s};

use serde::{Serialize, Deserialize};

use crate::{
  crypt_engines::{Commitment, CryptEngine},
  dl_eq::SHARED_KEY_BITS
};

lazy_static! {
  // Taken from Grin: https://github.com/mimblewimble/rust-secp256k1-zkp/blob/ed4297b0e3dba9b0793aab340c7c81cda6460bcf/src/constants.rs#L97
  static ref ALT_BASEPOINT: Point = {
    Point::from_bytes(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"))
      .expect("Alternate basepoint is invalid")
  };
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct SecpDleqProof {
  s: Scalar,
  c: Scalar,
}

impl SecpDleqProof {
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
    let SecpDleqProof { s, c } = self;
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

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct SecpSignature {
  r: [u8; 32],
  s: Scalar::<Public, Zero>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[allow(non_snake_case)]
pub struct SecpEncryptedSignature {
  R: Point,
  R_offset: Point,
  s_offset: Scalar::<Public>,
  dleq_proof: SecpDleqProof,
}

pub struct Secp256k1Engine;
impl CryptEngine for Secp256k1Engine {
  type PrivateKey = Scalar;
  type PublicKey = Point;
  type Signature = SecpSignature;
  type EncryptedSignature = SecpEncryptedSignature;

  fn new_private_key() -> Self::PrivateKey {
    Scalar::random(&mut OsRng)
  }
  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
    g!(key * G).mark::<Normal>()
  }

  fn bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    Scalar::from_bytes_mod_order(bytes).mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Private key is 0"))
  }
  fn bytes_to_public_key(bytes: &[u8]) -> anyhow::Result<Self::PublicKey> {
    Ok(bincode::deserialize(bytes)?)
  }
  fn bytes_to_signature(bytes: &[u8]) -> anyhow::Result<Self::Signature> {
    if bytes.len() != 64 {
      anyhow::bail!("Expected secp256k1 signature to be 64 bytes long");
    }
    let mut r = [0; 32];
    let mut s = [0; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    Ok(SecpSignature {
      r,
      s: Scalar::from_bytes(s).ok_or_else(|| anyhow::anyhow!("Invalid s scalar"))?.mark::<Public>(),
    })
  }
  #[allow(non_snake_case)]
  fn bytes_to_encrypted_signature(bytes: &[u8]) -> anyhow::Result<Self::EncryptedSignature> {
    Ok(bincode::deserialize(bytes)?)
  }
  fn little_endian_bytes_to_private_key(mut bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    bytes.reverse();
    Self::bytes_to_private_key(bytes)
  }

  fn dl_eq_generate_commitments(key: [u8; 32]) -> anyhow::Result<Vec<Commitment<Self>>> {
    let mut commitments = Vec::new();
    let mut blinding_key_total = Scalar::zero();
    let mut power_of_two = Scalar::one();
    let two = Scalar::from(2);
    for i in 0..SHARED_KEY_BITS {
      let blinding_key = if i == SHARED_KEY_BITS - 1 {
        let inv_power_of_two = power_of_two.invert();
        s!(-blinding_key_total * inv_power_of_two).mark::<NonZero>()
          .expect("Blinding key total before final is zero")
      } else {
        Scalar::random(&mut OsRng)
      };
      blinding_key_total = s!(blinding_key_total + blinding_key * power_of_two);
      power_of_two = s!(power_of_two * two).mark::<NonZero>().expect("Power of two is zero");
      let commitment_base = g!(blinding_key * ALT_BASEPOINT);
      let normalize_point = |point: Point<Jacobian, Public, Zero>| {
        point.mark::<Normal>().mark::<NonZero>().expect("Generated zero commitment")
      };
      let (commitment, commitment_minus_one) = if (key[i/8] >> (i % 8)) & 1 == 1 {
        (normalize_point(g!(commitment_base + G)), commitment_base.mark::<Normal>())
      } else {
        let minus_one = normalize_point(g!(commitment_base - G));
        (commitment_base.mark::<Normal>(), minus_one)
      };
      commitments.push(Commitment {
        blinding_key,
        commitment_minus_one,
        commitment,
      });
    }
    debug_assert!(blinding_key_total.is_zero());
    let decoded_key = Self::little_endian_bytes_to_private_key(key)?;
    let pubkey = g!(decoded_key * G).mark::<Normal>();
    debug_assert_eq!(
      &Self::dl_eq_reconstruct_key(commitments.iter().map(|c| &c.commitment))?,
      &pubkey
    );
    debug!("Generated dleq proof for secp256k1 pubkey {}", hex::encode(pubkey.to_bytes()));
    Ok(commitments)
  }
  fn dl_eq_compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey> {
    let challenge = Scalar::from_bytes_mod_order(challenge);
    Ok(s!(nonce + challenge * key).mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Generated zero s value"))?)
  }
  fn dl_eq_compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    let challenge = Scalar::from_bytes_mod_order(challenge);
    Ok(
      g!(s_value * ALT_BASEPOINT - challenge * key)
        .mark::<Normal>()
        .mark::<NonZero>()
        .ok_or_else(|| anyhow::anyhow!("Generated zero R value"))?
    )
  }
  fn dl_eq_commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(g!(commitment - G).mark::<Normal>().mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Generated zero commitment"))?)
  }
  fn dl_eq_reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey> {
    let mut power_of_two = Scalar::one();
    let mut res = Point::zero().mark::<Jacobian>();
    let two = Scalar::from(2);
    for comm in commitments {
      res = g!(res + power_of_two * comm);
      power_of_two = s!(power_of_two * two).mark::<NonZero>().expect("Generated zero power of two");
    }
    res.mark::<Normal>().mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Reconstructed zero key"))
  }
  fn dl_eq_blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey> {
    Ok(g!(key * ALT_BASEPOINT).mark::<Normal>())
  }

  fn private_key_to_bytes(key: &Self::PrivateKey) -> [u8; 32] {
    key.to_bytes()
  }
  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
    key.to_bytes().to_vec()
  }
  fn signature_to_bytes(sig: &Self::Signature) -> Vec<u8> {
    let mut result = sig.r.to_vec();
    result.extend(&sig.s.to_bytes());
    result
  }
  fn encrypted_signature_to_bytes(sig: &Self::EncryptedSignature) -> Vec<u8> {
    bincode::serialize(sig).expect("Failed to serialize encrypted signature")
  }
  fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32] {
    let mut bytes = key.to_bytes();
    bytes.reverse(); // secp is big endian
    bytes
  }

  #[allow(non_snake_case)]
  fn sign(secret_key: &Self::PrivateKey, message: &[u8]) -> anyhow::Result<Self::Signature> {
    let message: [u8; 32] = message
      .try_into()
      .map_err(|_| anyhow::anyhow!("ECDSA signatures must be of a 32 byte message hash"))?;
    let m = Scalar::from_bytes_mod_order(message).mark::<Public>();
    let r = Scalar::random(&mut OsRng);
    let R = g!(r * G).mark::<Normal>();
    let R_x = Scalar::from_bytes_mod_order(R.to_xonly().into_bytes())
      .mark::<(Public, NonZero)>()
      .ok_or_else(|| anyhow::anyhow!("Generated zero R value"))?;
    let mut s = s!({ r.invert() } * (m + R_x * secret_key)).mark::<Public>();
    s.conditional_negate(s.is_high());
    Ok(SecpSignature {
      r: R_x.to_bytes(),
      s,
    })
  }
  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> anyhow::Result<()> {
    let message: [u8; 32] = message
      .try_into()
      .map_err(|_| anyhow::anyhow!("ECDSA signatures must be of a 32 byte message hash"))?;
    let m = Scalar::from_bytes_mod_order(message).mark::<Public>();
    let s_inv = signature
      .s
      .clone()
      .mark::<NonZero>()
      .ok_or_else(|| anyhow::anyhow!("Signature has zero s value"))?
      .invert();
    let r = Scalar::from_bytes(signature.r)
      .and_then(|s| s.mark::<Public>().mark::<NonZero>())
      .ok_or_else(|| anyhow::anyhow!("Signature has invalid r value"))?;

    let computed_r = g!((s_inv * m) * G + (s_inv * r) * public_key)
      .mark::<NonZero>()
      .ok_or_else(|| anyhow::anyhow!("Signature resulted in zero R value"))?;
    if computed_r.x_eq_scalar(&r) {
      Ok(())
    } else {
      Err(anyhow::anyhow!("Bad signature"))
    }
  }

  #[allow(non_snake_case)]
  fn encrypted_sign(
    signing_key: &Self::PrivateKey,
    encryption_key: &Self::PublicKey,
    message: &[u8]
  ) -> anyhow::Result<Self::EncryptedSignature> {
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
    let dleq_proof = SecpDleqProof::new(&r, &encryption_key);
    let R_x = Scalar::from_bytes_mod_order(R.coordinates().0);
    let r_inverse = r.invert();
    let s_offset = s!(r_inverse * (message + R_x * signing_key));
    let s_offset = s_offset.mark::<Public>().mark::<NonZero>()
      .ok_or_else(|| anyhow::anyhow!("Generated zero s value"))?;
    let sig = SecpEncryptedSignature {
      R,
      R_offset: R_offset.mark::<Normal>(),
      s_offset,
      dleq_proof,
    };
    trace!(
      "Generated ed25519 encrypted signature for signing key {}, encryption key {}, and message {}: {}",
      hex::encode(g!(signing_key * G).mark::<Normal>().to_bytes()),
      hex::encode(encryption_key.to_bytes()),
      hex::encode(message_bytes),
      hex::encode(Self::encrypted_signature_to_bytes(&sig))
    );
    Ok(sig)
  }
  #[allow(non_snake_case)]
  fn encrypted_verify(
    signing_key: &Self::PublicKey,
    encryption_key: &Self::PublicKey,
    ciphertext: &Self::EncryptedSignature,
    message: &[u8]
  ) -> anyhow::Result<()> {
    trace!(
      "Verifying encrypted signature for signing key {}, encryption key {}, and message {}: {}",
      hex::encode(signing_key.to_bytes()),
      hex::encode(encryption_key.to_bytes()),
      hex::encode(message),
      hex::encode(Self::encrypted_signature_to_bytes(&ciphertext))
    );
    if message.len() != 32 {
      anyhow::bail!("Expected message for encrypted_verify to be 32 byte hash");
    }
    let mut message_bytes = [0u8; 32];
    message_bytes.copy_from_slice(message);
    let message = Scalar::from_bytes_mod_order(message_bytes)
      .mark::<NonZero>().ok_or_else(|| anyhow::anyhow!("Cannot verify signature of zero message"))?;
    let SecpEncryptedSignature { R, R_offset, s_offset, dleq_proof } = ciphertext;
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
  fn decrypt_signature(enc_sig: &Self::EncryptedSignature, key: &Self::PrivateKey) -> anyhow::Result<Self::Signature> {
    let key_inverse = key.invert();
    let mut s = s!(enc_sig.s_offset * key_inverse).mark::<Public>();
    s.conditional_negate(s.is_high());
    let sig = SecpSignature {
      r: enc_sig.R.coordinates().0,
      s: s.mark::<Zero>(),
    };
    trace!(
      "Decrypting signature with encryption pubkey {}: {} -> {}",
      hex::encode(g!(key * G).mark::<Normal>().to_bytes()),
      hex::encode(Self::encrypted_signature_to_bytes(&enc_sig)),
      hex::encode(Self::signature_to_bytes(&sig))
    );
    Ok(sig)
  }
  fn recover_key(encryption_key: &Self::PublicKey, ciphertext: &Self::EncryptedSignature, sig: &Self::Signature) -> anyhow::Result<Self::PrivateKey> {
    trace!(
      "Recovering encryption key {} from encrypted signature {} , decrypted signature {}",
      hex::encode(encryption_key.to_bytes()),
      hex::encode(Self::encrypted_signature_to_bytes(&ciphertext)),
      hex::encode(Self::signature_to_bytes(&sig))
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
}
