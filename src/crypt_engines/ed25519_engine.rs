use std::marker::PhantomData;

use lazy_static::lazy_static;
use hex_literal::hex;

use log::{debug, trace};

use rand::rngs::OsRng;
use digest::{Digest, generic_array::typenum::U64};

use curve25519_dalek::{
  constants::{ED25519_BASEPOINT_TABLE, ED25519_BASEPOINT_POINT},
  traits::Identity,
  scalar::Scalar,
  edwards::{EdwardsPoint, CompressedEdwardsY}
};

use serde::{Serialize, Deserialize};

use crate::{
  crypt_engines::{Commitment, CryptEngine},
  dl_eq::SHARED_KEY_BITS
};

lazy_static! {
  // Taken from Monero: https://github.com/monero-project/monero/blob/9414194b1e47730843e4dbbd4214bf72d3540cf9/src/ringct/rctTypes.h#L454
  static ref ALT_BASEPOINT: EdwardsPoint = {
    CompressedEdwardsY(hex!("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")).decompress().unwrap()
  };
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[allow(non_snake_case)]
pub struct Signature {
  R: EdwardsPoint,
  s: Scalar,
}

pub struct Ed25519Engine<D: Digest<OutputSize = U64>> {
  _phantom: PhantomData<D>,
}
pub type Ed25519Sha = Ed25519Engine<sha2::Sha512>;
pub type Ed25519Blake2b = Ed25519Engine<blake2::Blake2b>;

impl<D: Digest<OutputSize = U64>> CryptEngine for Ed25519Engine<D> {
  type PrivateKey = Scalar;
  type PublicKey = EdwardsPoint;
  type Signature = Signature;
  type EncryptedSignature = Signature;

  fn new_private_key() -> Self::PrivateKey {
    Scalar::random(&mut OsRng)
  }
  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
    key * &ED25519_BASEPOINT_TABLE
  }

  fn bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    Ok(Scalar::from_bytes_mod_order(bytes))
  }
  fn bytes_to_public_key(bytes: &[u8]) -> anyhow::Result<Self::PublicKey> {
    Ok(bincode::deserialize(bytes)?)
  }
  fn bytes_to_signature(bytes: &[u8]) -> anyhow::Result<Self::Signature> {
    if bytes.len() != 64 {
      anyhow::bail!("Expected ed25519 signature to be 64 bytes long");
    }
    let mut scalar_bytes = [0; 32];
    scalar_bytes.copy_from_slice(&bytes[32..]);
    #[allow(non_snake_case)]
    let R = CompressedEdwardsY::from_slice(&bytes[..32]).decompress().ok_or(anyhow::anyhow!("Invalid point in signature specified"))?;
    Ok(Signature {
      s: Scalar::from_bytes_mod_order(scalar_bytes),
      R: R
    })
  }
  fn bytes_to_encrypted_signature(bytes: &[u8]) -> anyhow::Result<Self::EncryptedSignature> {
    Ok(bincode::deserialize(bytes)?)
  }
  fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    Self::bytes_to_private_key(bytes)
  }

  fn dl_eq_generate_commitments(key: [u8; 32]) -> anyhow::Result<Vec<Commitment<Self>>> {
    let mut commitments = Vec::new();
    let mut blinding_key_total = Scalar::zero();
    let mut power_of_two = Scalar::one();
    let two = Scalar::from(2u8);
    for i in 0..SHARED_KEY_BITS {
      let blinding_key = if i == SHARED_KEY_BITS - 1 {
        -blinding_key_total * power_of_two.invert()
      } else {
        Scalar::random(&mut OsRng)
      };
      blinding_key_total += blinding_key * power_of_two;
      power_of_two *= two;
      let commitment_base = blinding_key * *ALT_BASEPOINT;
      let (commitment, commitment_minus_one) = if (key[i/8] >> (i % 8)) & 1 == 1 {
        (&commitment_base + &ED25519_BASEPOINT_POINT, commitment_base)
      } else {
        (commitment_base, &commitment_base - &ED25519_BASEPOINT_POINT)
      };
      commitments.push(Commitment {
        blinding_key,
        commitment_minus_one,
        commitment,
      });
    }
    debug_assert_eq!(blinding_key_total, Scalar::zero());
    let pubkey = &Scalar::from_bytes_mod_order(key) * &ED25519_BASEPOINT_TABLE;
    debug_assert_eq!(
      &Self::dl_eq_reconstruct_key(commitments.iter().map(|c| &c.commitment))?,
      &pubkey
    );
    debug!("Generated dleq proof for ed25519 pubkey {}", hex::encode(pubkey.compress().as_bytes()));
    Ok(commitments)
  }
  fn dl_eq_compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey> {
    Ok(nonce + Scalar::from_bytes_mod_order(challenge) * key)
  }
  fn dl_eq_compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(s_value * *ALT_BASEPOINT - Scalar::from_bytes_mod_order(challenge) * key)
  }
  fn dl_eq_commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(commitment - ED25519_BASEPOINT_POINT)
  }
  fn dl_eq_reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey> {
    let mut power_of_two = Scalar::one();
    let mut res = EdwardsPoint::identity();
    let two = Scalar::from(2u8);
    for comm in commitments {
      res += comm * power_of_two;
      power_of_two *= two;
    }
    Ok(res)
  }
  fn dl_eq_blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey> {
    Ok(key * *ALT_BASEPOINT)
  }

  fn private_key_to_bytes(key: &Self::PrivateKey) -> [u8; 32] {
    key.to_bytes()
  }
  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
    bincode::serialize(key).expect("Failed to serialize public key")
  }
  fn signature_to_bytes(sig: &Self::Signature) -> Vec<u8> {
    let mut bytes = sig.R.compress().to_bytes().to_vec();
    bytes.extend(&sig.s.to_bytes());
    bytes
  }
  fn encrypted_signature_to_bytes(sig: &Self::EncryptedSignature) -> Vec<u8> {
    bincode::serialize(sig).expect("Failed to serialize encrypted signature")
  }
  fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32] {
    key.to_bytes()
  }

  fn encrypted_sign(
    signing_key: &Self::PrivateKey,
    encryption_key: &Self::PublicKey,
    message: &[u8]
  ) -> anyhow::Result<Self::EncryptedSignature> {
    let nonce = Scalar::random(&mut OsRng);
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
      hex::encode(Self::encrypted_signature_to_bytes(&sig))
    );
    Ok(sig)
  }
  fn encrypted_verify(
    signing_key: &Self::PublicKey,
    encryption_key: &Self::PublicKey,
    ciphertext: &Self::EncryptedSignature,
    message: &[u8]
  ) -> anyhow::Result<()> {
    trace!(
      "Verifying encrypted signature for signing key {}, encryption key {}, and message {}: {}",
      hex::encode(signing_key.compress().as_bytes()),
      hex::encode(encryption_key.compress().as_bytes()),
      hex::encode(message),
      hex::encode(Self::encrypted_signature_to_bytes(&ciphertext))
    );
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
  fn decrypt_signature(sig: &Self::EncryptedSignature, key: &Self::PrivateKey) -> anyhow::Result<Self::Signature> {
    // update s and R to match challenge_nonce
    let sig = Signature {
      s: sig.s + key,
      R: sig.R + key * &ED25519_BASEPOINT_TABLE,
    };
    trace!(
      "Decrypting signature with encryption pubkey {}: {} -> {}",
      hex::encode((key * &ED25519_BASEPOINT_TABLE).compress().as_bytes()),
      hex::encode(Self::encrypted_signature_to_bytes(&sig)),
      hex::encode(Self::signature_to_bytes(&sig))
    );
    Ok(sig)
  }
  fn recover_key(expected_key: &Self::PublicKey, ciphertext: &Self::EncryptedSignature, sig: &Self::Signature) -> anyhow::Result<Self::PrivateKey> {
    trace!(
      "Recovering encryption key {} from encrypted signature {} , decrypted signature {}",
      hex::encode(expected_key.compress().as_bytes()),
      hex::encode(Self::encrypted_signature_to_bytes(&ciphertext)),
      hex::encode(Self::signature_to_bytes(&sig))
    );
    if &(sig.R - ciphertext.R) != expected_key {
      anyhow::bail!("Attempted to recover key with separate signatures, invalid signatures, or the wrong expected key");
    }
    let key = sig.s - ciphertext.s;
    if &(&key * &ED25519_BASEPOINT_TABLE) != expected_key {
      anyhow::bail!("Recovered VES key didn't match expected key");
    }
    Ok(key)
  }
}

impl<D: Digest<OutputSize = U64>> Ed25519Engine<D> {
  #[allow(non_snake_case)]
  pub fn sign(key: &Scalar, message: &[u8]) -> Signature {
    let r = Scalar::random(&mut OsRng);
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
    Signature {
      R,
      s,
    }
  }
}
