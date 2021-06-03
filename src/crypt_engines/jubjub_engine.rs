use std::{
  convert::TryInto,
  fmt::Debug
};

use rand::{rngs::OsRng};
use digest::Digest;
use serde::{Serialize, Deserialize};

use ff::Field;
use group::{Group, GroupEncoding};
use jubjub::{Fr, SubgroupPoint};
// SKG is used as the primary basepoint, as `ask` is what the atomic secret is, and `ask`'s public key is defined as its product
// JubJub's native generator is used as the alternate basepoint
use zcash_primitives::constants::{SPENDING_KEY_GENERATOR, PROOF_GENERATION_KEY_GENERATOR};

use crate::{
  crypt_engines::{Commitment, CryptEngine},
  dl_eq::SHARED_KEY_BITS
};

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct NonExistant;

// Work around for the lack of Serialize/Deserialize on Fr/SubgroupPoint.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct PrivateKey {
  bytes: [u8; 32]
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct PublicKey {
  bytes: [u8; 32]
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[allow(non_snake_case)]
pub struct Signature {
  R: [u8; 32],
  s: [u8; 32],
}

fn fr_from_bytes_mod(scalar: [u8; 32]) -> Fr {
  let mut wide: [u8; 64] = [0; 64];
  wide[..32].copy_from_slice(&scalar);
  Fr::from_bytes_wide(&wide)
}

pub struct JubjubEngine;

impl JubjubEngine {
  pub fn get_scalar(key: &PrivateKey) -> Fr {
    Fr::from_bytes(&key.bytes).unwrap()
  }

  pub fn get_point(key: &PublicKey) -> SubgroupPoint {
    SubgroupPoint::from_bytes(&key.bytes).unwrap()
  }

  pub fn get_identity_as_bytes() -> [u8; 32] {
    SubgroupPoint::identity().to_bytes()
  }

  pub fn add_private_key(a: &PrivateKey, b: &PrivateKey) -> PrivateKey {
    PrivateKey {
      bytes: (JubjubEngine::get_scalar(a) + JubjubEngine::get_scalar(b)).to_bytes()
    }
  }

  pub fn add_public_key(a: &PublicKey, b: &PublicKey) -> SubgroupPoint {
    JubjubEngine::get_point(a) + JubjubEngine::get_point(b)
  }

  pub fn mul_by_proof_generation_generator(key: &PrivateKey) -> SubgroupPoint {
    PROOF_GENERATION_KEY_GENERATOR * JubjubEngine::get_scalar(key)
  }
}

impl CryptEngine for JubjubEngine {
  type PrivateKey = PrivateKey;
  type PublicKey = PublicKey;
  type Signature = Signature;
  type EncryptedSignature = NonExistant;

  fn new_private_key() -> Self::PrivateKey {
    PrivateKey {
      bytes: Fr::random(&mut OsRng).to_bytes()
    }
  }

  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey {
    PublicKey {
      bytes: (SPENDING_KEY_GENERATOR * Fr::from_bytes(&key.bytes).unwrap()).to_bytes()
    }
  }

  fn bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    if Fr::from_bytes(&bytes).is_some().into() {
      Ok(PrivateKey {
        bytes
      })
    } else {
      Err(anyhow::anyhow!("Invalid private key"))
    }
  }

  fn bytes_to_public_key(bytes: &[u8]) -> anyhow::Result<Self::PublicKey> {
    if SubgroupPoint::from_bytes(&bytes.try_into()?).is_some().into() {
      Ok(PublicKey {
        bytes: bytes.try_into()?
      })
    } else {
      Err(anyhow::anyhow!("Invalid public key"))
    }
  }

  fn bytes_to_signature(bytes: &[u8]) -> anyhow::Result<Self::Signature> {
    if bytes.len() != 64 {
      anyhow::bail!("Expected JubJub signature to be 64 bytes long");
    }

    #[allow(non_snake_case)]
    let R = SubgroupPoint::from_bytes(&bytes[..32].try_into()?);
    let s = Fr::from_bytes(&bytes[32..].try_into()?);
    if R.is_none().into() || s.is_none().into() {
      anyhow::bail!("Invalid point/scalar value in signature");
    }

    // Could also use bytes[..32].try_into()?
    Ok(Signature {
      R: R.unwrap().to_bytes(),
      s: s.unwrap().to_bytes()
    })
  }

  fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey> {
    Self::bytes_to_private_key(bytes)
  }

  fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32] {
    Self::private_key_to_bytes(key)
  }

  fn dl_eq_generate_commitments(key: [u8; 32]) -> anyhow::Result<Vec<Commitment<Self>>> {
    let mut commitments = Vec::new();
    let mut blinding_key_total = Fr::zero();
    let mut power_of_two = Fr::one();
    for i in 0..SHARED_KEY_BITS {
      let blinding_key = if i == SHARED_KEY_BITS - 1 {
        -blinding_key_total * power_of_two.invert().unwrap()
      } else {
        Fr::random(&mut OsRng)
      };
      blinding_key_total += blinding_key * power_of_two;
      power_of_two = power_of_two.double();
      let commitment_base = &SubgroupPoint::generator() * blinding_key;
      let (commitment, commitment_minus_one) = if (key[i/8] >> (i % 8)) & 1 == 1 {
        (&commitment_base + SPENDING_KEY_GENERATOR, commitment_base)
      } else {
        (commitment_base, &commitment_base - SPENDING_KEY_GENERATOR)
      };
      commitments.push(Commitment {
        blinding_key: PrivateKey {
          bytes: blinding_key.to_bytes()
        },
        commitment_minus_one: PublicKey {
          bytes: commitment_minus_one.to_bytes()
        },
        commitment: PublicKey {
          bytes: commitment.to_bytes()
        }
      });
    }
    debug_assert_eq!(blinding_key_total, Fr::zero());
    debug_assert_eq!(
      Self::dl_eq_reconstruct_key(commitments.iter().map(|c| &c.commitment))?,
      PublicKey {
        bytes: (SPENDING_KEY_GENERATOR * Fr::from_bytes(&key).unwrap()).to_bytes()
      }
    );
    Ok(commitments)
  }

  fn dl_eq_compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey> {
    Ok(PrivateKey {
      bytes: (
        (Fr::from_bytes(&key.bytes).unwrap() * fr_from_bytes_mod(challenge)) +
        Fr::from_bytes(&nonce.bytes).unwrap()
      ).to_bytes()
    })
  }

  #[allow(non_snake_case)]
  fn dl_eq_compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(PublicKey {
      bytes: (
        (&SubgroupPoint::generator() * Fr::from_bytes(&s_value.bytes).unwrap()) -
        (SubgroupPoint::from_bytes(&key.bytes).unwrap() * fr_from_bytes_mod(challenge))
      ).to_bytes()
    })
  }

  fn dl_eq_commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey> {
    Ok(PublicKey {
      bytes: (SubgroupPoint::from_bytes(&commitment.bytes).unwrap() - SPENDING_KEY_GENERATOR).to_bytes()
    })
  }

  fn dl_eq_reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey> {
    let mut power_of_two = Fr::one();
    let mut res = SubgroupPoint::identity();
    for comm in commitments {
      res = res + (SubgroupPoint::from_bytes(&comm.bytes).unwrap() * power_of_two);
      power_of_two = power_of_two.double();
    }
    Ok(PublicKey {
      bytes: res.to_bytes()
    })
  }

  fn dl_eq_blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey> {
    Ok(PublicKey {
      bytes: (&SubgroupPoint::generator() * Fr::from_bytes(&key.bytes).unwrap()).to_bytes()
    })
  }

  fn private_key_to_bytes(key: &Self::PrivateKey) -> [u8; 32] {
    key.bytes
  }
  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8> {
    key.bytes.to_vec()
  }

  fn signature_to_bytes(sig: &Self::Signature) -> Vec<u8> {
    let mut bytes = sig.R.to_vec();
    bytes.extend(&sig.s);
    bytes
  }

  // This implements EdDSA; implementing RedDSA instead to further match ZCash would be optimal.
  // The reason this implements EdDSA is because *any* algorithm would work here, and we already had EdDSA code.
  // It is solely used as a proof of knowledge, outsourcing the actual spend auth signature to ZCash code.
  #[allow(non_snake_case)]
  fn sign(key: &Self::PrivateKey, message: &[u8]) -> anyhow::Result<Self::Signature> {
    let key = Fr::from_bytes(&key.bytes).unwrap();
    let r = Fr::random(&mut OsRng);
    let R = SPENDING_KEY_GENERATOR * r;
    let A = SPENDING_KEY_GENERATOR * &key;
    let mut hram = [0u8; 64];
    let hash = sha2::Sha512::new()
      .chain(&R.to_bytes())
      .chain(&A.to_bytes())
      .chain(message)
      .finalize();
    hram.copy_from_slice(&hash);
    let c = Fr::from_bytes_wide(&hram);
    let s = r + c * key;
    Ok(Signature {
      R: R.to_bytes(),
      s: s.to_bytes(),
    })
  }

  #[allow(non_snake_case)]
  fn verify_signature(public_key: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> anyhow::Result<()> {
    let mut hram = [0u8; 64];
    let hash = sha2::Sha512::new()
      .chain(&signature.R)
      .chain(&public_key.bytes)
      .chain(message)
      .finalize();
    hram.copy_from_slice(&hash);
    let c = Fr::from_bytes_wide(&hram);
    let expected_R = (SPENDING_KEY_GENERATOR * Fr::from_bytes(&signature.s).unwrap()) -
      (SubgroupPoint::from_bytes(&public_key.bytes).unwrap() * c);
    if SubgroupPoint::from(expected_R) == SubgroupPoint::from_bytes(&signature.R).unwrap() {
      Ok(())
    } else {
      Err(anyhow::anyhow!("Bad signature"))
    }
  }

  // JubJub is used in ZK-Snarks. They don't have traditional signatures
  // Because of that, the following functions should never be called. They accordingly immediately error
  // The above functions are kept, however, as part of the proof of knowledge required with the DL EQ proof
  fn bytes_to_encrypted_signature(_bytes: &[u8]) -> anyhow::Result<Self::EncryptedSignature> {
    panic!("JubJub isn't used with signatures; there shouldn't be anything to deserialize");
  }

  fn encrypted_signature_to_bytes(_sig: &Self::EncryptedSignature) -> Vec<u8> {
    panic!("JubJub isn't used with signatures; there shouldn't be anything to serialize");
  }

  fn encrypted_sign(
    _signing_key: &Self::PrivateKey,
    _encryption_key: &Self::PublicKey,
    _message: &[u8]
  ) -> anyhow::Result<Self::EncryptedSignature> {
    panic!("JubJub isn't used with signatures; there shouldn't be anything to encrypt");
  }

  fn encrypted_verify(
    _signing_key: &Self::PublicKey,
    _encryption_key: &Self::PublicKey,
    _ciphertext: &Self::EncryptedSignature,
    _message: &[u8]
  ) -> anyhow::Result<()> {
    panic!("JubJub isn't used with signatures; there shouldn't be anything to verify");
  }

  fn decrypt_signature(_sig: &Self::EncryptedSignature, _key: &Self::PrivateKey) -> anyhow::Result<Self::Signature> {
    panic!("JubJub isn't used with signatures; there shouldn't be anything to decrypt");
  }

  fn recover_key(_encryption_key: &Self::PublicKey, _ciphertext: &Self::EncryptedSignature, _sig: &Self::Signature) -> anyhow::Result<Self::PrivateKey> {
    panic!("JubJub isn't used with signatures; there shouldn't be anything to recover from");
  }
}
