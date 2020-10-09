use anyhow::Context;

use log::trace;

use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, digest::Digest};

use serde::{Serialize, Deserialize};

use crate::crypt_engines::CryptEngine;

/// The number of bits shared keys can be specified with.
/// Limited by ed25519's scalar modulus, which is 2^252 and change.
pub const SHARED_KEY_BITS: usize = 252;

#[derive(Serialize, Deserialize)]
pub struct DlEqProof<EngineA: CryptEngine, EngineB: CryptEngine> {
  base_commitments: Vec<(EngineA::PublicKey, EngineB::PublicKey)>,
  first_challenges: Vec<[u8; 32]>,
  s_values: Vec<[(EngineA::PrivateKey, EngineB::PrivateKey); 2]>,
  signatures: (EngineA::Signature, EngineB::Signature),
}

impl<EngineA: CryptEngine, EngineB: CryptEngine> DlEqProof<EngineA, EngineB> {
  pub fn new() -> (Self, EngineA::PrivateKey, EngineB::PrivateKey) {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    assert_eq!(SHARED_KEY_BITS, 252); // Change the following line if this changes
    key[31] &= 0b0000_1111; // Chop off bits that might be greater than the curve modulus
    let full_commitments_a = EngineA::dl_eq_generate_commitments(key).unwrap();
    let full_commitments_b = EngineB::dl_eq_generate_commitments(key).unwrap();
    assert_eq!(full_commitments_a.len(), SHARED_KEY_BITS);
    assert_eq!(full_commitments_b.len(), SHARED_KEY_BITS);
    let mut base_commitments = Vec::new();
    let mut first_challenges = Vec::new();
    let mut s_values = Vec::new();
    for (i, (comm_a, comm_b)) in full_commitments_a.into_iter().zip(full_commitments_b).enumerate() {
      let bit_set = (key[i/8] >> (i % 8)) & 1 == 1;
      let (mut real_comm, mut fake_comm) = ((&comm_a.commitment, &comm_b.commitment), (&comm_a.commitment_minus_one, &comm_b.commitment_minus_one));
      if bit_set {
        std::mem::swap(&mut real_comm, &mut fake_comm);
      }
      debug_assert_eq!(
        hex::encode(EngineA::public_key_to_bytes(&EngineA::dl_eq_blinding_key_to_public(&comm_a.blinding_key).unwrap())),
        hex::encode(EngineA::public_key_to_bytes(real_comm.0))
      );
      debug_assert_eq!(
        hex::encode(EngineB::public_key_to_bytes(&EngineB::dl_eq_blinding_key_to_public(&comm_b.blinding_key).unwrap())),
        hex::encode(EngineB::public_key_to_bytes(real_comm.1))
      );
      let future_nonce_a = EngineA::new_private_key();
      let future_nonce_b = EngineB::new_private_key();
      let cheating_challenge: [u8; 32] = Sha256::new()
        .chain(EngineA::public_key_to_bytes(&comm_a.commitment))
        .chain(EngineB::public_key_to_bytes(&comm_b.commitment))
        .chain(EngineA::public_key_to_bytes(&EngineA::dl_eq_blinding_key_to_public(&future_nonce_a).unwrap()))
        .chain(EngineB::public_key_to_bytes(&EngineB::dl_eq_blinding_key_to_public(&future_nonce_b).unwrap()))
        .finalize()
        .into();
      let cheating_s_a = EngineA::new_private_key();
      let cheating_s_b = EngineB::new_private_key();
      let real_challenge: [u8; 32] = Sha256::new()
        .chain(EngineA::public_key_to_bytes(&comm_a.commitment))
        .chain(EngineB::public_key_to_bytes(&comm_b.commitment))
        .chain(EngineA::public_key_to_bytes(&EngineA::dl_eq_compute_signature_R(&cheating_s_a, cheating_challenge, fake_comm.0).unwrap()))
        .chain(EngineB::public_key_to_bytes(&EngineB::dl_eq_compute_signature_R(&cheating_s_b, cheating_challenge, fake_comm.1).unwrap()))
        .finalize()
        .into();
      let real_s_a = EngineA::dl_eq_compute_signature_s(&future_nonce_a, real_challenge, &comm_a.blinding_key).unwrap();
      let real_s_b = EngineB::dl_eq_compute_signature_s(&future_nonce_b, real_challenge, &comm_b.blinding_key).unwrap();
      if bit_set {
        first_challenges.push(cheating_challenge);
        s_values.push([
          (real_s_a, real_s_b),
          (cheating_s_a, cheating_s_b),
        ]);
      } else {
        first_challenges.push(real_challenge);
        s_values.push([
          (cheating_s_a, cheating_s_b),
          (real_s_a, real_s_b),
        ]);
      }
      base_commitments.push((comm_a.commitment, comm_b.commitment));
    }
    let key_a = EngineA::little_endian_bytes_to_private_key(key).unwrap();
    let key_a_hash: [u8; 32] = Sha256::digest(&EngineA::public_key_to_bytes(&EngineA::to_public_key(&key_a))).into();
    let sig_a = EngineA::sign(&key_a, &key_a_hash).unwrap();
    let key_b = EngineB::little_endian_bytes_to_private_key(key).unwrap();
    let key_b_hash: [u8; 32] = Sha256::digest(&EngineB::public_key_to_bytes(&EngineB::to_public_key(&key_b))).into();
    let sig_b = EngineB::sign(&key_b, &key_b_hash).unwrap();
    (
      DlEqProof {
        base_commitments,
        first_challenges,
        s_values,
        signatures: (sig_a, sig_b),
      },
      key_a,
      key_b,
    )
  }

  pub fn verify(&self) -> anyhow::Result<(EngineA::PublicKey, EngineB::PublicKey)> {
    if (self.base_commitments.len() != SHARED_KEY_BITS) ||
      (self.first_challenges.len() != SHARED_KEY_BITS) ||
      (self.s_values.len() != SHARED_KEY_BITS)
    {
      anyhow::bail!("Discrete logarithm proof has wrong size");
    }
    for i in 0..SHARED_KEY_BITS {
      let (ref base_commitment_a, ref base_commitment_b) = self.base_commitments[i];
      let first_challenge = self.first_challenges[i];
      let ref s_values = self.s_values[i];
      let second_challenge: [u8; 32] = Sha256::new()
        .chain(EngineA::public_key_to_bytes(base_commitment_a))
        .chain(EngineB::public_key_to_bytes(base_commitment_b))
        .chain(EngineA::public_key_to_bytes(&EngineA::dl_eq_compute_signature_R(&s_values[1].0, first_challenge, base_commitment_a)?))
        .chain(EngineB::public_key_to_bytes(&EngineB::dl_eq_compute_signature_R(&s_values[1].1, first_challenge, base_commitment_b)?))
        .finalize()
        .into();
      let other_commitment_a = EngineA::dl_eq_commitment_sub_one(base_commitment_a)?;
      let other_commitment_b = EngineB::dl_eq_commitment_sub_one(base_commitment_b)?;
      let check_first_challenge: [u8; 32] = Sha256::new()
        .chain(EngineA::public_key_to_bytes(base_commitment_a))
        .chain(EngineB::public_key_to_bytes(base_commitment_b))
        .chain(EngineA::public_key_to_bytes(&EngineA::dl_eq_compute_signature_R(&s_values[0].0, second_challenge, &other_commitment_a)?))
        .chain(EngineB::public_key_to_bytes(&EngineB::dl_eq_compute_signature_R(&s_values[0].1, second_challenge, &other_commitment_b)?))
        .finalize()
        .into();
      if first_challenge != check_first_challenge {
        anyhow::bail!("Bad dleq proof! Regenerated challenge didn't match expected");
      }
    }
    let key_a = EngineA::dl_eq_reconstruct_key(self.base_commitments.iter().map(|c| &c.0))?;
    let key_a_hash: [u8; 32] = Sha256::digest(&EngineA::public_key_to_bytes(&key_a)).into();
    EngineA::verify_signature(&key_a, &key_a_hash, &self.signatures.0)
      .context("Error verifying signature for dleq public key A")?;
    let key_b = EngineB::dl_eq_reconstruct_key(self.base_commitments.iter().map(|c| &c.1))?;
    let key_b_hash: [u8; 32] = Sha256::digest(&EngineB::public_key_to_bytes(&key_b)).into();
    EngineB::verify_signature(&key_b, &key_b_hash, &self.signatures.1)
      .context("Error verifying signature for dleq public key B")?;
    trace!(
      "Verified dleq proof for keys {} and {}",
      hex::encode(EngineA::public_key_to_bytes(&key_a)),
      hex::encode(EngineB::public_key_to_bytes(&key_b))
    );
    Ok((key_a, key_b))
  }

  pub fn serialize(&self) -> Vec<u8> {
    bincode::serialize(self).expect("Failed to serialize dleq proof")
  }

  pub fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
    Ok(bincode::deserialize(bytes)?)
  }
}
