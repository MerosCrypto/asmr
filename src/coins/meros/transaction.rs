use std::{
  convert::TryInto,
  fmt::Debug
};

use bigint::uint::U256;
use blake2::digest::{Update, VariableOutput};
use argon2::{self, Config, ThreadMode, Variant, Version, hash_raw};

use serde::Deserialize;

use crate::crypto::{CryptEngine, ed25519_engine::Ed25519Sha};

const CONFIG: Config = Config {
  variant: Variant::Argon2d,
  version: Version::Version13,
  mem_cost: 8,
  time_cost: 1,
  lanes: 1,
  thread_mode: ThreadMode::Parallel,
  secret: &[],
  ad: &[],
  hash_length: 32
};

#[derive(Clone, Deserialize, Debug)]
pub struct Input {
  pub hash: String,
  pub nonce: u8
}

pub struct Output {
  pub key: Vec<u8>,
  pub value: u64
}

pub trait Transaction {
  fn inputs(&self) -> &Vec<Input>;
  fn outputs(&self) -> &Vec<Output>;
  fn hash(&self) -> Vec<u8>;
  fn serialize(&self) -> Vec<u8>;
}

pub struct Send {
  inputs: Vec<Input>,
  outputs: Vec<Output>,
  hash: Vec<u8>,
  signature: Option<Vec<u8>>,
  proof: u32
}

// This function consistently mines proofs into the space of hundreds
// It shold finish < 10. That said, it does still finish in a few seconds
fn mine(data: &[u8], diff: u32) -> u32 {
  let mut proof: i64 = -1;
  let mut hash = U256::max_value();
  let diff = U256::from(diff);
  while hash.overflowing_mul(diff).1 {
    proof += 1;
    hash = U256::from_little_endian(&hash_raw(data, &proof.to_le_bytes(), &CONFIG).unwrap());
  }
  std::cmp::max(0, proof).try_into().expect("Couldn't convert a spam proof to a u32")
}

impl Transaction for Send {
  fn inputs(&self) -> &Vec<Input> {
    &self.inputs
  }

  fn outputs(&self) -> &Vec<Output> {
    &self.outputs
  }

  fn hash(&self) -> Vec<u8> {
    self.hash.clone()
  }

  fn serialize(&self) -> Vec<u8> {
    let mut result = vec![self.inputs.len() as u8];
    for input in &self.inputs {
      result.extend(&hex::decode(&input.hash).expect("Input's hex hash wasn't hex"));
      result.push(input.nonce);
    }
    result.push(self.outputs.len() as u8);
    for output in &self.outputs {
      result.extend(&output.key);
      result.extend(&output.value.to_le_bytes());
    }
    result.extend(self.signature.as_ref().expect("Tried to serialize a Transaction which was never signed"));
    result.extend(&self.proof.to_le_bytes());
    result
  }
}

impl Send {
  pub fn new(inputs: Vec<Input>, outputs: Vec<Output>) -> Send {
    let mut hash = vec![2, inputs.len() as u8];
    for input in &inputs {
      hash.extend(&hex::decode(&input.hash).expect("Input's hex hash wasn't hex"));
      hash.push(input.nonce);
    }
    hash.push(outputs.len() as u8);
    for output in &outputs {
      hash.extend(&output.key);
      hash.extend(&output.value.to_le_bytes());
    }

    let mut hasher = blake2::VarBlake2b::new(32).unwrap();
    hasher.update(&hash);
    hasher.finalize_variable(|hash_ref| hash = hash_ref.to_vec());

    Send {
      inputs,
      outputs,
      hash,
      signature: None,
      proof: 0
    }
  }

  pub fn sign(&mut self, key: <Ed25519Sha as CryptEngine>::PrivateKey) {
    let mut to_sign = b"MEROS".to_vec();
    to_sign.extend(&self.hash);
    self.signature = Some(Ed25519Sha::signature_to_bytes(&Ed25519Sha::sign(&key, &to_sign).unwrap()));
  }

  pub fn mine(&mut self, diff: u32) {
    self.proof = mine(&self.hash, diff * (((70 + (self.inputs.len() * 33) + (self.outputs.len() * 40) / 143)) as u32));
  }
}
