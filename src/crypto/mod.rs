pub mod secp256k1;
pub mod ed25519;
pub mod sapling;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct KeyBundle {
  pub dleq: Vec<u8>,
  pub B: Vec<u8>,
  pub BR: Vec<u8>,
  pub scripted_destination: Vec<u8>
}

impl KeyBundle {
  pub fn serialize(&self) -> Vec<u8> {
    bincode::serialize(self).expect("Failed to serialize dleq proof")
  }

  pub fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
    Ok(bincode::deserialize(bytes)?)
  }
}
