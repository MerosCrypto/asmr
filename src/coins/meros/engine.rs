use std::net::SocketAddr;

use log::debug;
use serde::Deserialize;
use bitcoin::bech32::{self, ToBase32, FromBase32};

use crate::{
  crypt_engines::{CryptEngine, ed25519_engine::Ed25519Sha},
  coins::meros::transaction::{Input, Output, Send}
};

#[derive(Deserialize)]
pub struct MerosConfig {
  pub address: SocketAddr,
  pub destination: String,
  pub refund: String
}

pub struct MerosEngine {
  pub k: Option<<Ed25519Sha as CryptEngine>::PrivateKey>
}

impl MerosEngine {
  pub fn new() -> MerosEngine {
    MerosEngine {
      k: None
    }
  }

  pub fn decode_address(address: &str) -> anyhow::Result<Vec<u8>> {
    let mut result = Vec::<u8>::from_base32(&bech32::decode(address)?.1)?;
    if (result[0] != 0) || (result.len() != 33) {
      anyhow::bail!("Unsupported Meros address type.");
    }
    result.remove(0);
    Ok(result)
  }

  pub fn get_address(key: &[u8]) -> String {
    let mut data = vec![0];
    data.extend(key);
    bech32::encode("mr", data.to_base32()).unwrap()
  }

  pub fn create_send(
    key_a: <Ed25519Sha as CryptEngine>::PrivateKey,
    key_b: <Ed25519Sha as CryptEngine>::PrivateKey,
    utxos: Vec<Input>,
    destination: Vec<u8>,
    value: u64,
    diff: u32
  ) -> Send {
    let mut send = Send::new(
      utxos,
      vec![
        Output {
          key: destination,
          value: value
        }
      ]
    );
    let total_key = key_a + key_b;
    debug!(
      "Creating Meros send for shared address {}",
      Self::get_address((&total_key * &curve25519_dalek::constants::ED25519_BASEPOINT_TABLE).compress().as_bytes())
    );
    send.sign(total_key);
    send.mine(diff);
    send
  }
}
