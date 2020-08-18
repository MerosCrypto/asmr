use lazy_static::lazy_static;
use hex_literal::hex;

use serde::{Serialize, Deserialize};

use monero::network::Network;

use crate::crypt_engines::{CryptEngine, ed25519_engine::Ed25519Sha};

pub const NETWORK: Network = Network::Testnet;
pub const CONFIRMATIONS: isize = 1;

lazy_static! {
  pub static ref C: <Ed25519Sha as CryptEngine>::PublicKey = Ed25519Sha::bytes_to_public_key(&hex!("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")).unwrap();
}

#[derive(Serialize, Deserialize)]
pub struct XmrKeys {
  pub dl_eq: Vec<u8>,
  pub view_share: [u8; 32]
}

#[derive(Deserialize)]
pub struct XmrConfig {
  pub daemon: String,
  pub wallet: String
}

pub struct XmrEngine {
  pub k: Option<<Ed25519Sha as CryptEngine>::PrivateKey>,
  pub view: <Ed25519Sha as CryptEngine>::PrivateKey,
  pub spend: Option<<Ed25519Sha as CryptEngine>::PublicKey>,
}

impl XmrEngine {
  pub fn new() -> XmrEngine {
    XmrEngine {
      k: None,
      view: Ed25519Sha::new_private_key(),
      spend: None
    }
  }

  pub fn set_spend(&mut self, other: <Ed25519Sha as CryptEngine>::PublicKey) {
    self.spend = Some(Ed25519Sha::to_public_key(&self.k.expect("Verifying keys before generating")));
  }
}
