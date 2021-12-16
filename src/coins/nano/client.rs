use std::{
  marker::PhantomData,
  path::Path,
  fs::File
};

use async_trait::async_trait;

#[cfg(test)]
use rand::rngs::OsRng;

use curve25519_dalek::{
  scalar::Scalar,
  edwards::EdwardsPoint,
  constants::ED25519_BASEPOINT_TABLE
};

use dleq::engines::ed25519::Ed25519Engine;

use nanocurrency_types::{Account, BlockHash};

use crate::{
  crypto::KeyBundle,
  coins::{
    UnscriptedClient, ScriptedVerifier,
    nano::engine::{NanoConfig, NanoEngine}
  }
};

pub struct NanoClient {
  engine: NanoEngine,
  refund: Account,
  key_share: Option<Scalar>,
  shared_key: Option<EdwardsPoint>,
  address: Option<String>,
  input: Option<(BlockHash, u128)>,
}

impl NanoClient {
  pub fn new(config_path: &Path) -> anyhow::Result<NanoClient> {
    let config: NanoConfig = serde_json::from_reader(File::open(config_path)?)?;
    Ok(NanoClient{
      refund: config.refund.parse()
        .map_err(|e| anyhow::anyhow!("Error parsing Nano address: {}", e))?,
      engine: NanoEngine::new(config),
      key_share: None,
      shared_key: None,
      address: None,
      input: None,
    })
  }
}

#[async_trait]
impl UnscriptedClient for NanoClient {
  fn generate_keys<Verifier: ScriptedVerifier>(&mut self, verifier: &mut Verifier) -> Vec<u8> {
    let (dleq, key) = verifier.generate_keys_for_engine::<Ed25519Engine>(PhantomData);
    self.key_share = Some(key);
    KeyBundle {
      dleq,
      B: verifier.B(),
      BR: verifier.BR(),
      scripted_destination: verifier.destination_script()
    }.serialize()
  }

  fn verify_keys<Verifier: ScriptedVerifier>(&mut self, keys: &[u8], verifier: &mut Verifier) -> anyhow::Result<()> {
    let host_key = verifier.verify_keys_for_engine::<Ed25519Engine>(&keys, PhantomData)?;
    let our_pubkey = self.key_share.as_ref().expect("Verifying DLEQ proof before generating keys") * &ED25519_BASEPOINT_TABLE;
    self.shared_key = Some(our_pubkey + host_key);
    Ok(())
  }

  fn get_address(&mut self) -> String {
    let shared_key = self.shared_key.expect("Trying to get the Nano deposit addresss despite not having verified the host's DLEQ proof");
    let address = Account(shared_key.compress().to_bytes()).to_string();
    self.address = Some(address.clone());
    address
  }

  async fn wait_for_deposit(&mut self) -> anyhow::Result<()> {
    let address = self.address.clone().expect("Waiting for deposit despite not knowing the deposit address");
    while self.input.is_none() {
      tokio::time::sleep(std::time::Duration::from_secs(5)).await;
      let mut inputs = self.engine.get_confirmed_pending(&address).await?;
      inputs.truncate(1);
      self.input = inputs.pop();
    }
    Ok(())
  }

  async fn refund<Verifier: ScriptedVerifier + Send + Sync>(mut self, verifier: Verifier) -> anyhow::Result<()> {
    if let Some((input, amount)) = self.input {
      /*
        Once we publish the refund, two paths open up
        A) We can claim the BTC after the second timeout expires
        B) We can claim the NANO after the host claims the BTC
        We assume path A, and then revert to path B if path A fails
      */
      if let Some(recovered_key) = verifier.claim_refund_or_recover_key().await? {
        self.engine.send(
          Scalar::from_bytes_mod_order(recovered_key),
          self.key_share.expect("Finishing before generating keys"),
          input,
          self.refund,
          amount,
        ).await?;
      }
    }
    Ok(())
  }

  #[cfg(test)]
  fn override_refund_with_random_address(&mut self) {
    self.refund = Account((&Scalar::random(&mut OsRng) * &ED25519_BASEPOINT_TABLE).compress().to_bytes());
  }
  #[cfg(test)]
  async fn send_from_node(&mut self) -> anyhow::Result<()> {
    self.engine.send_from_node(self.address.as_ref().unwrap(), 1)
      .await
      .expect("Failed to send Nano from node wallet");
    Ok(())
  }
  #[cfg(test)]
  async fn advance_consensus(&self) -> anyhow::Result<()> {
    Ok(())
  }
  #[cfg(test)]
  fn get_refund_address(&self) -> String {
    self.refund.to_string()
  }
  #[cfg(test)]
  async fn get_if_funded(mut self, address: &str) -> bool {
    !self.engine.get_confirmed_pending(&address).await.unwrap().is_empty()
  }
}
