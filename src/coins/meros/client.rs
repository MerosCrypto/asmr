use std::{
  marker::PhantomData,
  path::Path,
  fs::File
};

use async_trait::async_trait;

use crate::{
  crypt_engines::{KeyBundle, CryptEngine, ed25519_engine::Ed25519Sha},
  coins::{
    UnscriptedClient, ScriptedVerifier,
    meros::{
      transaction::Transaction,
      engine::MerosEngine,
      rpc::MerosRpc
    }
  }
};

pub struct MerosClient {
  rpc: MerosRpc,
  refund: Vec<u8>,
  key_share: Option<<Ed25519Sha as CryptEngine>::PrivateKey>,
  shared_key: Option<<Ed25519Sha as CryptEngine>::PublicKey>,
  address: Option<String>,
  deposited: bool
}

impl MerosClient {
  pub fn new(config_path: &Path) -> anyhow::Result<MerosClient> {
    let config = serde_json::from_reader(File::open(config_path)?)?;
    Ok(MerosClient{
      rpc: MerosRpc::new(&config)?,
      refund: MerosEngine::decode_address(&config.refund)?,
      key_share: None,
      shared_key: None,
      address: None,
      deposited: false
    })
  }
}

#[async_trait]
impl UnscriptedClient for MerosClient {
  fn generate_keys<Verifier: ScriptedVerifier>(&mut self, verifier: &mut Verifier) -> Vec<u8> {
    let (dl_eq, key) = verifier.generate_keys_for_engine::<Ed25519Sha>(PhantomData);
    self.key_share = Some(key);
    KeyBundle {
      dl_eq,
      B: verifier.B(),
      BR: verifier.BR(),
      scripted_destination: verifier.destination_script()
    }.serialize()
  }

  fn verify_keys<Verifier: ScriptedVerifier>(&mut self, keys: &[u8], verifier: &mut Verifier) -> anyhow::Result<()> {
    let host_key = verifier.verify_keys_for_engine::<Ed25519Sha>(&keys, PhantomData)?;
    let our_pubkey = Ed25519Sha::to_public_key(self.key_share.as_ref().expect("Verifying DLEQ proof before generating keys"));
    self.shared_key = Some(our_pubkey + host_key);
    Ok(())
  }

  fn get_address(&mut self) -> String {
    let address = MerosEngine::get_address(
      &Ed25519Sha::public_key_to_bytes(
        &self.shared_key.expect("Trying to get the Meros deposit addresss despite not having verified the host's DLEQ proof")
      )
    );
    self.address = Some(address.clone());
    address
  }

  async fn wait_for_deposit(&mut self) -> anyhow::Result<()> {
    let address = self.address.clone().expect("Waiting for deposit despite not knowing the deposit address");
    let mut utxos = self.rpc.get_utxos(address.clone()).await;
    while utxos.len() == 0 {
      tokio::time::delay_for(std::time::Duration::from_secs(5)).await;
      utxos = self.rpc.get_utxos(address.clone()).await;
    }
    self.deposited = true;
    Ok(())
  }

  async fn refund<Verifier: ScriptedVerifier + Send + Sync>(mut self, verifier: Verifier) -> anyhow::Result<()> {
    // No deposit could have occurred/did occur
    if self.address.is_none() || (!self.deposited) {
      Ok(())
    } else {
      let utxos = self.rpc.get_utxos(self.address.expect("Couldn't get address despite the option being some")).await;

      /*    
        No UTXOs meant the other party already claimed these funds
        We can't then claim the BTC as this would've required us to try to claim the BTC
        And since we tried it, and failed, there's not much to do
        We can publish the refund transaction, yet the other party can instantly claim it for themselves
      */
      if utxos.len() == 0 {
        anyhow::bail!("Deposited yet no UTXOs exist and we're trying to call refund");
      } else {
        /*
          Once we publish the refund, two paths open up
          A) We can claim the BTC after the second timeout expires
          B) We can claim the MR after the host claims the BTC
          We assume path A, and then revert to path B if path A fails
        */
        if let Some(recovered_key) = verifier.claim_refund_or_recover_key().await? {
          let mut value_sum = 0;
          for input in utxos.clone() {
            value_sum += self.rpc.get_transaction_output_value(input.clone()).await?;
          }

          let send = MerosEngine::create_send(
            Ed25519Sha::little_endian_bytes_to_private_key(recovered_key)?,
            self.key_share.expect("Finishing before generating keys"),
            utxos,
            self.refund,
            value_sum,
            self.rpc.get_send_difficulty().await
          );
          self.rpc.publish_send(send.serialize()).await?;
        }
        Ok(())
      }
    }
  }

  #[cfg(test)]
  fn override_refund_with_random_address(&mut self) {
    self.refund = Ed25519Sha::public_key_to_bytes(&Ed25519Sha::to_public_key(&Ed25519Sha::new_private_key()));
  }
  #[cfg(test)]
  async fn send_from_node(&mut self) -> anyhow::Result<()> {
    self.rpc.send(self.address.clone().expect("Calling send from node before generating the address")).await
  }
  #[cfg(test)]
  async fn advance_consensus(&self) -> anyhow::Result<()> {
    Ok(())    
  }
  #[cfg(test)]
  fn get_refund_address(&self) -> String {
    MerosEngine::get_address(&self.refund)
  }
  #[cfg(test)]
  async fn get_if_funded(mut self, address: &str) -> bool {
    self.rpc.get_utxos(address.to_string()).await.len() != 0
  }
}
