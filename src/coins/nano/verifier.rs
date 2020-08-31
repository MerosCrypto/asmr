use std::{
  marker::PhantomData,
  io::Write,
  path::Path,
  fs::File,
};

use async_trait::async_trait;
use nanocurrency_types::{Account, BlockHash};

use crate::{
  crypt_engines::{CryptEngine, ed25519_engine::Ed25519Blake2b},
  dl_eq::DlEqProof,
  coins::{
    UnscriptedVerifier, ScriptedHost,
    nano::engine::{NanoConfig, NanoEngine},
  },
};

pub struct NanoVerifier {
  engine: NanoEngine,
  destination_key: Account,

  shared_key: Option<<Ed25519Blake2b as CryptEngine>::PublicKey>,
  input: Option<(BlockHash, u128)>,
}

impl NanoVerifier {
  pub fn new(config_path: &Path) -> anyhow::Result<NanoVerifier> {
    let config: NanoConfig = serde_json::from_reader(File::open(config_path)?)?;

    Ok(NanoVerifier {
      destination_key: config.destination.parse()
        .map_err(|e| anyhow::anyhow!("Error parsing Nano address: {}", e))?,
      engine: NanoEngine::new(config),

      shared_key: None,
      input: None,
    })
  }
}

#[async_trait]
impl UnscriptedVerifier for NanoVerifier {
  fn generate_keys_for_engine<OtherCrypt: CryptEngine>(&mut self, _: PhantomData<&OtherCrypt>) -> (Vec<u8>, OtherCrypt::PrivateKey) {
    let (proof, key1, key2) = DlEqProof::<Ed25519Blake2b, OtherCrypt>::new();
    self.engine.k = Some(key1);
    self.shared_key = Some(Ed25519Blake2b::to_public_key(&key1));
    (proof.serialize(), key2)
  }

  fn verify_dleq_for_engine<OtherCrypt: CryptEngine>(&mut self, dleq: &[u8], _: PhantomData<&OtherCrypt>) -> anyhow::Result<OtherCrypt::PublicKey> {
    let dleq = DlEqProof::<OtherCrypt, Ed25519Blake2b>::deserialize(dleq)?;
    let (key1, key2) = dleq.verify()?;
    self.shared_key = Some(self.shared_key.expect("Verifying DLEQ proof before generating keys") + key2);
    Ok(key1)
  }

  async fn verify_and_wait_for_send(&mut self) -> anyhow::Result<()> {
    let shared_key = self.shared_key.as_ref().expect("Waiting for send before verifying the other's DLEQ proof");
    let address = Account(shared_key.compress().to_bytes()).to_string();

    /*
      Considering Nano transactions are directly to public keys, there's not actually anything to verify
      There's no timelocks or alternate spending paths
      The node will only track the transaction if it's viable, including having a valid signature
    */

    while self.input.is_none() {
      let mut inputs = self.engine.get_confirmed_pending(&address).await?;
      inputs.truncate(1);
      self.input = inputs.pop();

      // Don't immediately run the next loop iteration
      if self.input.is_none() {
        tokio::time::delay_for(std::time::Duration::from_secs(5)).await;
      }
    }

    if !cfg!(test) {
      let amount = self.input.as_ref().unwrap().1 as f64 / 1e30;
      print!("You will receive {:.2} Nano. Continue (yes/no)? ", amount);
      std::io::stdout().flush().expect("Failed to flush stdout");
      let mut line = String::new();
      std::io::stdin().read_line(&mut line).expect("Couldn't read from stdin");
      if !line.to_lowercase().starts_with("y") {
        anyhow::bail!("User didn't confirm Nano amount");
      }
    }
    Ok(())
  }

  async fn finish<Host: ScriptedHost>(&mut self, host: &Host) -> anyhow::Result<()> {
    let input = self.input.clone().expect("Finishing before knowing of the UTXOs");
    self.engine.send(
      Ed25519Blake2b::little_endian_bytes_to_private_key(host.recover_final_key().await?)?,
      self.engine.k.expect("Finishing before generating keys"),
      input.0,
      self.destination_key.clone(),
      input.1,
    ).await?;
    Ok(())
  }
}
