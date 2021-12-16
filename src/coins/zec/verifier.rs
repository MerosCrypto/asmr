use std::{
  marker::PhantomData,
  io::Write,
  path::Path,
  fs::File
};

use async_trait::async_trait;

use jubjub::Fr;

use dleq::{DLEqProof, engines::DLEqEngine};

use crate::{
  crypto::sapling::SaplingEngine,
  coins::{
    UnscriptedVerifier, ScriptedHost,
    zec::engine::*
  }
};

pub struct ZecShieldedVerifier(ZecEngine);

impl ZecShieldedVerifier {
  pub async fn new(config_path: &Path) -> anyhow::Result<ZecShieldedVerifier> {
    Ok(ZecShieldedVerifier(ZecEngine::new(serde_json::from_reader(File::open(config_path)?)?).await?))
  }
}

#[async_trait]
impl UnscriptedVerifier for ZecShieldedVerifier {
  fn generate_keys_for_engine<OtherCrypt: DLEqEngine>(&mut self, _: PhantomData<&OtherCrypt>) -> (Vec<u8>, OtherCrypt::PrivateKey) {
    let (proof, key1, key2) = DLEqProof::<SaplingEngine, OtherCrypt>::new(&mut rand::rngs::OsRng);
    self.0.ask = Some(key1);
    (
      bincode::serialize(
        &ZecKeys {
          dleq: proof.serialize().expect("Couldn't serialize a DLEq proof"),
          nsk: self.0.nsk.to_bytes()
        }
      ).unwrap(),
      key2
    )
  }

  fn verify_dleq_for_engine<OtherCrypt: DLEqEngine>(&mut self, dleq: &[u8], _: PhantomData<&OtherCrypt>) -> anyhow::Result<OtherCrypt::PublicKey> {
    let keys: ZecKeys = bincode::deserialize(dleq)?;
    let dleq = DLEqProof::<OtherCrypt, SaplingEngine>::deserialize(&keys.dleq)?;
    let (key1, key2) = dleq.verify()?;
    let nsk = Fr::from_bytes(&keys.nsk);
    if !bool::from(nsk.is_some()) {
      anyhow::bail!("Invalid nsk provided by counterparty");
    }
    self.0.set_ak_nsk(key2, nsk.unwrap());
    Ok(key1)
  }

  async fn verify_and_wait_for_send(&mut self) -> anyhow::Result<()> {
    let vk = self.0.vk.clone().expect("Getting the deposit before sharing keys");
    let deposit = self.0.get_deposit(&vk, true).await?.unwrap();

    if !cfg!(test) {
      print!("You will receive {} atomic units of ZEC. Continue (yes/no)? ", deposit);
      std::io::stdout().flush().expect("Failed to flush stdout");
      let mut line = String::new();
      std::io::stdin().read_line(&mut line).expect("Couldn't read from stdin");
      if !line.to_lowercase().starts_with("y") {
        anyhow::bail!("User didn't confirm ZEC amount");
      }
    }

    Ok(())
  }

  async fn finish<Host: ScriptedHost>(&mut self, host: &Host) -> anyhow::Result<()> {
    let recovered_key = Fr::from_bytes(&host.recover_final_key().await?);
    if !bool::from(recovered_key.is_some()) {
      anyhow::bail!("Recovered invalid key");
    }
    self.0.claim(recovered_key.unwrap(), &self.0.config.destination).await
  }
}
