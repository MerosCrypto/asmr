use std::{
  marker::PhantomData,
  io::Write,
  path::Path,
  fs::File
};

use async_trait::async_trait;

use crate::{
  crypt_engines::{CryptEngine, jubjub_engine::JubjubEngine},
  dl_eq::DlEqProof,
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
  fn generate_keys_for_engine<OtherCrypt: CryptEngine>(&mut self, _: PhantomData<&OtherCrypt>) -> (Vec<u8>, OtherCrypt::PrivateKey) {
    let (proof, key1, key2) = DlEqProof::<JubjubEngine, OtherCrypt>::new();
    self.0.ask = Some(key1);
    (
      bincode::serialize(
        &ZecKeys {
          dl_eq: proof.serialize(),
          nsk: JubjubEngine::private_key_to_bytes(&self.0.nsk)
        }
      ).unwrap(),
      key2
    )
  }

  fn verify_dleq_for_engine<OtherCrypt: CryptEngine>(&mut self, dleq: &[u8], _: PhantomData<&OtherCrypt>) -> anyhow::Result<OtherCrypt::PublicKey> {
    let keys: ZecKeys = bincode::deserialize(dleq)?;
    let dleq = DlEqProof::<OtherCrypt, JubjubEngine>::deserialize(&keys.dl_eq)?;
    let (key1, key2) = dleq.verify()?;
    self.0.set_ak_nsk(
      &key2,
      &JubjubEngine::bytes_to_private_key(keys.nsk)?
    );
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
    self.0.claim(
      JubjubEngine::little_endian_bytes_to_private_key(host.recover_final_key().await?)?,
      &self.0.config.destination
    ).await
  }
}
