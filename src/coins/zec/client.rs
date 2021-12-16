use std::{
  marker::PhantomData,
  path::Path,
  fs::File
};

#[cfg(test)]
use std::convert::TryInto;

use async_trait::async_trait;

#[cfg(test)]
use rand::{RngCore, rngs::OsRng};

use jubjub::Fr;

#[cfg(test)]
use zcash_primitives::{
  zip32::{ExtendedSpendingKey, ExtendedFullViewingKey}
};

#[cfg(test)]
use zcash_client_backend::encoding::encode_payment_address;

use crate::{
  crypto::{KeyBundle, sapling::SaplingEngine},
  coins::{UnscriptedClient, ScriptedVerifier, zec::engine::*}
};

pub struct ZecShieldedClient {
  engine: ZecEngine,
  deposited: bool,
  #[cfg(test)]
  refund_seed: [u8; 32]
}

impl ZecShieldedClient {
  pub async fn new(config_path: &Path) -> anyhow::Result<ZecShieldedClient> {
    Ok(ZecShieldedClient {
      engine: ZecEngine::new(serde_json::from_reader(File::open(config_path)?)?).await?,
      deposited: false,
      #[cfg(test)]
      refund_seed: [0; 32]
    })
  }
}

#[async_trait]
impl UnscriptedClient for ZecShieldedClient {
  fn generate_keys<Verifier: ScriptedVerifier>(&mut self, verifier: &mut Verifier) -> Vec<u8> {
    let (dleq, key) = verifier.generate_keys_for_engine::<SaplingEngine>(PhantomData);
    self.engine.ask = Some(key);
    KeyBundle {
      dleq: bincode::serialize(
        &ZecKeys {
          dleq,
          nsk: self.engine.nsk.to_bytes()
        }
      ).unwrap(),
      B: verifier.B(),
      BR: verifier.BR(),
      scripted_destination: verifier.destination_script()
    }.serialize()
  }

  fn verify_keys<Verifier: ScriptedVerifier>(&mut self, keys: &[u8], verifier: &mut Verifier) -> anyhow::Result<()> {
    let mut bundle: KeyBundle = bincode::deserialize(keys)?;
    let zec_keys: ZecKeys = bincode::deserialize(&bundle.dleq)?;
    bundle.dleq = zec_keys.dleq;
    let nsk = Fr::from_bytes(&zec_keys.nsk);
    if !bool::from(nsk.is_some()) {
      anyhow::bail!("Invalid nsk value provided by counterparty");
    }
    self.engine.set_ak_nsk(
      verifier.verify_keys_for_engine::<SaplingEngine>(&bincode::serialize(&bundle).unwrap(), PhantomData)?,
      nsk.unwrap()
    );
    Ok(())
  }

  fn get_address(&mut self) -> String {
    self.engine.get_deposit_address()
  }

  async fn wait_for_deposit(&mut self) -> anyhow::Result<()> {
    let vk = self.engine.vk.clone().expect("Getting the deposit before sharing keys");
    self.deposited = self.engine.get_deposit(&vk, true).await?.is_some();
    Ok(())
  }

  async fn refund<Verifier: ScriptedVerifier>(self, verifier: Verifier) -> anyhow::Result<()> {
    if !self.deposited {
      Ok(())
    } else {
      if let Some(recovered_key) = verifier.claim_refund_or_recover_key().await? {
        let recovered_key = Fr::from_bytes(&recovered_key);
        if bool::from(recovered_key.is_some()) == false {
          anyhow::bail!("Recovered invalid key");
        }
        self.engine.claim(recovered_key.unwrap(), &self.engine.config.refund).await?;
      }
      Ok(())
    }
  }

  #[cfg(test)]
  fn override_refund_with_random_address(&mut self) {
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    self.refund_seed = seed;
    self.engine.config.refund = encode_payment_address(
      SAPLING_HRP,
      &ExtendedSpendingKey::master(&seed).default_address().expect("Couldn't get default address").1
    );
  }

  #[cfg(test)]
  async fn send_from_node(&mut self) -> anyhow::Result<()> {
    self.engine.send_from_wallet().await?;
    Ok(())
  }

  #[cfg(test)]
  async fn advance_consensus(&self) -> anyhow::Result<()> {
    self.engine.mine_block().await
  }

  #[cfg(test)]
  fn get_refund_address(&self) -> String {
    hex::encode(&self.refund_seed)
  }

  #[cfg(test)]
  async fn get_if_funded(mut self, address: &str) -> bool {
    let efvk: ExtendedFullViewingKey = (&ExtendedSpendingKey::master(hex::decode(address).unwrap()[..32].try_into().unwrap())).into();
    self.engine.get_deposit(&efvk.fvk.vk, false).await.expect("Couldn't get if a Transaction to a ViewKey exists").is_some()
  }
}
