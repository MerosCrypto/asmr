use std::{
  marker::PhantomData,
  path::Path,
  fs::File
};

#[cfg(test)]
use std::convert::TryInto;

use async_trait::async_trait;

use curve25519_dalek::scalar::Scalar;
#[cfg(test)]
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

use dleq::engines::ed25519::Ed25519Engine;

#[cfg(test)]
use monero::util::key::{PrivateKey, PublicKey, ViewPair};
use monero::util::address::Address;

use crate::{
  crypto::KeyBundle,
  coins::{
    ScriptedVerifier, UnscriptedClient,
    xmr::engine::*
  }
};
#[cfg(test)]
use crate::crypto::ed25519::random_scalar;

pub struct XmrClient {
  engine: XmrEngine,
  #[cfg(test)]
  refund_pair: Option<ViewPair>,
  address: Option<String>,
  deposited: bool
}

impl XmrClient {
  pub async fn new(config_path: &Path) -> anyhow::Result<XmrClient> {
    Ok(XmrClient {
      engine: XmrEngine::new(
        serde_json::from_reader(File::open(config_path)?)?
      ).await?,
      #[cfg(test)]
      refund_pair: None,
      address: None,
      deposited: false
    })
  }
}

#[async_trait]
impl UnscriptedClient for XmrClient {
  fn generate_keys<Verifier: ScriptedVerifier>(&mut self, verifier: &mut Verifier) -> Vec<u8> {
    let (dleq, key) = verifier.generate_keys_for_engine::<Ed25519Engine>(PhantomData);
    self.engine.k = Some(key);
    KeyBundle {
      dleq: bincode::serialize(
        &XmrKeys {
          dleq,
          view_share: self.engine.view.to_bytes()
        }
      ).unwrap(),
      B: verifier.B(),
      BR: verifier.BR(),
      scripted_destination: verifier.destination_script()
    }.serialize()
  }

  fn verify_keys<Verifier: ScriptedVerifier>(&mut self, keys: &[u8], verifier: &mut Verifier) -> anyhow::Result<()> {
    // Workaround for the problem described in verifier.rs
    // It comments there a simple rename of dleq should work
    // That said, this demonstrates the need for an extra field entirely
    let mut bundle: KeyBundle = bincode::deserialize(keys)?;
    let xmr_keys: XmrKeys = bincode::deserialize(&bundle.dleq)?;
    bundle.dleq = xmr_keys.dleq;
    self.engine.view += Scalar::from_bytes_mod_order(xmr_keys.view_share);
    self.engine.set_spend(verifier.verify_keys_for_engine::<Ed25519Engine>(&bincode::serialize(&bundle).unwrap(), PhantomData)?);
    Ok(())
  }

  fn get_address(&mut self) -> String {
    let address = Address::from_viewpair(NETWORK, &self.engine.get_view_pair()).to_string();
    self.address = Some(address.clone());
    address
  }

  async fn wait_for_deposit(&mut self) -> anyhow::Result<()> {
    self.engine.get_deposit(&self.engine.get_view_pair(), true).await?.unwrap();
    self.deposited = true;
    Ok(())
  }

  async fn refund<Verifier: ScriptedVerifier>(self, verifier: Verifier) -> anyhow::Result<()> {
    if !self.deposited {
      Ok(())
    } else {
      if let Some(recovered_key) = verifier.claim_refund_or_recover_key().await? {
        self.engine.claim(
          Scalar::from_bytes_mod_order(recovered_key),
          &self.engine.config.refund
        ).await?;
      }
      Ok(())
    }
  }

  #[cfg(test)]
  fn override_refund_with_random_address(&mut self) {
    self.refund_pair = Some(ViewPair {
      view: PrivateKey {
        scalar: random_scalar()
      },
      spend: PublicKey {
        point: (&random_scalar() * &ED25519_BASEPOINT_TABLE).compress()
      }
    });
    self.engine.config.refund = Address::from_viewpair(NETWORK, self.refund_pair.as_ref().unwrap()).to_string();
  }

  #[cfg(test)]
  async fn send_from_node(&mut self) -> anyhow::Result<()> {
    self.engine.send_from_wallet().await
  }
  #[cfg(test)]
  async fn advance_consensus(&self) -> anyhow::Result<()> {
    self.engine.mine_block().await
  }
  #[cfg(test)]
  fn get_refund_address(&self) -> String {
    // Actually return the ViewPair, in order to be able to track the address it maps to
    hex::encode(&self.refund_pair.as_ref().unwrap().view.scalar.to_bytes()) +
    &hex::encode(&self.refund_pair.as_ref().unwrap().spend.point.as_bytes())
  }

  #[cfg(test)]
  async fn get_if_funded(mut self, pair: &str) -> bool {
    let pair = hex::decode(pair).unwrap();
    let pair = ViewPair {
      view: PrivateKey {
        scalar: Scalar::from_bytes_mod_order(pair[0 .. 32].try_into().unwrap())
      },
      spend: PublicKey {
        point: (&Scalar::from_bytes_mod_order(pair[32..].try_into().unwrap()) * &ED25519_BASEPOINT_TABLE).compress()
      },
    };
    self.engine.get_deposit(&pair, false).await.expect("Couldn't get if a Transaction to a ViewPair exists").is_some()
  }
}
