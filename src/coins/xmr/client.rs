#[allow(unused_imports)]
use std::{
  marker::PhantomData,
  convert::TryInto,
  path::Path,
  fs::File
};

use async_trait::async_trait;

#[allow(unused_imports)]
use monero::util::{
  key::{PrivateKey, PublicKey, ViewPair},
  address::Address
};

use crate::{
  crypt_engines::{KeyBundle, CryptEngine, ed25519_engine::Ed25519Sha},
  coins::{
    ScriptedVerifier, UnscriptedClient,
    xmr::engine::*
  }
};

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
    let (dl_eq, key) = verifier.generate_keys_for_engine::<Ed25519Sha>(PhantomData);
    self.engine.k = Some(key);
    KeyBundle {
      dl_eq: bincode::serialize(
        &XmrKeys {
          dl_eq,
          view_share: Ed25519Sha::private_key_to_bytes(&self.engine.view)
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
    let xmr_keys: XmrKeys = bincode::deserialize(&bundle.dl_eq)?;
    bundle.dl_eq = xmr_keys.dl_eq;
    self.engine.view += Ed25519Sha::bytes_to_private_key(xmr_keys.view_share)?;
    self.engine.set_spend(verifier.verify_keys_for_engine::<Ed25519Sha>(&bincode::serialize(&bundle).unwrap(), PhantomData)?);
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
          Ed25519Sha::little_endian_bytes_to_private_key(recovered_key)?,
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
        scalar: Ed25519Sha::new_private_key()
      },
      spend: PublicKey {
        point: Ed25519Sha::to_public_key(&Ed25519Sha::new_private_key()).compress()
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
    hex::encode(Ed25519Sha::private_key_to_bytes(&self.refund_pair.as_ref().unwrap().view.scalar)) +
    &hex::encode(&self.refund_pair.as_ref().unwrap().spend.point.as_bytes())
  }

  #[cfg(test)]
  async fn get_if_funded(mut self, pair: &str) -> bool {
    let pair = hex::decode(pair).unwrap();
    let pair = ViewPair {
      view: PrivateKey {
        scalar: Ed25519Sha::bytes_to_private_key(pair[0 .. 32].try_into().unwrap()).unwrap()
      },
      spend: PublicKey {
        point: Ed25519Sha::bytes_to_public_key(pair[32..].try_into().unwrap()).unwrap().compress()
      },
    };
    self.engine.get_deposit(&pair, false).await.expect("Couldn't get if a Transaction to a ViewPair exists").is_some()
  }
}
