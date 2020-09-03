use std::{
  marker::PhantomData,
  path::Path,
  fs::File
};

use async_trait::async_trait;

use monero::util::{
  key::{PrivateKey, PublicKey, ViewPair},
  address::Address
};

use crate::{
  crypt_engines::{KeyBundle, CryptEngine, ed25519_engine::Ed25519Sha},
  coins::{
    ScriptedVerifier, UnscriptedClient,
    xmr::engine::*,
    xmr::rpc::XmrRpc
  }
};

pub struct XmrClient {
  engine: XmrEngine,
  rpc: XmrRpc,
  #[cfg(test)]
  refund_pair: Option<ViewPair>,
  refund_address: String
}

impl XmrClient {
  pub async fn new(config_path: &Path) -> anyhow::Result<XmrClient> {
    let config = serde_json::from_reader(File::open(config_path)?)?;
    Ok(XmrClient{
      engine: XmrEngine::new(),
      rpc: XmrRpc::new(&config).await?,
      #[cfg(test)]
      refund_pair: None,
      refund_address: config.refund
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
    Address::standard(
      NETWORK,
      PublicKey {
        point: self.engine.spend.expect("Getting address before verifying DLEQ proof").compress()
      },
      PublicKey {
        point: Ed25519Sha::to_public_key(&self.engine.view).compress()
      }
    ).to_string()
  }

  async fn wait_for_deposit(&mut self) -> anyhow::Result<()> {
    self.rpc.wait_for_deposit(&ViewPair {
      spend: PublicKey {
        point: self.engine.spend.expect("Waiting for transaction before verifying DLEQ proof").compress()
      },
      view: PrivateKey::from_scalar(self.engine.view)
    }).await?;
    Ok(())
  }

  async fn refund<Verifier: ScriptedVerifier >(self, _verifier: Verifier) -> anyhow::Result<()> {todo!()}

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
    self.refund_address = Address::from_viewpair(NETWORK, self.refund_pair.as_ref().unwrap()).to_string();
  }

  #[cfg(test)]
  async fn send_from_node(&mut self) -> anyhow::Result<()> {
    let address = self.get_address();
    self.rpc.send_from_wallet(&address).await
  }
  #[cfg(test)]
  async fn advance_consensus(&self) -> anyhow::Result<()> {
    self.rpc.mine_block().await
  }
  #[cfg(test)]
  fn get_refund_address(&self) -> String {
    self.refund_address.clone()
  }

  #[cfg(test)]
  async fn get_if_funded(self, address: &str) -> bool {
    if address != self.refund_address {
      panic!("Tried to get if an address other than our refund address was funded. This is unsupported on Monero");
    }

    // Get past the result and option. The refund transaction should both exist and not cause an RPC error in this test env
    //self.rpc.get_height().await - self.rpc.get_transaction(&self.refund_tx_hex_hash).await.unwrap().unwrap().1 > 0
    todo!()
  }
}
