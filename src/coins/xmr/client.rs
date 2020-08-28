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
  refund_address: String,
  refund_tx_hex_hash: String
}

impl XmrClient {
  pub async fn new(config_path: &Path) -> anyhow::Result<XmrClient> {
    let config = serde_json::from_reader(File::open(config_path)?)?;
    Ok(XmrClient{
      engine: XmrEngine::new(),
      rpc: XmrRpc::new(&config).await?,
      refund_address: "".to_string(),
      refund_tx_hex_hash: "".to_string()
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
    // TODO: Merge this and the Verifier's copy into the RPC as a common function
    let mut last_handled_block = self.rpc.height_at_start - 1;
    let view_pair = ViewPair {
      spend: PublicKey {
        point: self.engine.spend.expect("Waiting for transaction before verifying DLEQ proof").compress()
      },
      view: PrivateKey::from_scalar(self.engine.view)
    };

    'outer: loop {
      while self.rpc.get_height().await > last_handled_block {
        for tx in self.rpc.get_transactions_in_block(last_handled_block).await? {
          if tx.prefix.check_outputs(&view_pair, 0..1, 0..1).is_err() {
            continue
          }
          break 'outer;
        }
        last_handled_block += 1;
      }
      tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
    }

    Ok(())
  }

  async fn refund<Verifier: ScriptedVerifier >(self, _verifier: Verifier) -> anyhow::Result<()> {todo!()}

  #[cfg(test)]
  fn override_refund_with_random_address(&mut self) {todo!()}
  #[cfg(test)]
  async fn send_from_node(&mut self) -> anyhow::Result<()> {todo!()}
  #[cfg(test)]
  async fn advance_consensus(&self) -> anyhow::Result<()> {todo!()}
  #[cfg(test)]
  fn get_refund_address(&self) -> String {todo!()}
  #[cfg(test)]
  async fn get_if_funded(self, address: &str) -> bool {
    if address != self.refund_address {
      panic!("Tried to get if an address other than our refund address was funded. This is unsupported on Monero");
    }

    // Get past the result and option. The refund transaction should both exist and not cause an RPC error in this test env
    self.rpc.get_transaction(&self.refund_tx_hex_hash).await.unwrap().unwrap().1 > 0
  }
}
