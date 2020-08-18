use async_trait::async_trait;

use crate::coins::{
  UnscriptedClient, ScriptedVerifier,
  xmr::{engine::*, rpc::XmrRpc}
};

pub struct XmrClient {
  engine: XmrEngine,
  rpc: XmrRpc,
  refund_address: String,
  refund_tx_hex_hash: String
}

#[async_trait]
impl UnscriptedClient for XmrClient {
  fn generate_keys<Verifier: ScriptedVerifier>(&mut self, verifier: &mut Verifier) -> Vec<u8> {todo!()}
  fn verify_keys<Verifier: ScriptedVerifier>(&mut self, keys: &[u8], verifier: &mut Verifier) -> anyhow::Result<()> {todo!()}

  fn get_address(&mut self) -> String {todo!()}
  async fn wait_for_deposit(&mut self) -> anyhow::Result<()> {todo!()}
  async fn refund<Verifier: ScriptedVerifier >(self, verifier: Verifier) -> anyhow::Result<()> {todo!()}

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
