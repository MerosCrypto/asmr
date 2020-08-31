pub mod btc;
pub mod meros;
pub mod nano;

use std::marker::PhantomData;

use async_trait::async_trait;
use enum_dispatch::enum_dispatch;

use crate::crypt_engines::CryptEngine;

#[async_trait]
#[enum_dispatch(AnyScriptedHost)]
#[allow(non_snake_case)]
pub trait ScriptedHost: Send + Sync {
  fn generate_keys<Verifier: UnscriptedVerifier>(&mut self, verifier: &mut Verifier) -> Vec<u8>;
  fn verify_keys<Verifier: UnscriptedVerifier>(&mut self, keys: &[u8], verifier: &mut Verifier) -> anyhow::Result<()>;

  fn swap_secret(&self) -> [u8; 32];

  fn generate_deposit_address(&mut self) -> String;

  async fn create_lock_and_prepare_refund(&mut self) -> anyhow::Result<Vec<u8>>;
  fn verify_refund_and_spend(&mut self, refund_and_spend_sigs: &[u8]) -> anyhow::Result<()>;
  async fn publish_lock(&mut self) -> anyhow::Result<()>;

  async fn prepare_buy_for_client(&mut self) -> anyhow::Result<Vec<u8>>;

  async fn recover_final_key(&self) -> anyhow::Result<[u8; 32]>;
  async fn refund<Verifier: UnscriptedVerifier>(self, verifier: Verifier) -> anyhow::Result<()>;

  #[cfg(test)]
  fn override_refund_with_random_address(&mut self);
  #[cfg(test)]
  async fn send_from_node(&self) -> anyhow::Result<()>;
  #[cfg(test)]
  async fn advance_consensus(&self) -> anyhow::Result<()>;
  #[cfg(test)]
  fn get_refund_address(&self) -> String;
  #[cfg(test)]
  async fn get_if_funded(self, address: &str) -> bool;
}

#[enum_dispatch]
pub enum AnyScriptedHost {
  Btc(btc::host::BtcHost),
}

#[async_trait]
#[enum_dispatch(AnyUnscriptedClient)]
pub trait UnscriptedClient {
  fn generate_keys<Verifier: ScriptedVerifier>(&mut self, verifier: &mut Verifier) -> Vec<u8>;
  fn verify_keys<Verifier: ScriptedVerifier>(&mut self, keys: &[u8], verifier: &mut Verifier) -> anyhow::Result<()>;

  fn get_address(&mut self) -> String;
  async fn wait_for_deposit(&mut self) -> anyhow::Result<()>;
  async fn refund<Verifier: ScriptedVerifier >(self, verifier: Verifier) -> anyhow::Result<()>;

  #[cfg(test)]
  fn override_refund_with_random_address(&mut self);
  #[cfg(test)]
  async fn send_from_node(&mut self) -> anyhow::Result<()>;
  #[cfg(test)]
  async fn advance_consensus(&self) -> anyhow::Result<()>;
  #[cfg(test)]
  fn get_refund_address(&self) -> String;
  #[cfg(test)]
  async fn get_if_funded(self, address: &str) -> bool;
}

#[enum_dispatch]
pub enum AnyUnscriptedClient {
  Meros(meros::client::MerosClient),
  Nano(nano::client::NanoClient),
}

#[async_trait]
#[enum_dispatch(AnyScriptedVerifier)]
#[allow(non_snake_case)]
pub trait ScriptedVerifier: Send + Sync {
  fn destination_script(&self) -> Vec<u8>;

  // These `PhantomData`s are needed because enum_dispatch doesn't specify method type parameters (probably a bug)
  fn generate_keys_for_engine<OtherCrypt: CryptEngine>(&mut self, phantom: PhantomData<&OtherCrypt>) -> (Vec<u8>, OtherCrypt::PrivateKey);
  fn verify_keys_for_engine<OtherCrypt: CryptEngine>(&mut self, dleq: &[u8], phantom: PhantomData<&OtherCrypt>) -> anyhow::Result<OtherCrypt::PublicKey>;

  fn B(&self) -> Vec<u8>;
  fn BR(&self) -> Vec<u8>;

  fn verify_prepared_buy(&mut self, buy_info: &[u8]) -> anyhow::Result<()>;

  async fn verify_and_wait_for_lock(
    &mut self
  ) -> anyhow::Result<()>;

  async fn complete_refund_and_prepare_spend(
    &mut self,
    lock_and_host_signed_refund: &[u8]
  ) -> anyhow::Result<Vec<u8>>;

  async fn claim_refund_or_recover_key(self) -> anyhow::Result<Option<[u8; 32]>>;

  async fn finish(&self, swap_secret: &[u8]) -> anyhow::Result<()>;
}

#[enum_dispatch]
pub enum AnyScriptedVerifier {
  Btc(btc::verifier::BtcVerifier),
}

#[async_trait]
#[enum_dispatch(AnyUnscriptedVerifier)]
pub trait UnscriptedVerifier: Send + Sync {
  // These `PhantomData`s are needed because enum_dispatch doesn't specify method type parameters (probably a bug)
  fn generate_keys_for_engine<OtherCrypt: CryptEngine>(&mut self, phantom: PhantomData<&OtherCrypt>) -> (Vec<u8>, OtherCrypt::PrivateKey);
  fn verify_dleq_for_engine<OtherCrypt: CryptEngine>(&mut self, dleq: &[u8], phantom: PhantomData<&OtherCrypt>) -> anyhow::Result<OtherCrypt::PublicKey>;

  async fn verify_and_wait_for_send(&mut self) -> anyhow::Result<()>;
  async fn finish<Host: ScriptedHost >(&mut self, host: &Host) -> anyhow::Result<()>;
}

#[enum_dispatch]
pub enum AnyUnscriptedVerifier {
  Meros(meros::verifier::MerosVerifier),
  Nano(nano::verifier::NanoVerifier),
}
