use crate::{
  crypt_engines::{CryptEngine, jubjub_engine::JubjubEngine},
  coins::zec::engine::{ZecConfig, ZecEngine}
};

#[tokio::test]
async fn receive_funds() -> anyhow::Result<()> {
  let mut engine = ZecEngine::new(ZecConfig {
    url: "http://user:pass@127.0.0.1:18232".to_string(),
    destination: "".to_string(),
    refund: "".to_string()
  }).await?;

  let other_ask = JubjubEngine::new_private_key();
  let other_nsk = JubjubEngine::new_private_key();

  engine.ask = Some(JubjubEngine::new_private_key());
  engine.set_ak_nsk(&JubjubEngine::to_public_key(&other_ask), &other_nsk);
  let vk = engine.vk.clone().expect("ViewingKey wasn't created despite setting the other ak/nsk");
  assert!(engine.get_deposit(&vk, false).await?.is_none());
  engine.send_from_wallet().await?;
  assert!(engine.get_deposit(&vk, false).await?.is_some());
  Ok(())
}

#[tokio::test]
async fn send_funds() -> anyhow::Result<()> {
  // Copied from the above test to get a funded engine
  let mut engine = ZecEngine::new(ZecConfig {
    url: "http://user:pass@127.0.0.1:18232".to_string(),
    destination: "".to_string(),
    refund: "".to_string()
  }).await?;

  let other_ask = JubjubEngine::new_private_key();
  let other_nsk = JubjubEngine::new_private_key();

  engine.ask = Some(JubjubEngine::new_private_key());
  engine.set_ak_nsk(&JubjubEngine::to_public_key(&other_ask), &other_nsk);
  let vk = engine.vk.clone().expect("ViewingKey wasn't created despite setting the other ak/nsk");
  engine.send_from_wallet().await?;
  let value = engine.get_deposit(&vk, false).await?;
  assert!(value.is_some());

  // Now the trick is spending our funds. This is done by creating ANOTHER engine which will receive the funds
  let mut recipient = ZecEngine::new(ZecConfig {
    url: "http://user:pass@127.0.0.1:18232".to_string(),
    destination: "".to_string(),
    refund: "".to_string()
  }).await?;
  recipient.ask = Some(JubjubEngine::new_private_key());
  recipient.set_ak_nsk(
    &JubjubEngine::to_public_key(&JubjubEngine::new_private_key()),
    &JubjubEngine::new_private_key()
  );

  // Address to send to
  let address = recipient.get_deposit_address();

  // Send the funds
  engine.claim(other_ask, &address).await?;
  engine.mine_block().await?;

  // Verify we were sent to
  let vk = recipient.vk.clone().expect("ViewingKey wasn't created despite setting the other ak/nsk");
  assert!(recipient.get_deposit(&vk, false).await?.is_some());

  Ok(())
}
