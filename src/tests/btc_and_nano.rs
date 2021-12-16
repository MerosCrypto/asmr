use std::{
  path::PathBuf,
  future::Future,
  time::Duration
};

use tokio::time::sleep;

use crate::{
  coins::{
    *,
    btc::{host::BtcHost, verifier::BtcVerifier},
    nano::{client::NanoClient, verifier::NanoVerifier}
  },
  tests::swap::{
    success::test_success,
    host::{
      no_address::test_no_host_address,
      never_funded_address::test_never_funded_address,
      funded_address_no_lock::test_funded_address_no_lock,
      funded_address_created_lock::test_funded_address_created_lock,
      published_lock::test_published_lock,
      attempted_refund_yet_success::test_attempted_refund_yet_success
    },
    client::{
      no_address::test_no_client_address,
      generated_address::test_generated_address,
      funded_get_unscripted::test_funded_get_unscripted,
      funded_get_scripted::test_funded_get_scripted
    }
  }
};

pub async fn run_test<F, Fut>(host_test: bool, test: F)
  where F: FnOnce(AnyScriptedHost, AnyUnscriptedVerifier, AnyUnscriptedClient, AnyScriptedVerifier) -> Fut,
    Fut: Future<Output = anyhow::Result<bool>>
{
  let scripted: PathBuf = "config/bitcoin.json".to_string().into();
  let unscripted: PathBuf = "config/nano.json".to_string().into();

  let mut host: AnyScriptedHost = BtcHost::new(&scripted).expect("Failed to create BTC host").into();
  host.override_refund_with_random_address();
  let host_refund = host.get_refund_address();
  let hosts_verifier: AnyUnscriptedVerifier = NanoVerifier::new(&unscripted).expect("Failed to create Nano verifier").into();

  let mut client: AnyUnscriptedClient = NanoClient::new(&unscripted).expect("Failed to create Nano client").into();
  client.override_refund_with_random_address();
  let client_refund = client.get_refund_address();
  let clients_verifier: AnyScriptedVerifier = BtcVerifier::new(&scripted).expect("Failed to create BTC verifier").into();

  let should_have_funds = test(host, hosts_verifier, client, clients_verifier).await.unwrap();
  if host_test {
    let host = BtcHost::new(&scripted).unwrap();
    host.advance_consensus().await.unwrap();
    assert_eq!(should_have_funds, host.get_if_funded(&host_refund).await);
  } else {
    let client = NanoClient::new(&unscripted).unwrap();
    sleep(Duration::from_secs(5)).await; // wait for the transaction to be confirmed
    assert_eq!(should_have_funds, client.get_if_funded(&client_refund).await);
  }
}

#[tokio::test]
pub async fn test_btc_and_nano() {
  let _ = env_logger::builder().is_test(true).try_init();
  run_test(true, test_success).await;

  run_test(true, test_no_host_address).await;
  run_test(true, test_never_funded_address).await;
  run_test(true, test_funded_address_no_lock).await;
  run_test(true, test_funded_address_created_lock).await;
  run_test(true, test_published_lock).await;
  run_test(true, test_attempted_refund_yet_success).await;

  run_test(false, test_no_client_address).await;
  run_test(false, test_generated_address).await;
  run_test(false, test_funded_get_unscripted).await;
  run_test(false, test_funded_get_scripted).await;
}
