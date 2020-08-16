use anyhow::Context;

use crate::coins::*;

pub async fn test_published_lock(
  mut host: AnyScriptedHost,
  mut hosts_verifier: AnyUnscriptedVerifier,
  mut client: AnyUnscriptedClient,
  mut clients_verifier: AnyScriptedVerifier
) -> anyhow::Result<bool> {
  let host_keys = host.generate_keys(&mut hosts_verifier);
  let client_keys = client.generate_keys(&mut clients_verifier);
  host.verify_keys(&client_keys, &mut hosts_verifier).context("Couldn't verify client DlEq proof")?;
  client.verify_keys(&host_keys, &mut clients_verifier).context("Couldn't verify host DlEq proof")?;

  let _ = host.generate_deposit_address();
  host.send_from_node().await?;
  host.advance_consensus().await?;

  let refund_and_spend = clients_verifier.complete_refund_and_prepare_spend(
    &host.create_lock_and_prepare_refund().await.context("Couldn't create the BTC lock")?
  ).await.context("Couldn't complete the refund transaction")?;
  host.verify_refund_and_spend(&refund_and_spend)?;
  host.publish_lock().await.context("Couldn't publish the lock")?;
  // 1 to get on the chain, 6 to beat the timelock
  for _ in 0 .. 7 {
    host.advance_consensus().await?;
  }
  host.refund(hosts_verifier).await?;
  
  Ok(true)
}
