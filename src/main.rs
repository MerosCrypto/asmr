#![deny(unused_must_use)]

mod crypt_engines;
mod coins;
mod cli;
mod dl_eq;

#[cfg(test)]
mod tests;

use std::{panic, time::Duration};

use anyhow::Context;
use log::{error, info};
use structopt::StructOpt;

use futures::prelude::*;
use tokio::{
  prelude::*,
  time::timeout,
  net::{TcpStream, TcpListener}
};

use crate::{
  coins::{
    *,
    btc::{host::BtcHost, verifier::BtcVerifier},
    meros::{client::MerosClient, verifier::MerosVerifier},
    nano::{client::NanoClient, verifier::NanoVerifier}
  },
  cli::{ScriptedCoin, UnscriptedCoin, Cli}
};

const MAGIC: &[u8] = b"ASMR";
const MAGIC_RESPONSE: &[u8] = b"ConfirmASMR";
const MAX_ITEM_LENGTH: u32 = 256 * 1024; // 256 KB. The largest transmitted data is the DL EQ Proof which is still less than this
const TIMEOUT: Duration = Duration::from_secs(60 * 60); // 1 hour

#[tokio::main]
async fn main() {
  env_logger::init();

  let opts = Cli::from_args();
  let scripted_config = opts.scripted_config.clone()
    .unwrap_or_else(|| format!("config/{:?}.json", opts.pair.scripted).to_lowercase().into());
  let unscripted_config = opts.unscripted_config.clone()
    .unwrap_or_else(|| format!("config/{:?}.json", opts.pair.unscripted).to_lowercase().into());

  let mut listen_handle = None;
  if opts.host_or_client.is_host() {
    let mut scripted_host: AnyScriptedHost = match opts.pair.scripted {
      ScriptedCoin::Bitcoin => BtcHost::new(&scripted_config).map(Into::into),
    }.expect("Failed to create scripted host");
    let mut unscripted_verifier: AnyUnscriptedVerifier = match opts.pair.unscripted {
      UnscriptedCoin::Meros => MerosVerifier::new(&unscripted_config).map(Into::into),
      UnscriptedCoin::Nano => NanoVerifier::new(&unscripted_config).map(Into::into),
    }.expect("Failed to create unscripted verifier");

    // Have the host also host the server socket
    // As this is a proof of concept, this is a valid simplification
    // It simply removes the need to add another config flag/switch
    let opts = opts.clone();
    listen_handle = Some(tokio::spawn(async move {
      let mut listener = TcpListener::bind(opts.tcp_address).await
        .expect("Failed to create TCP listener");
      info!("Listening as host on {}", opts.tcp_address);
      let (stream, addr) = listener.accept().await
        .expect("Failed to accept incoming TCP connection");
      info!("Got connection from {}", addr);

      let swap_fut = panic::AssertUnwindSafe(host(
        opts,
        stream,
        &mut scripted_host,
        &mut unscripted_verifier
      )).catch_unwind();
      let swap_res = timeout(TIMEOUT, swap_fut).await;
      let attempt_refund = match swap_res {
        // Timeout
        Err(_) => {
          error!("Host swap timed out");
          true
        }
        // Panic occurred
        Ok(Err(_)) => true,
        // Normal error
        Ok(Ok(Err(err))) => {
          error!("Error attempting host swap: {:?}", err);
          true
        },
        // Success
        Ok(Ok(Ok(()))) => false,
      };
      if attempt_refund {
        scripted_host.refund(unscripted_verifier).await.expect("Couldn't call refund");
      }
    }));
  }

  if opts.host_or_client.is_client() {
    let mut unscripted_client: AnyUnscriptedClient = match opts.pair.unscripted {
      UnscriptedCoin::Meros => MerosClient::new(&unscripted_config).map(Into::into),
      UnscriptedCoin::Nano => NanoClient::new(&unscripted_config).map(Into::into),
    }.expect("Failed to create unscripted client");
    let mut scripted_verifier: AnyScriptedVerifier = match opts.pair.scripted {
      ScriptedCoin::Bitcoin => BtcVerifier::new(&scripted_config).map(Into::into),
    }.expect("Failed to create scripted verifier");

    let stream = TcpStream::connect(opts.tcp_address).await.expect("Failed to connect to host");
    let swap_fut = panic::AssertUnwindSafe(client(
      opts,
      stream,
      &mut unscripted_client,
      &mut scripted_verifier
    )).catch_unwind();
    let swap_res = timeout(TIMEOUT, swap_fut).await;
    let attempt_refund = match swap_res {
      // Timeout
      Err(_) => {
        error!("Client swap timed out");
        true
      }
      // Panic occurred
      Ok(Err(_)) => true,
      // Normal error
      Ok(Ok(Err(err))) => {
        error!("Error attempting client swap: {:?}", err);
        true
      },
      // Success
      Ok(Ok(Ok(()))) => false,
    };
    if attempt_refund {
      unscripted_client.refund(scripted_verifier).await.expect("Couldn't call refund");
    }
  }

  if let Some(listen_handle) = listen_handle {
    listen_handle.await.expect("Swap host panicked");
  }
}

async fn write(stream: &mut TcpStream, value: &[u8]) -> anyhow::Result<()> {
  let len = value.len() as u32;
  assert!(len <= MAX_ITEM_LENGTH);
  let len = len.to_le_bytes();
  stream.write_all(&len).await?;
  stream.write_all(value).await?;
  Ok(())
}

async fn read(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
  let mut len_buf = [0u8; 4];
  stream.read_exact(&mut len_buf).await?;
  let len = u32::from_le_bytes(len_buf);
  if len > MAX_ITEM_LENGTH {
    panic!("Attempted to read {} byte item, longer than maximum", len);
  }
  let mut buf = vec![0u8; len as usize];
  stream.read_exact(&mut buf).await?;
  Ok(buf)
}

async fn host(opts: Cli, mut stream: TcpStream, host: &mut AnyScriptedHost, verifier: &mut AnyUnscriptedVerifier) -> anyhow::Result<()> {
  // Verify the protocol using magic bytes
  stream.write_all(MAGIC).await.context("Failed to write magic bytes")?;
  write(&mut stream, opts.pair.to_string().as_bytes()).await.context("Failed to write pair name to socket")?;
  let mut magic = [0u8; MAGIC_RESPONSE.len()];
  stream.read_exact(&mut magic).await.context("Failed to read magic bytes")?;
  anyhow::ensure!(magic == MAGIC_RESPONSE, "Bad magic bytes - is the client an ASMR instance?");

  // Send over our keys
  // Namely the DL EQ proof, scripted lock/refund keys, and scripted destination key
  write(&mut stream, &host.generate_keys(verifier)).await?;

  // Read and verify the keys
  host.verify_keys(&read(&mut stream).await?, verifier).context("Couldn't verify client DlEq proof")?;

  // Have funds enter the system
  // We use our own intermediate address to ensure the transaction isn't malleable, a problem with BTC solved via SegWit
  println!("Send to {} and this will automatically proceed when funds are confirmed.", host.generate_deposit_address());

  /*
    Now that we've exchanged the relevant keys, it's time to start on the transactions
    The host is supposed to create the lock, the refund, and the spend, signing the refund

    Then, the whitepaper says to transmit all three, so the client can verify everything
    That said, the client can't properly verify the lock
    They'd need to verify its inputs exist and are correct, have the correct script, and has a valid signature
    If the client can properly verify this transaction chain, they can publish the lock
    If the client can publish the lock, before the host has their refund signature, the client can lose nothing while causing the host to lose everything

    To solve this problem, the client has to wait to verify the lock
    That said, they only need the lock at this time to sign the refund/spend transaction for the host
    They can do this solely knowing the lock's transaction ID
    Since they generate new keys, they can blindly trust the provided TX ID, as there's no risk of being tricked into signing over our own funds
    While we could have the client do a partial verification of the lock now, they'd still have to verify it again later
    As of right now, there's no security risk in putting this off

    If we want to remove the risk of having the client sign over their own funds, in case they do have other funds
    We can have them receive the lock transaction, do a partial verification, and recalculate the ID
    Since they never sign the lock itself, even if the lock spends their funds, they'll be secure

    It should also be noted the refund and spend don't need to be transmitted
    Their only meaningful info is the keys used for them, which was included in the above key transmission
    That said, the refund signature does still need to be transmitted
  */
  write(&mut stream, &host.create_lock_and_prepare_refund().await.context("Couldn't create the BTC lock")?).await?;

  // Next, we have to receive the client's signature for the refund
  // As well as the client's encrypted signature for our claim of the refund
  host.verify_refund_and_spend(&read(&mut stream).await?)?;

  // Once we have our failure path secured, we publish the lock and move on
  host.publish_lock().await.context("Couldn't publish the lock")?;

  // In order for the client to be able to now purchase from our lock, we need to prepare buy transaction for them
  // This is sent over with an encrypted signature so when they publish the decrypted version, we learn their key
  write(&mut stream, &host.prepare_buy_for_client().await.context("Couldn't prepare the buy")?).await?;

  // Now, we wait for the unscripted send to appear
  verifier.verify_and_wait_for_send().await.context("Couldn't verify and wait for the unscripted send")?;

  // Now that we've verified both transactions are on their networks and confirmed, we transmit the swap secret
  write(&mut stream, &host.swap_secret()).await?;

  // Finally, we watch for the client to buy from the lock
  // Then we can recover the key and claim the other coin
  verifier.finish(host).await.context("Couldn't finish buying the unscripted coin")?;
  Ok(())
}

async fn client(opts: Cli, mut stream: TcpStream, client: &mut AnyUnscriptedClient, verifier: &mut AnyScriptedVerifier) -> anyhow::Result<()> {
  // The majority of comments explaining this protocol and this implementation is in the host function
  // The comments here are meant to explain the client-specific side of things

  let mut magic = [0u8; MAGIC.len()];
  stream.read_exact(&mut magic).await.context("Failed to read magic bytes")?;
  anyhow::ensure!(magic == MAGIC, "Bad magic bytes - is the host an ASMR instance?");
  let remote_pair = read(&mut stream).await?;
  if remote_pair != opts.pair.to_string().as_bytes() {
    anyhow::bail!("The host is attempting to exchange a different pair");
  }
  stream.write_all(MAGIC_RESPONSE).await.context("Failed to write magic bytes")?;

  write(&mut stream, &client.generate_keys(verifier)).await?;
  client.verify_keys(&read(&mut stream).await?, verifier).context("Couldn't verify host DlEq proof")?;

  // Receive the host's refund signature and send back our own
  // Also offer them a way to claim the refund transaction if our side cancels/errors
  let refund_and_spend_signatures = verifier.complete_refund_and_prepare_spend(
    &read(&mut stream).await?
  ).await.context("Couldn't complete the refund transaction")?;
  write(&mut stream, &refund_and_spend_signatures).await?;

  // Receive info about the buy transaction we will end up publishing
  // Namely, the host's signature, which we'll use to verify the buy and make sure we should continue
  verifier.verify_prepared_buy(&read(&mut stream).await?)?;

  /*
    We now need to finally verify the lock, as well as start tracking it
    We can get the lock via two methods
    A) Checking the spendable outputs for the lock script's address (via P2WSH in the case of BTC)
    B) Being transmitted its TX ID
    The first is preferred due it lowering the amount of data transferred between the two parties
  */
  verifier.verify_and_wait_for_lock().await.context("Couldn't verify the lock")?;

  // Now that the lock is on chain and we have everything we need to buy its funds, we need to publish our transaction
  println!("Send to {} and this will automatically proceed when funds are confirmed.", client.get_address());
  client.wait_for_deposit().await?;

  // Now, receive the swap secret and finish buying the funds locked by the host
  verifier.finish(&read(&mut stream).await?).await.context("Couldn't finishing buying the scripted coin")?;

  Ok(())
}
