use std::{
  marker::PhantomData,
  io::Write,
  path::Path,
  fs::File
};

use async_trait::async_trait;

use curve25519_dalek::{scalar::Scalar, edwards::CompressedEdwardsY};

use dleq::{DLEqProof, engines::{DLEqEngine, ed25519::Ed25519Engine}};

use crate::coins::{UnscriptedVerifier, ScriptedHost, xmr::engine::*};

pub struct XmrVerifier(XmrEngine);

impl XmrVerifier {
  pub async fn new(config_path: &Path) -> anyhow::Result<XmrVerifier> {
    Ok(
      XmrVerifier(
        XmrEngine::new(
          serde_json::from_reader(File::open(config_path)?)?
        ).await?
      )
    )
  }
}

#[async_trait]
impl UnscriptedVerifier for XmrVerifier {
  fn generate_keys_for_engine<OtherCrypt: DLEqEngine>(&mut self, _phantom: PhantomData<&OtherCrypt>) -> (Vec<u8>, OtherCrypt::PrivateKey) {
    let (proof, key1, key2) = DLEqProof::<Ed25519Engine, OtherCrypt>::new(&mut rand::rngs::OsRng);
    self.0.k = Some(key1);
    (
      bincode::serialize(
        &XmrKeys {
          dleq: proof.serialize().expect("Couldn't serialize a DLEq proof"),
          view_share: self.0.view.to_bytes()
        }
      ).expect("Couldn't serialize the unscripted keys"),
      key2
    )
  }

  /*
    Ironically, despite being designed to well-support a Monero protocol
    This wasn't designed with the second key needed for Monero transactions in mind
    We compensate by using an UnscriptedKeys struct, wrapping the proof
    verify_dleq should be renamed to verify_keys as it no longer just takes in the dl eq proof
  */
  fn verify_dleq_for_engine<OtherCrypt: DLEqEngine>(&mut self, dleq: &[u8], _: PhantomData<&OtherCrypt>) -> anyhow::Result<OtherCrypt::PublicKey> {
    let keys: XmrKeys = bincode::deserialize(dleq)?;
    let dleq = DLEqProof::<OtherCrypt, Ed25519Engine>::deserialize(&keys.dleq)?;
    let (key1, key2) = dleq.verify()?;
    self.0.view += Scalar::from_bytes_mod_order(keys.view_share);
    self.0.set_spend(key2);
    Ok(key1)
  }

  async fn verify_and_wait_for_send(&mut self) -> anyhow::Result<()> {
    let pair = self.0.get_view_pair();
    let send = self.0.get_deposit(&pair, true).await?.unwrap();

    // Verify metadata
    if (send.prefix.version.0 != 2) || (send.prefix.unlock_time.0 != 0) {
      anyhow::bail!("Invalid version/unlock time");
    }

    // Calls unwrap due to get_deposit already validating this
    let outputs = send.check_outputs(&pair, 0..1, 0..1).unwrap();

    // Decrypt the amount, verify the accuracy of the commitment, and confirm with the user
    let amount = send.rct_signatures.sig.as_ref().expect("Transaction from RPC didn't have signature data")
      .ecdh_info[outputs[0].index()].open_commitment(
        &pair,
        &outputs[0].tx_pubkey(),
        outputs[0].index(),
        &CompressedEdwardsY(
          send.rct_signatures.sig.as_ref().unwrap().out_pk[outputs[0].index()].mask.key
        ).decompress().ok_or(anyhow::anyhow!("Invalid point for commitment"))?
      ).ok_or(anyhow::anyhow!("Invalid commitment"))?.amount;

    if !cfg!(test) {
      print!("You will receive {} atomic units of XMR. Continue (yes/no)? ", amount);
      std::io::stdout().flush().expect("Failed to flush stdout");
      let mut line = String::new();
      std::io::stdin().read_line(&mut line).expect("Couldn't read from stdin");
      if !line.to_lowercase().starts_with("y") {
        anyhow::bail!("User didn't confirm XMR amount");
      }
    }

    Ok(())
  }

  async fn finish<Host: ScriptedHost>(&mut self, host: &Host) -> anyhow::Result<()> {
    self.0.claim(
      Scalar::from_bytes_mod_order(host.recover_final_key().await?),
      &self.0.config.destination
    ).await
  }
}
