use std::{
  marker::PhantomData,
  convert::TryInto,
  io::Write,
  path::Path,
  fs::File
};

use async_trait::async_trait;

use curve25519_dalek::scalar::Scalar;

use monero::{
  util::{
    key::{PrivateKey, PublicKey, ViewPair},
    ringct::EcdhInfo
  },
  cryptonote::hash::Hash
};

use crate::{
  crypt_engines::{CryptEngine, ed25519_engine::Ed25519Sha},
  dl_eq::DlEqProof,
  coins::{
    UnscriptedVerifier, ScriptedHost,
    xmr::engine::*,
    xmr::rpc::XmrRpc
  }
};

pub struct XmrVerifier {
  engine: XmrEngine,
  rpc: XmrRpc
}

impl XmrVerifier {
  pub async fn new(config_path: &Path) -> anyhow::Result<XmrVerifier> {
    let config = serde_json::from_reader(File::open(config_path)?)?;
    Ok(
      XmrVerifier {
        engine: XmrEngine::new(),
        rpc: XmrRpc::new(&config).await?
      }
    )
  }
}

#[async_trait]
impl UnscriptedVerifier for XmrVerifier {
  fn generate_keys_for_engine<OtherCrypt: CryptEngine>(&mut self, phantom: PhantomData<&OtherCrypt>) -> (Vec<u8>, OtherCrypt::PrivateKey) {
    let (proof, key1, key2) = DlEqProof::<Ed25519Sha, OtherCrypt>::new();
    self.engine.k = Some(key1);
    (
      bincode::serialize(
        &XmrKeys {
          dl_eq: proof.serialize(),
          view_share: Ed25519Sha::private_key_to_bytes(&self.engine.view)
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
  fn verify_dleq_for_engine<OtherCrypt: CryptEngine>(&mut self, dleq: &[u8], _: PhantomData<&OtherCrypt>) -> anyhow::Result<OtherCrypt::PublicKey> {
    let keys: XmrKeys = bincode::deserialize(dleq)?;
    let dleq = DlEqProof::<OtherCrypt, Ed25519Sha>::deserialize(&keys.dl_eq)?;
    let (key1, key2) = dleq.verify()?;
    self.engine.view += Ed25519Sha::bytes_to_private_key(keys.view_share)?;
    self.engine.set_spend(key2);
    Ok(key1)
  }

  async fn verify_and_wait_for_send(&mut self) -> anyhow::Result<()> {
    let mut last_handled_block = self.rpc.height_at_start - 1;
    let view_pair = ViewPair {
      spend: PublicKey {
        point: self.engine.spend.expect("Waiting for transaction before verifying DLEQ proof").compress()
      },
      view: PrivateKey::from_scalar(self.engine.view)
    };

    // Find the send
    let send;
    'outer: loop {
      while self.rpc.get_height().await > last_handled_block {
        for tx in self.rpc.get_transactions_in_block(last_handled_block).await {
          if tx.prefix.check_outputs(&view_pair, 0..1, 0..1).is_err() {
            continue
          }
          send = tx;
          break 'outer;
        }
        last_handled_block += 1;
      }
      tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
    }

    // Verify metadata
    if (send.prefix.version.0 != 2) || (send.prefix.unlock_time.0 != 0) {
      anyhow::bail!("Invalid version/unlock time");
    }

    let outputs = send.prefix.check_outputs(&view_pair, 0..1, 0..1).unwrap();

    // Decrypt the amount, verify the accuracy of the commitment, and confirm with the user
    let enc_amount;
    if let EcdhInfo::Bulletproof2 { amount } = send.rct_signatures.sig.as_ref().expect("Transaction from RPC didn't have signature data").ecdh_info[outputs[0].index] {
      enc_amount = u64::from_le_bytes(amount.to_fixed_bytes());
    } else {
      anyhow::bail!("Unrecognized transaction type");
    }
  
    let amount_key;
    if let Some(uncompressed) = outputs[0].tx_pubkey.point.decompress() {
      amount_key = self.engine.view * uncompressed;
    } else {
      anyhow::bail!("Invalid key used in transaction");
    }
    amount_key.mul_by_cofactor();
    let amount_key = Scalar::from_bytes_mod_order(
      Hash::hash(&amount_key.compress().to_bytes()).to_fixed_bytes()
    ).to_bytes();
  
    let mut amount_enc_key = "amount".as_bytes().to_vec();
    amount_enc_key.extend(&amount_key);

    let amount = u64::from_le_bytes(
      Hash::hash(&amount_enc_key).to_fixed_bytes()[0 .. 8].try_into().unwrap()
    ) ^ enc_amount;

    let mut commitment_key = "commitment_mask".as_bytes().to_vec();
    commitment_key.extend(&amount_key);
    let commitment_key = Scalar::from_bytes_mod_order(
      Hash::hash(&commitment_key).to_fixed_bytes()
    );
    if (
      Ed25519Sha::to_public_key(&commitment_key) +
      (*C * Scalar::from(amount))
    ) != Ed25519Sha::bytes_to_public_key(
      &send.rct_signatures.sig.as_ref().unwrap().out_pk[outputs[0].index].mask.key
    )? {
      anyhow::bail!("Invalid commitment")
    }

    if !cfg!(test) {
      print!("You will receive {} XMR. Continue (yes/no)? ", amount);
      std::io::stdout().flush().expect("Failed to flush stdout");
      let mut line = String::new();
      std::io::stdin().read_line(&mut line).expect("Couldn't read from stdin");
      if !line.to_lowercase().starts_with("y") {
        anyhow::bail!("User didn't confirm XMR amount");
      }
    }

    Ok(())
  }

  async fn finish<Host: ScriptedHost >(&mut self, host: &Host) -> anyhow::Result<()> {
    println!("View key:            {}", hex::encode(self.engine.view.as_bytes()));
    println!("Recovered spend key: {}", hex::encode(host.recover_final_key().await?));
    Ok(())
  }
}
