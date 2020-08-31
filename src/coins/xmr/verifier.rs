use std::{
  marker::PhantomData,
  convert::TryInto,
  io::Write,
  path::Path,
  fs::File
};

use async_trait::async_trait;
use hex;

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
  rpc: XmrRpc,
  amount: Option<u64>
}

impl XmrVerifier {
  pub async fn new(config_path: &Path) -> anyhow::Result<XmrVerifier> {
    let config = serde_json::from_reader(File::open(config_path)?)?;
    Ok(
      XmrVerifier {
        engine: XmrEngine::new(),
        rpc: XmrRpc::new(&config).await?,
        amount: None
      }
    )
  }
}

#[async_trait]
impl UnscriptedVerifier for XmrVerifier {
  fn generate_keys_for_engine<OtherCrypt: CryptEngine>(&mut self, _phantom: PhantomData<&OtherCrypt>) -> (Vec<u8>, OtherCrypt::PrivateKey) {
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
    let pair = ViewPair {
      spend: PublicKey {
        point: self.engine.spend.expect("Waiting for transaction before verifying DLEQ proof").compress()
      },
      view: PrivateKey::from_scalar(self.engine.view)
    };
    let send = self.rpc.wait_for_deposit(&pair).await?;

    // Verify metadata
    if (send.prefix.version.0 != 2) || (send.prefix.unlock_time.0 != 0) {
      anyhow::bail!("Invalid version/unlock time");
    }

    let outputs = send.prefix.check_outputs(&pair, 0..1, 0..1).unwrap();

    // Decrypt the amount, verify the accuracy of the commitment, and confirm with the user
    let enc_amount;
    if let EcdhInfo::Bulletproof2 { amount } = send.rct_signatures.sig.as_ref().expect("Transaction from RPC didn't have signature data").ecdh_info[outputs[0].index] {
      enc_amount = u64::from_le_bytes(amount.to_fixed_bytes());
    } else {
      anyhow::bail!("Unrecognized transaction type");
    }

    let mut amount_key;
    if let Some(uncompressed) = outputs[0].tx_pubkey.point.decompress() {
      amount_key = self.engine.view * uncompressed;
    } else {
      anyhow::bail!("Invalid key used in transaction");
    }
    amount_key = amount_key.mul_by_cofactor();
    let mut to_hash = amount_key.compress().to_bytes().to_vec();
    // TODO: Handle this edge case
    if outputs[0].index > 127 {
      anyhow::bail!("Transaction output uses VarInt encoding which isn't supported")
    }
    to_hash.push(outputs[0].index as u8);
    let amount_key = Scalar::from_bytes_mod_order(
      Hash::hash(&to_hash).to_bytes()
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
      print!("You will receive {} atomic units of XMR. Continue (yes/no)? ", amount);
      std::io::stdout().flush().expect("Failed to flush stdout");
      let mut line = String::new();
      std::io::stdin().read_line(&mut line).expect("Couldn't read from stdin");
      if !line.to_lowercase().starts_with("y") {
        anyhow::bail!("User didn't confirm XMR amount");
      }
    }
    self.amount = Some(amount);

    Ok(())
  }

  async fn finish<Host: ScriptedHost >(&mut self, host: &Host) -> anyhow::Result<()> {
    self.rpc.claim(
      (
        Ed25519Sha::little_endian_bytes_to_private_key(host.recover_final_key().await?)? +
        self.engine.k.expect("Finishing before generating keys")
      ),
      self.engine.view,
      // TODO: Use the actual destination address
      "42L9GkQeerChpA4rz4MTagL5mBGbEnvPzWLRL5vfJTr3bd8Diz6okcpd9vkxerLXHADdPMbTW9Xk8JcWj8WbeGEmD3aKdsi",
      self.amount.expect("Finishing before verifying the XMR send")
    ).await
  }
}
