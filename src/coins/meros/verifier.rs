use std::{
  marker::PhantomData,
  io::Write,
  path::Path,
  fs::File
};

use async_trait::async_trait;

use crate::{
  crypt_engines::{CryptEngine, ed25519_engine::Ed25519Sha},
  dl_eq::DlEqProof,
  coins::{
    UnscriptedVerifier, ScriptedHost,
    meros::{
      transaction::{Input, Transaction},
      engine::MerosEngine,
      rpc::MerosRpc
    }
  }
};

pub struct MerosVerifier {
  engine: MerosEngine,
  rpc: MerosRpc,
  destination_key: Vec<u8>,

  shared_key: Option<<Ed25519Sha as CryptEngine>::PublicKey>,
  utxos: Option<Vec<Input>>,
  value_sum: Option<u64>
}

impl MerosVerifier {
  pub fn new(config_path: &Path) -> anyhow::Result<MerosVerifier> {
    let config = serde_json::from_reader(File::open(config_path)?)?;

    Ok(MerosVerifier {
      engine: MerosEngine::new(),
      rpc: MerosRpc::new(&config)?,
      destination_key: MerosEngine::decode_address(&config.destination)?,

      shared_key: None,
      utxos: None,
      value_sum: None
    })
  }
}

#[async_trait]
impl UnscriptedVerifier for MerosVerifier {
  fn generate_keys_for_engine<OtherCrypt: CryptEngine>(&mut self, _: PhantomData<&OtherCrypt>) -> (Vec<u8>, OtherCrypt::PrivateKey) {
    let (proof, key1, key2) = DlEqProof::<Ed25519Sha, OtherCrypt>::new();
    self.engine.k = Some(key1);
    self.shared_key = Some(Ed25519Sha::to_public_key(&key1));
    (proof.serialize(), key2)
  }

  fn verify_dleq_for_engine<OtherCrypt: CryptEngine>(&mut self, dleq: &[u8], _: PhantomData<&OtherCrypt>) -> anyhow::Result<OtherCrypt::PublicKey> {
    let dleq = DlEqProof::<OtherCrypt, Ed25519Sha>::deserialize(dleq)?;
    let (key1, key2) = dleq.verify()?;
    self.shared_key = Some(self.shared_key.expect("Verifying DLEQ proof before generating keys") + key2);
    Ok(key1)
  }

  async fn verify_and_wait_for_send(&mut self) -> anyhow::Result<()> {
    let address = MerosEngine::get_address(
      &Ed25519Sha::public_key_to_bytes(
        self.shared_key.as_ref().expect("Waiting for send before verifying the other's DLEQ proof")
      )
    );

    /*
      Considering Meros transactions are directly to public keys, there's not actually anything to verify
      There's no timelocks or alternate spending paths
      The node will only track the transaction if it's viable, including having a valid signature
      We do need to make the transaction was verified, yet Meros's getUTXOs route already has that premise
      That said, Meros also isn't at mainnet and subject to changes, so it's best to be extremely secure here
    */

    let mut result = Vec::new();
    let mut value_sum = 0;
    let mut done = false;
    while !done {
      result = Vec::new();
      value_sum = 0;
      done = true;

      for input in self.rpc.get_utxos(address.clone()).await {
        // Verify the UTXO is confirmed
        // We don't need to check if it's spent since we have half of the key and it therefore can't be spent without us
        if !self.rpc.get_confirmed(input.hash.clone()).await? {
          done = false;
          break;
        }
        value_sum += self.rpc.get_transaction_output_value(input.clone()).await?;
        result.push(input);
      }

      // Don't immediately run the next loop iteration
      done = done && (result.len() != 0);
      if !done {
        tokio::time::delay_for(std::time::Duration::from_secs(5)).await;
      }
    }
    self.value_sum = Some(value_sum);
    self.utxos = Some(result);

    if !cfg!(test) {
      print!("You will receive {} MR. Continue (yes/no)? ", value_sum);
      std::io::stdout().flush().expect("Failed to flush stdout");
      let mut line = String::new();
      std::io::stdin().read_line(&mut line).expect("Couldn't read from stdin");
      if !line.to_lowercase().starts_with("y") {
        anyhow::bail!("User didn't confirm MR amount");
      }
    }
    Ok(())
  }

  async fn finish<Host: ScriptedHost>(&mut self, host: &Host) -> anyhow::Result<()> {
    let send = MerosEngine::create_send(
      Ed25519Sha::little_endian_bytes_to_private_key(host.recover_final_key().await?)?,
      self.engine.k.expect("Finishing before generating keys"),
      self.utxos.clone().expect("Finishing before knowing of the UTXOs"),
      self.destination_key.clone(),
      self.value_sum.expect("Finishing before knowing of the amount"),
      self.rpc.get_send_difficulty().await
    );
    self.rpc.publish_send(send.serialize()).await?;
    Ok(())
  }
}
