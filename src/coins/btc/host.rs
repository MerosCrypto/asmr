use std::{
  marker::PhantomData,
  path::Path,
  fs::File
};

use async_trait::async_trait;
use hex_literal::hex;
use rand::{rngs::OsRng, RngCore};
use digest::Digest;

use secp256kfun::{marker::*, Scalar, Point, G, g};
use dleq::engines::secp256kfun::Secp256k1Engine;

use bitcoin::{
  secp256k1,
  hashes::hex::FromHex, hash_types::Txid,
  blockdata::{script::Script, transaction::{OutPoint, TxIn, TxOut, Transaction, SigHashType}},
  util::{address::Address, bip143::SigHashCache},
  consensus::serialize
};

use crate::{
  crypto::{KeyBundle, secp256k1::*},
  coins::{
    ScriptedHost, UnscriptedVerifier,
    btc::{engine::*, rpc::*}
  }
};

pub struct BtcHost {
  engine: BtcEngine,
  rpc: BtcRpc,
  #[cfg(test)]
  refund_pubkey: Option<bitcoin::util::key::PublicKey>,
  refund_pubkey_script: Script,
  address: Option<(Scalar, String, [u8; 20])>,

  swap_secret: [u8; 32],
  swap_hash: Vec<u8>,

  lock: Option<Transaction>,
  lock_height: Option<isize>,

  refund: Option<Transaction>,
  spend: Option<Transaction>,
  refund_script: Option<Script>,
  refund_message: Option<secp256k1::Message>,
  refund_signature: Option<Vec<u8>>,
  spend_message: Option<Vec<u8>>,
  encrypted_spend_signature: Option<EncryptedSignature>,

  client: Option<Vec<u8>>,
  client_refund: Option<Vec<u8>>,
  client_destination_script: Option<Script>,

  encryption_key: Option<Point>,
  encrypted_signature: Option<EncryptedSignature>,
  buy: Option<Txid>
}

impl BtcHost {
  pub fn new(config_path: &Path) -> anyhow::Result<BtcHost> {
    let config = serde_json::from_reader(File::open(config_path)?)?;

    let mut swap_secret = [0; 32];
    OsRng.fill_bytes(&mut swap_secret);
    Ok(BtcHost {
      engine: BtcEngine::new(),
      rpc: BtcRpc::new(&config)?,
      #[cfg(test)]
      refund_pubkey: None,
      refund_pubkey_script: BtcEngine::decode_address(&config.refund)?,
      address: None,

      swap_secret,
      swap_hash: sha2::Sha256::digest(&swap_secret).to_vec(),

      lock: None,
      lock_height: None,

      refund: None,
      spend: None,
      refund_script: None,
      refund_message: None,
      refund_signature: None,
      spend_message: None,
      encrypted_spend_signature: None,

      client: None,
      client_refund: None,
      client_destination_script: None,

      encryption_key: None,
      encrypted_signature: None,
      buy: None
    })
  }

  async fn prepare_refund_and_spend(&mut self, lock_id: Txid, lock_value: u64) -> anyhow::Result<(u64, Vec<u8>)> {
    let fee_per_byte = self.rpc.get_fee_per_byte().await?;
    let (refund_script, refund, refund_message, sig) = self.engine.prepare_and_sign_refund(
      lock_id,
      true,
      self.client_refund.as_ref().expect("Creating refund before verifying keys"),
      self.client.as_ref().expect("Creating refund before verifying keys"),
      lock_value,
      fee_per_byte
    )?;

    let spend = BtcEngine::prepare_spend(
      refund.txid(),
      self.refund_pubkey_script.clone(),
      refund.output[0].value,
      fee_per_byte
    )?;
    let mut components = SigHashCache::new(&spend);
    self.spend_message = Some(
      components.signature_hash(
        0,
        &Script::from(self.engine.refund_script_bytes.clone().expect("Creating spend before refund script")),
        refund.output[0].value,
        SigHashType::All
      ).to_vec()
    );

    self.refund_script = Some(refund_script);
    self.refund = Some(refund);
    self.refund_message = Some(refund_message);
    self.refund_signature = Some(sig.clone());
    self.spend = Some(spend);

    Ok((fee_per_byte, sig))
  }
}

#[async_trait]
impl ScriptedHost for BtcHost {
  fn generate_keys<Verifier: UnscriptedVerifier>(&mut self, verifier: &mut Verifier) -> Vec<u8> {
    let (dleq, key) = verifier.generate_keys_for_engine::<Secp256k1Engine>(PhantomData);
    self.engine.bs = Some(key);
    KeyBundle {
      dleq,
      B: g!(self.engine.b * G).mark::<Normal>().to_bytes().to_vec(),
      BR: g!(self.engine.br * G).mark::<Normal>().to_bytes().to_vec(),
      scripted_destination: self.refund_pubkey_script.to_bytes()
    }.serialize()
  }

  fn verify_keys<Verifier: UnscriptedVerifier>(&mut self, keys: &[u8], verifier: &mut Verifier) -> anyhow::Result<()> {
    let keys = KeyBundle::deserialize(keys)?;
    let key = verifier.verify_dleq_for_engine::<Secp256k1Engine>(&keys.dleq, PhantomData)?;
    if (keys.B.len() != 33) || (keys.BR.len() != 33) {
      anyhow::bail!("Keys have an invalid length");
    }
    self.client = Some(keys.B);
    self.client_refund = Some(keys.BR);
    self.encryption_key = Some(key);
    self.client_destination_script = Some(Script::from(keys.scripted_destination));
    Ok(())
  }

  fn swap_secret(&self) -> [u8; 32] {
    self.swap_secret
  }

  fn generate_deposit_address(&mut self) -> String {
    let address = BtcEngine::generate_deposit_address();
    self.address = Some(address.clone());
    address.1.to_string()
  }

  async fn create_lock_and_prepare_refund(
    &mut self
  ) -> anyhow::Result<Vec<u8>> {
    let client = self.client.as_ref().expect("Creating lock before verifying keys");
    let client_refund = self.client_refund.as_ref().expect("Creating lock before verifying keys");

    let address = self.address.clone().expect("Creating lock before creating address");
    let mut inputs_to_use = self.rpc.get_spendable(&address.1).await?;
    while inputs_to_use.len() == 0 {
      tokio::time::sleep(std::time::Duration::from_secs(10)).await;
      inputs_to_use = self.rpc.get_spendable(&address.1).await?;
    }

    let mut value = 0;
    let inputs = inputs_to_use.iter().map(|input| {
      value += input.value;
      Ok(TxIn {
        previous_output: OutPoint{txid: Txid::from_hex(&input.tx_hash)?, vout: input.tx_pos},
        script_sig: Script::new(),
        sequence: 0xFFFFFFFF,
        witness: Vec::new()
      })
    }).collect::<anyhow::Result<_>>()?;

    self.engine.create_lock_script(&self.swap_hash, true, client, client_refund);
    let mut lock_script_hash = hex!("0020").to_vec();
    lock_script_hash.extend(sha2::Sha256::digest(self.engine.lock_script_bytes()));

    let mut lock = Transaction {
      version: 2,
      lock_time: 0,
      input: inputs,
      output: vec![TxOut {
        value,
        script_pubkey: Script::from(lock_script_hash)
      }]
    };
    let fee = ((lock.get_weight() / 4) as u64) * self.rpc.get_fee_per_byte().await?;
    lock.output[0].value = lock.output[0].value.checked_sub(fee)
      .ok_or_else(|| anyhow::anyhow!("Not enough Bitcoin to pay for {} sats of fees", fee))?;

    let private_key = secp256k1::SecretKey::from_slice(
      &address.0.to_bytes()
    ).expect("secp256kfun generated an invalid secp256k1 key, yet we already used it earlier");

    let address0 = address.0;
    let key_bytes = g!(address0 * G).mark::<Normal>().to_bytes();

    let mut segwit_script_code = hex!("76a914").to_vec();
    segwit_script_code.extend(&address.2);
    segwit_script_code.extend(hex!("88ac").to_vec());
    let segwit_script_code = Script::from(segwit_script_code);

    let cloned_lock = lock.clone();
    let mut components = SigHashCache::new(&cloned_lock);
    for i in 0 .. lock.input.len() {
      let signature = SECP.sign(
        &secp256k1::Message::from_slice(&components.signature_hash(i, &segwit_script_code, value, SigHashType::All))?,
        &private_key
      ).serialize_der();

      let mut signature = signature.to_vec();
      signature.push(1);
      lock.input[i].witness = vec![signature, key_bytes.to_vec()];
    }

    let fee_per_byte_and_sig = self.prepare_refund_and_spend(lock.txid(), lock.output[0].value).await?;
    let result = Ok(
      bincode::serialize(
        &LockAndRefundInfo {
          swap_hash: self.swap_hash.clone(),
          lock_id: serialize(&lock.txid()),
          host_refund_signature: fee_per_byte_and_sig.1,
          value: lock.output[0].value,
          fee_per_byte: fee_per_byte_and_sig.0
        }
      ).expect("Couldn't serialize the lock and refund info")
    );

    self.lock = Some(lock);
    result
  }

  fn verify_refund_and_spend(&mut self, refund_and_spend_sigs: &[u8]) -> anyhow::Result<()> {
    let sigs: ClientRefundAndSpendSignatures = bincode::deserialize(refund_and_spend_sigs)?;
    let refund_signature = sigs.refund_signature;
    let encrypted_spend_signature = EncryptedSignature::deserialize(&sigs.encrypted_spend_signature)?;

    SECP.verify(
      self.refund_message.as_ref().expect("Couldn't grab the refund's message despite attempting to verify the refund"),
      &secp256k1::Signature::from_der(&refund_signature)?,
      &secp256k1::PublicKey::from_slice(self.client_refund.as_ref().expect("Couldn't grab the client's refund public key despite attempting to verify the refund"))?
    )?;

    let bs = self.engine.bs.as_ref().expect("Verifying spend before generating keys");
    encrypted_verify(
      &bincode::deserialize(self.client_refund.as_ref().expect("Trying to verify the spend signature before exchanging keys"))?,
      &g!(bs * G).mark::<Normal>(),
      &encrypted_spend_signature,
      self.spend_message.as_ref().expect("Trying to verify the spend before knowing its message")
    )?;

    // Complete the refund transaction
    let mut refund = self.refund.take().expect("Verifying and completing the refund before creating it");
    refund.input[0].witness = vec![
      Vec::new(),
      refund_signature,
      self.refund_signature.clone().expect("Verifying the refund yet we never signed it"),
      Vec::new(),
      self.engine.lock_script_bytes.clone().expect("Finishing despite not knowing the lock script")
    ];
    refund.input[0].witness[1].push(1);
    refund.input[0].witness[2].push(1);
    self.refund = Some(refund);

    self.encrypted_spend_signature = Some(encrypted_spend_signature);

    Ok(())
  }

  async fn publish_lock(
    &mut self
  ) -> anyhow::Result<()> {
    let lock = self.lock.as_ref().expect("Trying to publish a lock transaction before creating it");
    self.rpc.publish(&serialize(lock)).await?;

    let address = Address::p2wsh(self.engine.lock_script(), NETWORK).to_string();
    let mut history = self.rpc.get_address_history(&address).await;
    while (history.len() == 0) || (history[0].confirmations < CONFIRMATIONS) {
      #[cfg(test)]
      self.rpc.mine_block().await?;

      tokio::time::sleep(std::time::Duration::from_secs(20)).await;
      history = self.rpc.get_address_history(&address).await;
    }
    self.lock_height = Some(self.rpc.get_height().await);
    Ok(())
  }

  async fn refund<Verifier: UnscriptedVerifier>(mut self, mut verifier: Verifier) -> anyhow::Result<()> {
    /*
      There are four states to be aware of:
      A) Never even created an address
      B) Created address but didn't fund
      C) Created address and did fund but didn't publish lock
      D) Published lock
      In the last case, if we fail to publish the refund, it may be because the client already claimed the BTC
      In that case, all we can do is finish purchasing the unscripted coin
    */

    // Path A
    if self.address.is_none() {
      Ok(())
    } else {
      // If the lock exists, confirm it was published
      let mut lock_exists = false;
      if let Some(lock) = self.lock.clone() {
        let mut lock_id = lock.txid().to_vec();
        lock_id.reverse();
        lock_exists = self.rpc.get_transaction(&hex::encode(&lock_id)).await.is_ok();
      }

      // Path B or C
      if !lock_exists {
        let address = self.address.expect("Address is some yet couldn't get its value");
        let utxos = self.rpc.get_spendable(&address.1).await?;
        // Path B
        if utxos.len() == 0 {
          Ok(())
        // Path C
        } else {
          let mut value = 0;
          let inputs = utxos.iter().map(|input| {
            value += input.value;
            Ok(TxIn {
              previous_output: OutPoint{txid: Txid::from_hex(&input.tx_hash)?, vout: input.tx_pos},
              script_sig: Script::new(),
              sequence: 0xFFFFFFFF,
              witness: Vec::new()
            })
          }).collect::<anyhow::Result<_>>()?;

          let mut return_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: inputs,
            output: vec![
              TxOut {
                script_pubkey: self.refund_pubkey_script,
                value
              }
            ]
          };
          let fee = ((return_tx.get_weight() / 4) as u64) * self.rpc.get_fee_per_byte().await?;
          return_tx.output[0].value = return_tx.output[0].value.checked_sub(fee)
            .ok_or_else(|| anyhow::anyhow!("Not enough Bitcoin to pay for {} sats of fees", fee))?;

          let private_key = secp256k1::SecretKey::from_slice(
            &address.0.to_bytes()
          ).expect("secp256kfun generated an invalid secp256k1 key");

          let address0 = address.0;
          let key_bytes = g!(address0 * G).mark::<Normal>().to_bytes();

          let mut segwit_script_code = hex!("76a914").to_vec();
          segwit_script_code.extend(&address.2);
          segwit_script_code.extend(hex!("88ac").to_vec());
          let segwit_script_code = Script::from(segwit_script_code);

          let cloned_return = return_tx.clone();
          let mut components = SigHashCache::new(&cloned_return);
          for i in 0 .. return_tx.input.len() {
            let signature = SECP.sign(
              &secp256k1::Message::from_slice(&components.signature_hash(i, &segwit_script_code, value, SigHashType::All))?,
              &private_key
            ).serialize_der();

            let mut signature = signature.to_vec();
            signature.push(1);
            return_tx.input[i].witness = vec![signature, key_bytes.to_vec()];
          }

          self.rpc.publish(&serialize(&return_tx)).await?;
          Ok(())
        }
      } else {
        // If we published the lock, we need to publish the refund transaction
        // First, we need to wait for T0 to expire

        while self.rpc.get_height().await < (self.lock_height.expect("Never set lock height despite published lock") + (T0 as isize)) {
          #[cfg(test)]
          for _ in 0 .. T0 {
            self.rpc.mine_block().await?;
          }
          tokio::time::sleep(std::time::Duration::from_secs(20)).await;
        }

        let refund = self.refund.clone().expect("Refund transaction doesn't exist despite having published the lock");
        let refund_id = refund.txid();
        let _ = self.rpc.publish(&serialize(&refund)).await;
        let refund_address = Address::p2wsh(
          self.refund_script.as_ref().expect("Calling refund after publishing the lock but before knowinng the refund script"),
          NETWORK
        ).to_string();

        // Wait for the refund to confirm
        'outer: loop {
          #[cfg(test)]
          self.rpc.mine_block().await?;

          let history = self.rpc.get_address_history(&refund_address).await;
          let mut found = false;
          for tx in history {
            if (tx.tx.txid()) == (refund_id.clone()) {
              found = true;
              if (tx.confirmations) >= CONFIRMATIONS {
                break 'outer;
              }
            }
          }

          // Transaction was beat
          // Path D/forced success
          if !found {
            return verifier.finish(&mut self).await;
          }

          tokio::time::sleep(std::time::Duration::from_secs(20)).await;
        }

        // Complete and publish the spend transaction.
        let mut spend = self.spend.expect("Spend transaction doesn't exist despite having published the lock");
        spend.input[0].witness = vec![
          Vec::new(),
          secp256k1::Signature::from_compact(
            &decrypt_signature(
              &self.encrypted_spend_signature.expect("Spend signature doesn't exist despite having published the lock"),
              &self.engine.bs.expect("Never generated keys despite having published the lock")
            )?.serialize()
          )?.serialize_der().to_vec(),
          SECP.sign(
            &secp256k1::Message::from_slice(
              &self.spend_message.expect("Spend message doesn't exist despite having published the lock")
            )?,
            &secp256k1::SecretKey::from_slice(&self.engine.br.to_bytes())?
          ).serialize_der().to_vec(),
          vec![1],
          self.engine.refund_script_bytes.expect("Finishing despite not knowing the lock script")
        ];
        spend.input[0].witness[1].push(1);
        spend.input[0].witness[2].push(1);
        self.rpc.publish(&serialize(&spend)).await?;

        Ok(())
      }
    }
  }

  async fn prepare_buy_for_client(&mut self) -> anyhow::Result<Vec<u8>> {
    let lock = self.lock.as_ref().expect("Preparing a buy transaction for the client despite not having created the lock");

    let mut buy = Transaction {
      version: 2,
      lock_time: 0,
      input: vec![
        TxIn {
          previous_output: OutPoint {
            txid: lock.txid(),
            vout: 0
          },
          script_sig: Script::new(),
          sequence: 0xFFFFFFFF,
          witness: Vec::new()
        }
      ],
      output: vec![
        TxOut {
          script_pubkey: self.client_destination_script.clone().expect("Preparing buy for client before knowing their destination"),
          value: lock.output[0].value
        }
      ]
    };
    let fee = ((buy.get_weight() as u64) / 4) * self.rpc.get_fee_per_byte().await?;
    buy.output[0].value = buy.output[0].value.checked_sub(fee)
      .ok_or_else(|| anyhow::anyhow!("Not enough Bitcoin to pay for {} sats of fees", fee))?;

    let mut components = SigHashCache::new(&buy);
    let encrypted_signature = encrypted_sign(
      &self.engine.b,
      self.encryption_key.as_ref().expect("Attempted to generate encrypted sign before verifying dleq proof"),
      &components.signature_hash(
        0,
        self.engine.lock_script(),
        lock.output[0].value,
        SigHashType::All
      )
    )?;

    self.buy = Some(buy.txid());

    let result = Ok(
      bincode::serialize(&BuyInfo {
        value: buy.output[0].value,
        encrypted_signature: encrypted_signature.serialize()
      })?
    );
    self.encrypted_signature = Some(encrypted_signature);
    result
  }

  async fn recover_final_key(&self) -> anyhow::Result<[u8; 32]> {
    let encrypted_signature = self.encrypted_signature.as_ref().expect("Trying to recover the final key before preparing the encrypted signature");

    let mut buy_hash = self.buy.expect("Trying to recover the final key before creating the buy").to_vec();
    buy_hash.reverse();
    let buy_hash = hex::encode(buy_hash);
    let mut buy = Err(anyhow::anyhow!(""));
    while buy.is_err() {
      buy = self.rpc.get_transaction(&buy_hash).await;
      if buy.is_err() {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
      }
    }

    let their_signature = &buy?.input[0].witness[2];
    let signature = secp256k1::Signature::from_der(
      &their_signature[.. their_signature.len() - 1]
    ).expect("Signature included in the buy transaction wasn't valid despite getting on chain").serialize_compact();

    let mut key = recover_key(
      self.encryption_key.as_ref().expect("Attempted to recover final key before verifying dleq proof"),
      encrypted_signature,
      &Signature::deserialize(&signature).expect("Failed to deserialize decrypted signature")
    ).expect("Failed to recover key from decrypted signature").to_bytes();
    key.reverse();
    Ok(key)
  }

  #[cfg(test)]
  fn override_refund_with_random_address(&mut self) {
    let pubkey = bitcoin::util::key::PublicKey::from_private_key(
      &SECP,
      &bitcoin::util::key::PrivateKey {
        compressed: true,
        network: NETWORK,
        key: secp256k1::SecretKey::from_slice(
          &Scalar::random(&mut OsRng).to_bytes()
        ).expect("secp256kfun generated invalid key")
      }
    );

    self.refund_pubkey_script = BtcEngine::decode_address(
      &Address::p2pkh(
        &pubkey,
        NETWORK
      ).to_string()
    ).expect("Generated an invalid random address");

    self.refund_pubkey = Some(pubkey);
  }
  #[cfg(test)]
  async fn send_from_node(&self) -> anyhow::Result<()> {
    self.rpc.send_from_electrum(&self.address.as_ref().unwrap().1.to_string()).await
  }
  #[cfg(test)]
  async fn advance_consensus(&self) -> anyhow::Result<()> {
    for _ in 0 .. CONFIRMATIONS {
      self.rpc.mine_block().await?
    }
    Ok(())
  }
  #[cfg(test)]
  fn get_refund_address(&self) -> String {
    Address::p2pkh(&self.refund_pubkey.expect("Calling test get_refund_address despite not overriding it"), NETWORK).to_string()
  }
  #[cfg(test)]
  async fn get_if_funded(self, address: &str) -> bool {
    self.rpc.get_spendable(address).await.expect("Couldn't get the UTXOs for an address").len() != 0
  }
}
