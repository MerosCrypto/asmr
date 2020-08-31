use std::convert::TryInto;

use lazy_static::lazy_static;
use hex_literal::hex;

use serde::{Serialize, Deserialize};

use bitcoin::{
  secp256k1::{self, Secp256k1},
  hashes::Hash, hash_types::{Txid, WPubkeyHash},
  blockdata::{script::Script, transaction::{OutPoint, TxIn, TxOut, Transaction}},
  network::constants::Network,
  util::{address::Address, bip143::SighashComponents}
};

use crate::crypt_engines::{CryptEngine, secp256k1_engine::Secp256k1Engine};

pub const T0: u8 = 6;
pub const T1: u8 = 6;
pub const SWAP_CUTOFF_BLOCKS: isize = 4;

#[cfg(not(feature = "no_confs"))]
pub const CONFIRMATIONS: isize = 1;
#[cfg(feature = "no_confs")]
pub const CONFIRMATIONS: isize = -1;

#[cfg(not(test))]
pub const NETWORK: Network = Network::Testnet;
#[cfg(test)]
pub const NETWORK: Network = Network::Regtest;

lazy_static! {
  pub static ref SECP: Secp256k1<secp256k1::All> = Secp256k1::new();
}

#[derive(Deserialize)]
pub struct BtcConfig {
  pub url: String,
  pub btc_url: Option<String>,
  pub destination: String,
  pub refund: String
}

#[derive(Serialize, Deserialize)]
pub struct BuyInfo {
  pub value: u64,
  pub encrypted_signature: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct LockAndRefundInfo {
  pub swap_hash: Vec<u8>,
  pub lock_id: Vec<u8>,
  pub host_refund_signature: Vec<u8>,
  pub value: u64,
  pub fee_per_byte: u64
}

#[derive(Serialize, Deserialize)]
pub struct ClientRefundAndSpendSignatures {
  pub refund_signature: Vec<u8>,
  pub encrypted_spend_signature: Vec<u8>
}

pub struct BtcEngine {
  pub b: <Secp256k1Engine as CryptEngine>::PrivateKey,
  pub br: <Secp256k1Engine as CryptEngine>::PrivateKey,
  pub bs: Option<<Secp256k1Engine as CryptEngine>::PrivateKey>,

  pub lock_script_bytes: Option<Vec<u8>>,
  lock_script: Option<Script>,

  pub refund_script_bytes: Option<Vec<u8>>
}

impl BtcEngine {
  pub fn new() -> BtcEngine {
    BtcEngine {
      b: Secp256k1Engine::new_private_key(),
      br: Secp256k1Engine::new_private_key(),
      bs: None,

      lock_script_bytes: None,
      lock_script: None,

      refund_script_bytes: None
    }
  }

  pub fn decode_address(address: &str) -> anyhow::Result<Script> {
    let address: Address = address.parse()?;
    Ok(address.script_pubkey())
  }

  pub fn generate_deposit_address() -> (<Secp256k1Engine as CryptEngine>::PrivateKey, String, [u8; 20]) {
    let key = Secp256k1Engine::new_private_key();
    let public_key = &bitcoin::util::key::PublicKey {
      compressed: true,
      key: secp256k1::PublicKey::from_secret_key(
        &SECP,
        &secp256k1::SecretKey::from_slice(
          &Secp256k1Engine::private_key_to_bytes(&key)
        ).expect("Secp256k1Engine generated an invalid secp256k1 key")
      ),
    };
    let mut hash_engine = WPubkeyHash::engine();
    public_key.write_into(&mut hash_engine);

    (
      key,
      Address::p2wpkh(public_key, NETWORK).to_string(),
      // This is the same payload used in the Address
      // The field unfortunately isn't public though
      WPubkeyHash::from_engine(hash_engine).as_ref().try_into().expect("Couldn't convert a twenty-byte hash to a twenty-byte array")
    )
  }
}

impl BtcEngine {
  pub fn create_lock_script(
    &mut self,
    swap_hash: &[u8],
    is_host: bool,
    other: &[u8],
    other_refund: &[u8]
  ) -> Vec<u8> {
    let b = Secp256k1Engine::public_key_to_bytes(&Secp256k1Engine::to_public_key(&self.b));
    let br = Secp256k1Engine::public_key_to_bytes(&Secp256k1Engine::to_public_key(&self.br));
    let mut bs = vec![other, &b, other_refund, &br];
    if !is_host {
      bs.swap(0, 1);
      bs.swap(2, 3);
    }

    let mut lock_script = hex!("63a820").to_vec();
    lock_script.extend(swap_hash.to_vec());
    lock_script.extend(&hex!("885221"));
    lock_script.extend(bs[0]);

    lock_script.extend(&hex!("21"));
    lock_script.extend(bs[1]);

    lock_script.extend(&hex!("52ae67"));
    match T0 {
      0 => lock_script.push(0),
      1 ..= 16 => lock_script.push(80 + T0),
      _ => lock_script.extend(&[1, T0])
    };
    lock_script.extend(&hex!("b2755221"));
    lock_script.extend(bs[2]);
    lock_script.extend(&hex!("21"));
    lock_script.extend(bs[3]);
    lock_script.extend(&hex!("52ae68"));

    self.lock_script_bytes = Some(lock_script.clone());
    self.lock_script = Some(Script::from(lock_script.clone()));
    lock_script
  }

  /*
    Initially, we just called this function when we needed it
    Then, we called it at the start and then kept a copy in the host/verifier
    Then, when writing the failure paths, this file needed the lock script
    We could've pased it, but the question was why bother?
    And then finally, we always called expect after
    This is due to the exact ordering around this variable
    While moving the expect here does offer minor obfuscation, it also offers a lot of cleanliness
  */
  pub fn lock_script_bytes(&self) -> &[u8] {
    self.lock_script_bytes.as_ref().expect("Retrieving the lock script before creating it")
  }

  pub fn lock_script(&self) -> &Script {
    self.lock_script.as_ref().expect("Retrieving the lock script before creating it")
  }

  pub fn prepare_and_sign_refund(
    &mut self,
    lock_id: Txid,
    is_host: bool,
    other_refund: &[u8],
    client: &[u8],
    value: u64,
    fee_per_byte: u64
  ) -> anyhow::Result<(Script, Transaction, secp256k1::Message, Vec<u8>)> {
    #[allow(non_snake_case)]
    let BR = Secp256k1Engine::public_key_to_bytes(&Secp256k1Engine::to_public_key(&self.br));
    let mut refund_keys: Vec<&[u8]> = vec![&BR, other_refund];
    if is_host {
      refund_keys.swap(0, 1);
    }

    let mut refund_script = vec![0x63, 0x52];
    refund_script.push(refund_keys[0].len() as u8);
    refund_script.extend(refund_keys[0]);
    refund_script.push(refund_keys[1].len() as u8);
    refund_script.extend(refund_keys[1]);
    refund_script.extend(&[0x52, 0xae, 0x67]);
    match T1 {
      0 => refund_script.push(0),
      1 ..= 16 => refund_script.push(80 + T1),
      _ => refund_script.extend(&[1, T1])
    };
    refund_script.extend(&[0xb2, 0x75, client.len() as u8]);
    refund_script.extend(client);
    refund_script.extend(&[0xac, 0x68]);
    self.refund_script_bytes = Some(refund_script.clone());
    let refund_script = Script::from(refund_script);
    let mut refund = Transaction {
      version: 2,
      lock_time: 0,
      input: vec![
        TxIn {
          previous_output: OutPoint {
            txid: lock_id,
            vout: 0
          },
          script_sig: Script::new(),
          sequence: T0 as u32,
          witness: Vec::new()
        }
      ],
      output: vec![
        TxOut {
          script_pubkey: Address::p2wsh(&refund_script, NETWORK).script_pubkey(),
          value: value
        }
      ]
    };
    let fee = ((refund.get_weight() as u64) / 4) * fee_per_byte;
    refund.output[0].value = refund.output[0].value.checked_sub(fee)
      .ok_or_else(|| anyhow::anyhow!("Not enough Bitcoin to pay for {} sats of fees", fee))?;

    let components = SighashComponents::new(&refund);
    let message = secp256k1::Message::from_slice(
      &components.sighash_all(
        &refund.input[0],
        self.lock_script(),
        value
      )
    )?;

    Ok(
      (
        refund_script,
        refund,
        message,
        SECP.sign(
          &message,
          &secp256k1::SecretKey::from_slice(
            &Secp256k1Engine::private_key_to_bytes(
              &self.br
            )
          ).expect("Secp256k1Engine generated invalid SECP Private Key")
        ).serialize_der().to_vec()
      )
    )
  }

  pub fn prepare_spend(
    refund_id: Txid,
    output: Script,
    value: u64,
    fee_per_byte: u64
  ) -> anyhow::Result<Transaction> {
    let mut spend = Transaction {
      version: 2,
      lock_time: 0,
      input: vec![
        TxIn {
          previous_output: OutPoint {
            txid: refund_id,
            vout: 0
          },
          script_sig: Script::new(),
          sequence: 0xFFFFFFFF,
          witness: Vec::new()
        }
      ],
      output: vec![
        TxOut {
          script_pubkey: output,
          value: value
        }
      ]
    };
    let fee = ((spend.get_weight() as u64) / 4) * fee_per_byte;
    spend.output[0].value = spend.output[0].value.checked_sub(fee)
      .ok_or_else(|| anyhow::anyhow!("Not enough Bitcoin to pay for {} sats of fees", fee))?;
    Ok(spend)
  }

  /*
    This is a bit strict
    It requires every transaction to not just be SegWit, but native SegWit
    That said, this library generates native SegWit addresses, and it's a far easier check
    The ease it offers also offers enhanced security guarantees
  */
  fn is_segwit(input: &TxIn) -> anyhow::Result<()> {
    if (input.script_sig.len() != 0) || (input.witness.len() == 0) {
      anyhow::bail!("Transaction doesn't use SegWit");
    }
    Ok(())
  }

  pub fn verify_meta_and_inputs(tx: Transaction) -> anyhow::Result<()> {
    if (tx.version != 2) || (tx.lock_time != 0) {
      anyhow::bail!("Invalid lock version/lock time");
    }

    for input in tx.input {
      BtcEngine::is_segwit(&input)?;
    }

    Ok(())
  }
}
