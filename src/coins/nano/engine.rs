use std::{
  collections::HashMap,
  fmt::Debug,
  thread,
  sync::{Arc, atomic::{self, AtomicBool}, mpsc},
};

use log::{debug, info};
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use nanocurrency_types::{Account, BlockInner, BlockHash, Block, BlockHeader};

use crate::crypt_engines::{CryptEngine, ed25519_engine::Ed25519Blake2b};

/// A workaround for the Nano RPC returning empty strings instead of empty arrays or objects.
pub mod nano_rpc_maybe_empty {
  use serde::{Serialize, Deserialize, de::{Deserializer, Error}, ser::Serializer};

  #[allow(dead_code)] // 5 lines of dead code for serialize support if we ever want it ¯\_(ツ)_/¯
  pub fn serialize<T: Serialize + PartialEq + Default, S: Serializer>(item: &T, serializer: S) -> Result<S::Ok, S::Error> {
    if item == &Default::default() {
      "".serialize(serializer)
    } else {
      item.serialize(serializer)
    }
  }

  pub fn deserialize<'de, T: Deserialize<'de> + PartialEq + Default, D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OrString<T> {
      Thing(T),
      String(String),
    }
    match OrString::deserialize(deserializer)? {
      OrString::Thing(t) => Ok(t),
      OrString::String(s) => {
        if s.is_empty() {
          Ok(T::default())
        } else {
          Err(D::Error::custom(format!("Got unexpected non-empty string {:?} from Nano RPC", s)))
        }
      }
    }
  }
}

#[derive(Deserialize)]
pub struct NanoConfig {
  pub rpc_url: String,
  pub destination: String,
  pub refund: String,
  #[cfg(test)]
  pub wallet: String,
  #[cfg(test)]
  pub wallet_account: String,
}

pub struct NanoEngine {
  pub k: Option<<Ed25519Blake2b as CryptEngine>::PrivateKey>,
  pub client: reqwest::Client,
  pub config: NanoConfig,
}

impl NanoEngine {
  pub fn new(config: NanoConfig) -> NanoEngine {
    NanoEngine {
      k: None,
      client: reqwest::Client::new(),
      config,
    }
  }

  async fn rpc_call<
    Request: Serialize + Debug,
    Response: DeserializeOwned + Debug
  >(&self, request: &Request) -> anyhow::Result<Response> {
    #[derive(Deserialize, Debug)]
    #[serde(untagged)]
    enum RespOrError<T> {
      Error {
        error: String,
      },
      Response(T),
    }
    let resp = self
      .client
      .post(&self.config.rpc_url)
      .json(request)
      .send()
      .await?
      .json()
      .await?;
    debug!("Nano RPC call {:?} returned {}", request, resp);
    match serde_json::from_value(resp)? {
      RespOrError::Error { error } => anyhow::bail!("Nano RPC returned an error: {}", error),
      RespOrError::Response(resp) => Ok(resp),
    }
  }

  async fn publish(&self, block: &Block, subtype: &str) -> anyhow::Result<()> {
    #[derive(Serialize, Debug)]
    struct ProcessRequest<'a> {
      action: &'a str,
      json_block: &'a str,
      subtype: &'a str,
      block: &'a Block,
    }
    #[derive(Deserialize, Debug)]
    struct ProcessResponse {
      hash: String,
    }
    let req = ProcessRequest {
      action: "process",
      json_block: "true",
      subtype,
      block,
    };
    let res: ProcessResponse = self.rpc_call(&req).await?;
    debug_assert_eq!(res.hash, hex::encode_upper(block.get_hash().0));
    Ok(())
  }

  fn compute_work(root: [u8; 32], threshold: u64) -> u64 {
    info!("Generating Nano proof of work for root {} with threshold 0x{:016x}", hex::encode(&root), threshold);
    // TODO support calling an external work RPC
    let (send, recv) = mpsc::channel();
    let running = Arc::new(AtomicBool::new(true));
    let thread_count = num_cpus::get();
    for i in 0..thread_count {
      let send = send.clone();
      let running = running.clone();
      thread::spawn(move || {
        let mut nonce = (u64::MAX / thread_count as u64) * i as u64;
        while nanocurrency_types::work_value(&root, nonce) < threshold &&
          running.load(atomic::Ordering::Relaxed)
        {
          nonce += 1;
        }
        let _ = send.send(nonce);
      });
    }
    let nonce = recv.recv().expect("Work computation threads died");
    running.store(false, atomic::Ordering::Relaxed);
    debug!("Generated Nano proof of work nonce {:016x} for root {}", nonce, hex::encode(&root));
    nonce
  }

  fn complete_block(inner: BlockInner, key: <Ed25519Blake2b as CryptEngine>::PrivateKey, work_threshold: u64) -> Block {
    let hash = inner.get_hash();
    let signature = Ed25519Blake2b::sign(&key, &hash.0).unwrap();
    let work = Self::compute_work(inner.root_bytes().clone(), work_threshold);
    Block {
      inner,
      header: BlockHeader {
        signature: nanocurrency_types::Signature::from_bytes(
          &Ed25519Blake2b::signature_to_bytes(&signature)
        ).expect("Generated invalid signature"),
        work,
      }
    }
  }

  async fn get_work_threshold(&self, is_receive: bool) -> anyhow::Result<u64> {
    #[derive(Serialize, Debug)]
    struct ActiveDifficultyRequest {
      action: &'static str,
    }
    #[derive(Deserialize, Debug)]
    struct ActiveDifficultyResponse {
      network_current: String,
    }
    let request = ActiveDifficultyRequest {
      action: "active_difficulty",
    };
    let resp: ActiveDifficultyResponse = self.rpc_call(&request).await?;
    let mut threshold = u64::from_str_radix(&resp.network_current, 16)?;
    if is_receive && !cfg!(test) { // In automated tests epoch 2 might not've happened yet
      threshold = (threshold.wrapping_neg() / 64).wrapping_neg();
    }
    Ok(threshold)
  }

  pub async fn send(
    &self,
    key_a: <Ed25519Blake2b as CryptEngine>::PrivateKey,
    key_b: <Ed25519Blake2b as CryptEngine>::PrivateKey,
    input: BlockHash,
    destination: Account,
    value: u128,
  ) -> anyhow::Result<()> {
    let total_key = key_a + key_b;
    let account = Account((&total_key * &curve25519_dalek::constants::ED25519_BASEPOINT_TABLE).compress().to_bytes());
    debug!("Creating Nano send for shared address {}", account);
    let open_inner = BlockInner::State {
      account: account.clone(),
      previous: BlockHash::default(),
      representative: Account([0u8; 32]),
      balance: value,
      link: input.0,
    };
    let open = Self::complete_block(open_inner, total_key, self.get_work_threshold(true).await?);
    self.publish(&open, "open").await?;
    let send_inner = BlockInner::State {
      account,
      previous: open.get_hash(),
      representative: Account([0u8; 32]),
      balance: 0,
      link: destination.0,
    };
    let send = Self::complete_block(send_inner, total_key, self.get_work_threshold(false).await?);
    self.publish(&send, "send").await?;
    Ok(())
  }

  pub async fn get_confirmed_pending(&self, account: &str) -> anyhow::Result<Vec<(BlockHash, u128)>> {
    #[derive(Serialize, Debug)]
    struct PendingRequest<'a> {
      action: &'a str,
      account: &'a str,
      source: &'a str,
      include_only_confirmed: &'a str,
    }
    #[derive(Deserialize, Debug)]
    struct PendingResponse {
      #[serde(with = "nano_rpc_maybe_empty")]
      blocks: HashMap<String, PendingBlock>,
    }
    #[derive(Deserialize, Debug, PartialEq)]
    struct PendingBlock {
      amount: String,
    }
    let request = PendingRequest {
      action: "pending",
      account,
      source: "true",
      include_only_confirmed: "true",
    };
    let response: PendingResponse = self.rpc_call(&request).await?;
    response.blocks.into_iter().map(|(hash_str, info)| {
      let mut hash = BlockHash::default();
      hex::decode_to_slice(hash_str, &mut hash.0)?;
      let amount = info.amount.parse()?;
      Ok((hash, amount))
    }).collect()
  }

  #[cfg(test)]
  pub async fn send_from_node(&self, destination: &str, amount: u128) -> anyhow::Result<BlockHash> {
    #[derive(Serialize, Debug)]
    struct SendRequest<'a> {
      action: &'a str,
      wallet: &'a str,
      source: &'a str,
      destination: &'a str,
      amount: String,
    }
    #[derive(Deserialize, Debug)]
    struct SendResponse {
      block: String,
    }
    let request = SendRequest {
      action: "send",
      wallet: &self.config.wallet,
      source: &self.config.wallet_account,
      destination,
      amount: amount.to_string(),
    };
    let resp: SendResponse = self.rpc_call(&request).await?;
    let mut hash = BlockHash::default();
    hex::decode_to_slice(resp.block, &mut hash.0)?;
    Ok(hash)
  }
}
