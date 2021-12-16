use std::fmt::Debug;

use log::debug;

use lazy_static::lazy_static;
use hex_literal::hex;
use rand::{rngs::OsRng, RngCore};

use curve25519_dalek::{
  scalar::Scalar,
  edwards::{EdwardsPoint, CompressedEdwardsY},
  constants::ED25519_BASEPOINT_TABLE
};

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::json;

use reqwest;
use digest_auth::AuthContext;

use monero::{
  util::{
    key::{PrivateKey, PublicKey, ViewPair},
    address::Address
  },
  blockdata::{
    transaction::Transaction,
    block::Block
  },
  consensus::encode::deserialize,
  network::Network
};

use crate::crypto::ed25519::random_scalar;

#[cfg(not(feature = "no_confs"))]
pub const CONFIRMATIONS: isize = 3;
// Required to always use at least one confirmation because we iterate over new blocks, not the mempool
// This can be set to 0 for the same effect; it's just misleading to suggest it doesn't actually need confs
// At the same time, this feature being named no_confs is also decently misleading, but it is used for other coins
#[cfg(feature = "no_confs")]
pub const CONFIRMATIONS: isize = 1;

// This should NOT be used with the mainnet. It is a Proof of Concept
// It only uses the mainnet network byte because it's shared with regtest
pub const NETWORK: Network = Network::Mainnet;

lazy_static! {
  pub static ref C: EdwardsPoint = CompressedEdwardsY::from_slice(
    &hex!("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")
  ).decompress().unwrap();
}

#[derive(Deserialize, Debug)]
struct EmptyResponse {}
#[derive(Deserialize, Debug)]
struct JsonRpcResponse<T> {
  result: T
}

#[derive(Clone, Deserialize)]
pub struct XmrConfig {
  daemon: String,
  wallet: String,
  wallet_user: String,
  wallet_pass: String,
  pub destination: String,
  pub refund: String
}

#[derive(Serialize, Deserialize)]
pub struct XmrKeys {
  pub dleq: Vec<u8>,
  pub view_share: [u8; 32]
}

pub struct XmrEngine {
  pub config: XmrConfig,

  pub k: Option<Scalar>,
  pub view: Scalar,
  spend: Option<EdwardsPoint>,

  height_at_start: isize,
  deposit: Option<String>,
  #[cfg(test)]
  wallet_address: Option<String>
}

impl XmrEngine {
  pub async fn new(config: XmrConfig) -> anyhow::Result<XmrEngine> {
    let mut result = XmrEngine {
      config,

      k: None,
      view: random_scalar(),
      spend: None,

      height_at_start: -1,
      deposit: None,
      #[cfg(test)]
      wallet_address: None
    };
    result.height_at_start = result.get_height().await;
    Ok(result)
  }

  pub fn set_spend(&mut self, other: EdwardsPoint) {
    self.spend = Some((&self.k.expect("Verifying keys before generating") * &ED25519_BASEPOINT_TABLE) + other);
  }

  pub fn get_view_pair(&self) -> ViewPair {
    ViewPair {
      spend: PublicKey {
        point: self.spend.expect("Getting view pair before verifying DLEQ proof").compress()
      },
      view: PrivateKey::from_scalar(self.view)
    }
  }

  async fn rpc_call<
    Params: Serialize + Debug,
    Response: DeserializeOwned + Debug
  >(&self, method: &str, params: Option<Params>) -> anyhow::Result<Response> {
    let client = reqwest::Client::new();
    let mut builder = client.post(&(self.config.daemon.clone() + "/" + method));
    if let Some(params) = params.as_ref() {
      builder = builder.json(params);
    }
    let res = builder
      .send()
      .await?
      .text()
      .await?;
    debug!("RPC call to {} with {:?} returned {}", method, params, &res);
    Ok(
      serde_json::from_str(&res)
        .map_err(|_| anyhow::anyhow!("Request failed due to incompatible RPC version"))?
    )
  }

  async fn wallet_call<
    Params: Serialize + Debug,
    Response: DeserializeOwned + Debug
  >(&self, method: &str, params: Params) -> anyhow::Result<JsonRpcResponse<Response>> {
    let client = reqwest::Client::new();

    let mut prompt = digest_auth::parse(
      client
        .post(&self.config.wallet)
        .send()
        .await?
        .headers()["www-authenticate"]
        .to_str()?
    )?;
    let context = AuthContext::new_post::<_, _, _, &[u8]>(
      self.config.wallet_user.clone(),
      self.config.wallet_pass.clone(),
      "/json_rpc",
      None
    );
    let answer = prompt.respond(&context)?.to_header_string();

    let res = client
      .post(&(self.config.wallet.clone() + "/json_rpc"))
      .header("Authorization", answer)
      .json(&json!({
        "jsonrpc": "2.0",
        "id": (),
        "method": method,
        "params": params
      }))
      .send()
      .await?
      .text()
      .await?;

    debug!("Wallet RPC call to {} with {:?} returned {}", method, params, &res);
    Ok(
      serde_json::from_str(&res)
        .map_err(|_| anyhow::anyhow!("Request failed due to incompatible RPC version"))?
    )
  }

  pub async fn get_height(&self) -> isize {
    #[derive(Deserialize, Debug)]
    struct HeightResponse {
      height: isize
    }
    self.rpc_call::<Option<()>, HeightResponse>("get_height", None).await.expect("Failed to get the height").height
  }

  pub async fn get_transaction(&self, hash_hex: &str) -> anyhow::Result<Option<(Transaction, isize)>> {
    #[derive(Deserialize, Debug)]
    struct TransactionResponse {
      as_hex: String,
      block_height: isize
    }
    #[derive(Deserialize, Debug)]
    struct TransactionsResponse {
      txs: Vec<TransactionResponse>
    }

    let txs: TransactionsResponse = self.rpc_call("get_transactions", Some(json!({
      "txs_hashes": [hash_hex]
    }))).await?;
    Ok(
      if txs.txs.len() == 0 {
        None
      } else {
        Some(
          (
            deserialize(
              &hex::decode(&txs.txs[0].as_hex).expect("Monero RPC returned a non-hex transaction")
            ).expect("Monero returned a transaction we couldn't deserialize"),
            txs.txs[0].block_height
          )
        )
      }
    )
  }

  pub async fn get_deposit(&mut self, pair: &ViewPair, wait: bool) -> anyhow::Result<Option<Transaction>> {
    #[derive(Deserialize, Debug)]
    struct BlockResponse {
      blob: String
    }
    #[derive(Deserialize, Debug)]
    struct JsonRpcResponse {
      result: BlockResponse
    }

    let mut block = self.height_at_start - 1;
    let mut tx_hash;
    let mut result;
    'outer: loop {
      while self.get_height().await > block {
        for hash in deserialize::<Block>(
          &hex::decode(
            &(
              self.rpc_call::<_, JsonRpcResponse>(
                "json_rpc",
                Some(json!({
                  "jsonrpc": "2.0",
                  "id": (),
                  "method": "get_block",
                  "params": {
                    "height": block
                  }
                }))
              ).await?
            ).result.blob
          ).expect("Monero returned a non-hex blob")
        ).expect("Monero returned a block we couldn't deserialize").tx_hashes {
          tx_hash = hex::encode(hash.as_bytes());
          result = self.get_transaction(&tx_hash)
            .await?
            .expect("Couldn't get transaction included in block");

          let outputs = result.0.check_outputs(pair, 0..1, 0..1);
          if outputs.is_err() || (outputs.unwrap().len() == 0) {
            continue;
          }

          if block != result.1 {
            anyhow::bail!("Transaction's confirmation height changed");
          }

          break 'outer;
        }
        block += 1;
      }

      if !wait {
        return Ok(None);
      }
      tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
    if !wait {
      return Ok(Some(result.0));
    }

    let mut confirmation_height = result.1;
    while self.get_height().await - confirmation_height < CONFIRMATIONS {
      tokio::time::sleep(std::time::Duration::from_secs(10)).await;
      confirmation_height = self.get_transaction(&tx_hash).await?.unwrap().1;
      if confirmation_height != block {
        anyhow::bail!("Transaction's confirmation height changed");
      }
    }

    self.deposit = Some(tx_hash);
    Ok(Some(result.0))
  }

  pub async fn claim(
    &self,
    spend_key: Scalar,
    destination: &str
  ) -> anyhow::Result<()> {
    #[derive(Deserialize, Debug)]
    struct WalletResponse {
      address: String
    }

    let spend_key = spend_key + self.k.expect("Claiming funds before generating a k");
    let address = Address::standard(
      NETWORK,
      PublicKey {
        point: (&spend_key * &ED25519_BASEPOINT_TABLE).compress()
      },
      PublicKey {
        point: (&self.view * &ED25519_BASEPOINT_TABLE).compress()
      }
    ).to_string();

    let mut name = [0; 32];
    OsRng.fill_bytes(&mut name);

    let res: WalletResponse = self.wallet_call("generate_from_keys", json!({
        "restore_height": self.height_at_start,
        "filename": hex::encode(&name),
        "address": address,
        "spendkey": hex::encode(&spend_key.to_bytes()),
        "viewkey": hex::encode(&self.view.to_bytes()),
        "password": ""
      })
    ).await.expect("Couldn't create the wallet").result;
    if res.address != address {
      anyhow::bail!("Generated a different wallet");
    }

    // Wait ten blocks for the transaction to unlock
    while self.get_height().await - self.get_transaction(
      self.deposit.as_ref().expect("Claiming Monero before knowing of its deposit")
    ).await?.unwrap().1 < 10 {
      #[cfg(test)]
      self.mine_block().await?;

      tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }

    // Trigger a rescan
    let _: EmptyResponse = self.wallet_call("rescan_blockchain", json!({})).await?.result;

    // Use sweep to forward the funds
    let _: EmptyResponse = self.wallet_call("sweep_all", json!({
      "address": destination,
    })).await.expect("Couldn't transfer the Monero").result;

    Ok(())
  }

  #[cfg(test)]
  pub async fn send_from_wallet(&mut self) -> anyhow::Result<()> {
    #[derive(Deserialize, Debug)]
    struct AddressResponse {
      address: String
    }

    // Create a new wallet
    let mut name = [0; 32];
    OsRng.fill_bytes(&mut name);
    let _: EmptyResponse = self.wallet_call("create_wallet", json!({
      "filename": hex::encode(&name),
      "language": "English"
    })).await.expect("Couldn't create a new wallet").result;

    let res: AddressResponse = self.wallet_call("get_address", json!({
      "account_index": 0
    })).await.expect("Couldn't get the address").result;
    self.wallet_address = Some(res.address);

    // Mine 70 blocks to it (coin maturity happens at 60)
    for _ in 0 .. 7 {
      self.mine_block().await?;
    }
    let _: EmptyResponse = self.wallet_call("rescan_blockchain", json!({})).await?.result;

    // Send 1 XMR to our address
    let _: EmptyResponse = self.wallet_call("transfer", json!({
      "destinations": [{
        "address": Address::from_viewpair(NETWORK, &self.get_view_pair()).to_string(),
        "amount": (1000000000000 as u64)
      }]
    })).await.expect("Couldn't transfer the Monero for testing purposes").result;
    self.mine_block().await?;

    Ok(())
  }

  #[cfg(test)]
  pub async fn mine_block(&self) -> anyhow::Result<()> {
    let _: EmptyResponse = self.rpc_call("json_rpc", Some(json!({
      "jsonrpc": "2.0",
      "id": (),
      "method": "generateblocks",
      "params": {
        "wallet_address": if self.wallet_address.is_some() {
          self.wallet_address.as_ref().unwrap()
        } else {
          // Fallback for when the recreated client advances the consensus one last time
          // Random address from one of the swap runs
          "456BaF31m8NF1DQ9HRA7ZJ7JJZMVLw1ZY5Uzev5q7QBxFPqkyy1vNRN2Yvn43sE6LLYtQtLH16HKjHDhn1W7a2Wy1aWbp3U"
        },
        "amount_of_blocks": 10
      }
    }))).await?;
    Ok(())
  }
}
