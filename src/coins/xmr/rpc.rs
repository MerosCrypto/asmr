use std::fmt::Debug;

use log::debug;

use rand::{rngs::OsRng, RngCore};

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::json;

use reqwest;
use digest_auth::AuthContext;

use monero::{
  util::{
    key::{PublicKey, ViewPair},
    address::Address
  },
  blockdata::{
    transaction::Transaction,
    block::Block
  },
  consensus::encode::deserialize
};

use crate::{
  crypt_engines::{CryptEngine, ed25519_engine::Ed25519Sha},
  coins::xmr::engine::*
};

#[derive(Deserialize, Debug)]
struct EmptyResponse {}
#[derive(Deserialize, Debug)]
struct JsonRpcResponse<T> {
  result: T
}

pub struct XmrRpc {
  daemon: String,
  wallet: String,
  wallet_user: String,
  wallet_pass: String,
  height_at_start: isize,
  deposit: Option<String>,
  #[cfg(test)]
  wallet_address: Option<String>
}

impl XmrRpc {
  pub async fn new(config: &XmrConfig) -> anyhow::Result<XmrRpc> {
    let mut result = XmrRpc {
      daemon: config.daemon.clone() + "/",
      wallet: config.wallet.clone() + "/json_rpc",
      wallet_user: config.wallet_user.clone(),
      wallet_pass: config.wallet_pass.clone(),
      height_at_start: -1,
      deposit: None,
      #[cfg(test)]
      wallet_address: None
    };
    result.height_at_start = result.get_height().await;
    Ok(result)
  }

  async fn rpc_call<
    Params: Serialize + Debug,
    Response: DeserializeOwned + Debug
  >(&self, method: &str, params: Option<Params>) -> anyhow::Result<Response> {
    let client = reqwest::Client::new();
    let mut builder = client.post(&(self.daemon.clone() + method));
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
        .post(&self.wallet)
        .send()
        .await?
        .headers()["www-authenticate"]
        .to_str()?
    )?;
    let context = AuthContext::new_post::<_, _, _, &[u8]>(self.wallet_user.clone(), self.wallet_pass.clone(), "/json_rpc", None);
    let answer = prompt.respond(&context)?.to_header_string();

    let res = client
      .post(&self.wallet)
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
    };
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
    };

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

          let outputs = result.0.prefix.check_outputs(pair, 0..1, 0..1);
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
      tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
    }

    if !wait {
      return Ok(Some(result.0));
    }

    let mut confirmation_height = result.1;
    while self.get_height().await - confirmation_height < CONFIRMATIONS {
      tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
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
    spend_key: <Ed25519Sha as CryptEngine>::PrivateKey,
    view_key: <Ed25519Sha as CryptEngine>::PrivateKey,
    destination: &str
  ) -> anyhow::Result<()> {
    #[derive(Deserialize, Debug)]
    struct WalletResponse {
      address: String
    }
    #[derive(Deserialize, Debug)]
    struct SweepResponse {
      tx_hash_list: Vec<String>
    }

    let address = Address::standard(
      NETWORK,
      PublicKey {
        point: Ed25519Sha::to_public_key(&spend_key).compress()
      },
      PublicKey {
        point: Ed25519Sha::to_public_key(&view_key).compress()
      }
    ).to_string();

    let mut name = [0; 32];
    OsRng.fill_bytes(&mut name);

    let res: WalletResponse = self.wallet_call("generate_from_keys", json!({
        "restore_height": self.height_at_start,
        "filename": hex::encode(&name),
        "address": address,
        "spendkey": hex::encode(&Ed25519Sha::private_key_to_bytes(&spend_key)),
        "viewkey": hex::encode(&Ed25519Sha::private_key_to_bytes(&view_key)),
        "password": ""
      })
    ).await.expect("Couldn't create the wallet").result;
    if res.address != address {
      anyhow::bail!("Generated a different wallet");
    }

    // Wait ten blocks for the transaction to unlock
    let confirmation_height = self.get_transaction(
      self.deposit.as_ref().expect("Claiming Monero before knowing of its deposit")
    ).await?.unwrap().1;
    while self.get_height().await - confirmation_height < 10 {
      #[cfg(test)]
      self.mine_block().await?;

      tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
    }
    
    // Trigger a rescan
    let _: EmptyResponse = self.wallet_call("rescan_blockchain", json!({})).await?.result;

    let _: SweepResponse = self.wallet_call("sweep_all", json!({
      "address": destination,
    })).await.expect("Couldn't transfer the Monero").result;

    Ok(())
  }

  #[cfg(test)]
  pub async fn send_from_wallet(&mut self, address: &str) -> anyhow::Result<()> {
    #[derive(Deserialize, Debug)]
    struct AddressResponse {
      address: String
    }
    #[derive(Deserialize, Debug)]
    struct TransactionResponse {
      tx_hash: String
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

    // Send to the specified address
    let _: TransactionResponse = self.wallet_call("transfer", json!({
      "destinations": [{
        "address": address,
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
          "456BaF31m8NF1DQ9HRA7ZJ7JJZMVLw1ZY5Uzev5q7QBxFPqkyy1vNRN2Yvn43sE6LLYtQtLH16HKjHDhn1W7a2Wy1aWbp3U"
        },
        "amount_of_blocks": 10
      }
    }))).await?;
    Ok(())
  }
}
