use std::fmt::Debug;

use log::debug;

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::json;

use bitcoin::{blockdata::transaction::Transaction, consensus::deserialize};

use crate::coins::btc::engine::BtcConfig;

#[derive(Serialize)]
struct FullParams<'a, T> {
  jsonrpc: &'a str,
  id: (),
  method: &'a str,
  params: T
}

#[derive(Deserialize, Debug)]
struct InfoResponse {
  blockchain_height: isize
}

#[derive(Deserialize, Debug)]
pub struct UnspentInputResponse {
  pub height: u32,
  pub tx_hash: String,
  pub tx_pos: u32,
  pub value: u64
}

#[derive(Debug)]
pub struct AddressHistoryItem {
  pub tx: Transaction,
  pub height: isize,
  pub confirmations: isize,
}

pub struct BtcRpc {
  url: String,
  #[allow(dead_code)]
  btc_url: Option<String>
}

impl BtcRpc {
  pub fn new(config: &BtcConfig) -> anyhow::Result<BtcRpc> {
    Ok(BtcRpc {
      url: config.url.clone(),
      btc_url: config.btc_url.clone()
    })
  }

  async fn rpc_call<
    Params: Serialize + Debug,
    Response: DeserializeOwned + Debug
  >(&self, method: &str, params: &Params) -> anyhow::Result<Response> {
    #[derive(Deserialize, Debug)]
    #[serde(untagged)]
    enum FullResponse<T> {
      Err {
        error: String,
      },
      Ok {
        result: T,
      },
    }

    let client = reqwest::Client::new();
    let res =
      client.post(&self.url)
      .json(
        &FullParams {
          jsonrpc: "2.0",
          id: (),
          method,
          params
        }
      )
      .send()
      .await?
      .text()
      .await?;
    debug!("RPC call to {} with {:?} returned {}", method, params, &res);
    let parsed_res: FullResponse<Response> = serde_json::from_str(&res)
      .map_err(|_| anyhow::anyhow!("Electrum request failed due to incompatible RPC version (method not found)"))?;
    match parsed_res {
      FullResponse::Err { error } => anyhow::bail!("Electrum RPC returned an error: {}", error),
      FullResponse::Ok { result } => Ok(result),
    }
  }

  pub async fn get_spendable(&self, address: &str) -> anyhow::Result<Vec<UnspentInputResponse>> {
    self.rpc_call("getaddressunspent", &[address]).await
  }

  pub async fn get_fee_per_byte(&self) -> anyhow::Result<u64> {
    // TODO: Revisit. Electrum returns fees in sats/kvByte and our size calculations are off
    Ok(100)
  }

  pub async fn get_transaction(&self, hash_hex: &str) -> anyhow::Result<Transaction> {
    let tx: String = self.rpc_call("gettransaction", &[hash_hex]).await?;
    let decoded_hex = hex::decode(tx).expect("Electrum returned a transaction that wasn't stored as hex");
    Ok(deserialize(&decoded_hex).expect("Electrum returned a transaction we couldn't deserialize"))
  }

  pub async fn get_height(&self) -> isize {
    let info: InfoResponse = self.rpc_call("getinfo", &json!([])).await.expect("Couldn't get the network info");
    info.blockchain_height
  }

  pub async fn get_address_history(&self, address: &str) -> Vec<AddressHistoryItem> {
    #[derive(Deserialize, Debug)]
    struct AddressHistoryResponse {
      fee: Option<u64>,
      height: isize,
      tx_hash: String
    };

    let history: Vec<AddressHistoryResponse> = self.rpc_call(
      "getaddresshistory",
      &[address]
    ).await.expect("Couldn't get the history of an address; this should only occur if we generated an invalid address");

    let mut result = Vec::new();
    let chain_height = self.get_height().await;
    for tx in history {
      result.push(
        AddressHistoryItem {
          tx: self.get_transaction(&tx.tx_hash).await.expect("Couldn't get a transaction part of an address's history"),
          confirmations: if tx.height < 1 {tx.height} else {chain_height - tx.height + 1},
          height: tx.height
        }
      );
    }
    result
  }

  pub async fn publish(&self, tx: &[u8]) -> anyhow::Result<String> {
    self.rpc_call("broadcast", &[hex::encode(tx)]).await
  }

  #[cfg(test)]
  pub async fn send_from_electrum(&self, address: &str) -> anyhow::Result<()> {
    let tx: String = self
      .rpc_call("payto", &json!([address, 0.01]))
      .await?;
    let _: String = self.rpc_call("broadcast", &[tx]).await.expect("Couldn't publish the transaction");
    self.mine_block().await
  }

  #[cfg(test)]
  pub async fn mine_block(&self) -> anyhow::Result<()> {
    let address: String = self.rpc_call("getunusedaddress", &json!([])).await?;
    let client = reqwest::Client::new();
    let res: serde_json::Value =
      client.post(&self.btc_url.clone().expect("Calling directly to BTCd except no URL was specified"))
      .json(
        & FullParams {
          jsonrpc: "2.0",
          id: (),
          method: "generatetoaddress",
          params: json!([1, address])
        }
      )
      .send()
      .await?
      .json()
      .await?;
    debug!("Bitcoin generatetoaddress response: {}", serde_json::to_string(&res)?);
    Ok(())
  }
}
