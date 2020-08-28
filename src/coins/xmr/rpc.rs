use std::fmt::Debug;

use log::debug;

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::json;

use reqwest;

use monero::{
  blockdata::{
    transaction::Transaction,
    block::Block
  },
  consensus::encode::deserialize
};

use crate::coins::xmr::engine::XmrConfig;

pub struct XmrRpc {
  daemon: String,
  wallet: String,
  pub height_at_start: isize,
  #[cfg(test)]
  wallet_address: String
}

impl XmrRpc {
  pub async fn new(config: &XmrConfig) -> anyhow::Result<XmrRpc> {
    let mut result = XmrRpc {
      daemon: config.daemon.clone() + "/",
      wallet: config.wallet.clone() + "/",
      height_at_start: -1,
      // TODO: Grab an address from the Monero wallet
      #[cfg(test)]
      wallet_address: "".to_string()
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
    if params.is_some() {
      builder = builder.json(params.as_ref().unwrap());
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

  pub async fn get_height(&self) -> isize {
    #[derive(Deserialize, Debug)]
    struct HeightResponse {
      height: isize
    };

    let res: HeightResponse = self.rpc_call::<Option<()>, _>("get_height", None).await.expect("Failed to get the height");
    res.height
  }

  pub async fn get_fee_per_byte(&self) -> anyhow::Result<(u64, u64)> {
    #[derive(Deserialize, Debug)]
    struct FeeInfo {
      fee: u64,
      quantization_mask: u64
    };

    let res: FeeInfo = self.rpc_call::<Option<()>, _>("get_fee_estimate", None).await?;
    Ok((res.fee, res.quantization_mask))
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
            if txs.txs[0].block_height < 1 {
              txs.txs[0].block_height
            } else {
              self.get_height().await - txs.txs[0].block_height + 1
            }
          )
        )
      }
    )
  }

  pub async fn get_transactions_in_block(&self, height: isize) -> anyhow::Result<Vec<Transaction>> {
    #[derive(Deserialize, Debug)]
    struct BlockResponse {
      blob: String
    }
    #[derive(Deserialize, Debug)]
    struct JsonRpcResponse {
      result: BlockResponse
    }

    let res: JsonRpcResponse = self.rpc_call("json_rpc", Some(json!({
      "jsonrpc": "2.0",
      "id": (),
      "method": "get_block",
      "params": {
        "height": height
      }
    }))).await?;
    let block: Block = deserialize(&hex::decode(&res.result.blob)?).expect("Monero returned a block we couldn't deserialize");
    let mut result = Vec::new();
    for hash in block.tx_hashes {
      result.push(
        self.get_transaction(&hex::encode(hash.as_bytes()))
          .await?
          .expect("Couldn't get transaction included in block")
          .0
      );
    }
    Ok(result)
  }

  pub async fn publish(&self, tx: &[u8]) -> anyhow::Result<()> {
    #[derive(Deserialize, Debug)]
    struct PublishResponse {
      double_spend: bool,
      status: String
    };

    let res: PublishResponse = self.rpc_call("send_raw_transaction", Some(json!({
      "tx_as_hex": hex::encode(tx)
    }))).await?;

    if (res.double_spend) || (res.status != "OK") {
      anyhow::bail!("Double spend/not okay");
    }
    Ok(())
  }

  #[cfg(test)]
  pub async fn send_from_wallet(&self, address: &str) -> anyhow::Result<()> {
    todo!()
  }

  #[cfg(test)]
  pub async fn mine_block(&self) -> anyhow::Result<()> {
    self.rpc_call("generateblocks", Some(json!({
      "wallet_address": self.wallet_address,
      "amount_of_blocks": 1
    }))).await
  }
}
