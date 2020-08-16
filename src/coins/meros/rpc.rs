
use std::{
  marker::Send,
  str::FromStr,
  fmt::Debug,
  io::prelude::*,
  net::{TcpStream, SocketAddr}
};

use log::debug;

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::json;

use tokio::task;

use crate::{
  coins::{
    meros::{
      transaction::Input,
      engine::MerosConfig
    }
  }
};


pub struct MerosRpc(SocketAddr);

impl MerosRpc {
  pub fn new(config: &MerosConfig) -> anyhow::Result<MerosRpc> {
    Ok(MerosRpc(config.address))
  }

  async fn rpc_call<
    Params: Clone + Send + Sync + Serialize + Debug + 'static,
    Response: Send + DeserializeOwned + Debug + 'static
  >(&self, method: String, params: Params) -> anyhow::Result<Response> {
    #[derive(Serialize)]
    struct FullParams<'a, T> {
      jsonrpc: &'a str,
      id: (),
      method: &'a str,
      params: T,
    }

    #[derive(Deserialize, Debug)]
    #[serde(untagged)]
    enum FullResponse<T> {
      Err {
        error: serde_json::Value
      },
      Ok {
        result: T
      },
    }

    let ip = self.0.clone();
    let method_clone = method.clone();
    let params_clone = params.clone();
    let parsed_res = task::spawn_blocking(move || -> anyhow::Result<FullResponse<Response>> {
      let mut stream = TcpStream::connect(ip)?;
      stream.write_all(
        serde_json::to_string(
          &FullParams {
            jsonrpc: "2.0",
            id: (),
            method: &method_clone,
            params: params_clone
          }
        )?.as_ref()
      )?;
      Ok(
        serde_json::from_value(
          serde_json::Value::deserialize(
            &mut serde_json::de::Deserializer::from_reader(&mut stream)
          )?
        ).map_err(|_| anyhow::anyhow!("Meros request failed due to incompatible RPC version"))?
      )
    }).await??;
    debug!("RPC call to {} with {:?} finished.", method, params);

    match parsed_res {
      FullResponse::Err { error } => anyhow::bail!("Meros RPC returned an error: {}", error),
      FullResponse::Ok { result } => Ok(result),
    }
  }

  pub async fn get_utxos(&mut self, address: String) -> Vec<Input> {
    self.rpc_call("transactions_getUTXOs".to_string(), [address]).await.expect("Couldn't call transactions.getUTXOs")
  }

  pub async fn get_transaction_output_value(&mut self, input: Input) -> anyhow::Result<u64> {
    #[derive(Deserialize, Debug)]
    struct OutputResponse {
      amount: String
    };
    #[derive(Deserialize, Debug)]
    struct TxResponse {
      outputs: Vec<OutputResponse>
    };

    let tx: TxResponse = self.rpc_call("transactions_getTransaction".to_string(), [input.hash]).await?;
    if tx.outputs.len() <= (input.nonce as usize) {
      anyhow::bail!("Transaction doesn't have an output with that index");
    }
    Ok(u64::from_str(&tx.outputs[(input.nonce as usize)].amount).expect("Meros didn't return a String for the output value"))
  }

  pub async fn get_confirmed(&mut self, hash: String) -> anyhow::Result<bool> {
    #[derive(Deserialize, Debug)]
    struct StatusResponse {
      verified: bool
    };

    let status: StatusResponse = self.rpc_call("consensus_getStatus".to_string(), [hash]).await?;
    Ok(status.verified)
  }

  pub async fn publish_send(&mut self, tx: Vec<u8>) -> anyhow::Result<()> {
    let result = self.rpc_call("transactions_publishSend".to_string(), [hex::encode(tx)]).await?;
    if result {
      Ok(())
    } else {
      anyhow::bail!("Published an invalid send");
    }
  }

  pub async fn get_send_difficulty(&mut self) -> u32 {
    self.rpc_call("consensus_getSendDifficulty".to_string(), json!([])).await.expect("Couldn't get the send difficulty")
  }

  #[cfg(test)]
  pub async fn send(&mut self, address: String) -> anyhow::Result<()> {
    let _: String = self.rpc_call("personal_send".to_string(), json!([address, "1"])).await?;
    Ok(())
  }
}
