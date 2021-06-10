use std::{
  convert::TryInto,
  fmt::Debug
};
use log::debug;

use rand::{RngCore, rngs::OsRng};

use digest::Digest;

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::json;

use reqwest;

use zcash_primitives::{
  primitives::{ViewingKey, Diversifier, Note},
  sapling::Node,
  merkle_tree::{CommitmentTree, IncrementalWitness},
  keys::{OutgoingViewingKey, ExpandedSpendingKey},
  zip32::ExtendedSpendingKey,
  transaction::{components::Amount, Transaction, builder::Builder},
  note_encryption::try_sapling_note_decryption,
  constants::regtest::{self, HRP_SAPLING_PAYMENT_ADDRESS},
  consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters}
};
use zcash_proofs::prover::LocalTxProver;
use zcash_client_backend::encoding::{encode_payment_address, decode_payment_address};

use crate::crypt_engines::{CryptEngine, jubjub_engine::JubjubEngine};

#[cfg(not(feature = "no_confs"))]
pub const CONFIRMATIONS: isize = 4;
#[cfg(feature = "no_confs")]
pub const CONFIRMATIONS: isize = 1;

#[cfg(test)]
pub const SAPLING_HRP: &str = HRP_SAPLING_PAYMENT_ADDRESS;

// Needed as zcash_primitives provides mainnet (zcash_primitives::consensus::MainNetwork)
// and testnet (zcash_primitives::consensus::TestNetwork) params, yet not regtest
// Expected to be used with:
// ./bin/zcashd --regtest -nuparams=5ba81b19:1 -nuparams=76b809bb:1 -nuparams=2bb40e60:1 -nuparams=f5b9230b:1 -nuparams=e9ff75a6:1
#[derive(Clone)]
struct RegtestParams(());
impl Parameters for RegtestParams {
  fn activation_height(&self, _nu: NetworkUpgrade) -> Option<BlockHeight> {
    Some(BlockHeight::from_u32(1))
  }
  fn coin_type(&self) -> u32 {
    1
  }
  fn hrp_sapling_extended_spending_key(&self) -> &str {
    regtest::HRP_SAPLING_EXTENDED_SPENDING_KEY
  }
  fn hrp_sapling_extended_full_viewing_key(&self) -> &str {
    regtest::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY
  }
  fn hrp_sapling_payment_address(&self) -> &str {
    HRP_SAPLING_PAYMENT_ADDRESS
  }
  fn b58_pubkey_address_prefix(&self) -> [u8; 2] {
    regtest::B58_PUBKEY_ADDRESS_PREFIX
  }
  fn b58_script_address_prefix(&self) -> [u8; 2] {
    regtest::B58_SCRIPT_ADDRESS_PREFIX
  }
  fn is_nu_active(&self, _nu: NetworkUpgrade, _height: BlockHeight) -> bool {
     true
  }
}

#[derive(Serialize)]
struct FullParams<'a, T> {
  jsonrpc: &'a str,
  id: (),
  method: &'a str,
  params: T
}

#[derive(Deserialize, Debug)]
struct EmptyResponse {}

#[derive(Clone, Deserialize)]
pub struct ZecConfig {
  pub url: String,
  pub destination: String,
  pub refund: String
}

#[derive(Serialize, Deserialize)]
pub struct ZecKeys {
  pub dl_eq: Vec<u8>,
  pub nsk: [u8; 32]
}

pub struct ZecEngine {
  pub config: ZecConfig,
  prover: LocalTxProver,

  pub ask: Option<<JubjubEngine as CryptEngine>::PrivateKey>,
  pub nsk: <JubjubEngine as CryptEngine>::PrivateKey,
  pub vk: Option<ViewingKey>,
  diversifier: Option<Diversifier>,

  height_at_start: isize,
  tree: CommitmentTree<Node>,

  // Other coins would generally return these, yet it's advantageous to have them inlined to reduce code reuse
  // Especially due to the considerations of them as privacy tech
  // It does change the mutability of get_deposit, yet that already had to be mutable due to the above tree
  // Unless that was also passed around, in which case we just have a secondary struct for effectively no reason
  witness: Option<IncrementalWitness<Node>>,
  note: Option<Note>,
  branch: Option<BranchId>,

  #[cfg(test)]
  wallet_address: String
}

impl ZecEngine {
  pub async fn new(config: ZecConfig) -> anyhow::Result<ZecEngine> {
    let mut result = ZecEngine {
      config,
      // Inline the params directly into the binary
      prover: LocalTxProver::from_bytes(
        std::include_bytes!("data/sapling-spend.params"),
        std::include_bytes!("data/sapling-output.params")
      ),

      ask: None,
      nsk: JubjubEngine::new_private_key(),
      vk: None,
      diversifier: None,

      height_at_start: -1,
      tree: CommitmentTree::<Node>::empty(),

      witness: None,
      note: None,
      branch: None,

      #[cfg(test)]
      wallet_address: "".to_string()
    };
    result.height_at_start = result.get_height().await;

    #[allow(non_snake_case)]
    #[derive(Deserialize, Debug)]
    struct CommitmentResponse {
      finalState: String
    }
    #[derive(Deserialize, Debug)]
    struct SaplingResponse {
      commitments: CommitmentResponse
    }
    #[derive(Deserialize, Debug)]
    struct TreeResponse {
      sapling: SaplingResponse
    }
    let tree: TreeResponse = result.rpc_call("z_gettreestate", &json![[result.height_at_start.to_string()]]).await?;
    result.tree = CommitmentTree::<Node>::read(&*hex::decode(tree.sapling.commitments.finalState).expect("ZCashd returned a non-hex tree"))?;

    #[cfg(test)]
    {
      result.wallet_address = result.rpc_call("z_getnewaddress", &json!([])).await?;
    }

    Ok(result)
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
    let res: String =
      client.post(&self.config.url)
      .json(
        & FullParams {
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
      .map_err(|_| anyhow::anyhow!("ZCashd didn't respond with expected JSON"))?;
    match parsed_res {
      FullResponse::Err { error } => anyhow::bail!("ZCashd RPC returned an error: {}", error),
      FullResponse::Ok { result } => Ok(result),
    }
  }

  pub fn set_ak_nsk(
    &mut self,
    ak: &<JubjubEngine as CryptEngine>::PublicKey,
    nsk: &<JubjubEngine as CryptEngine>::PrivateKey
  ) {
    self.nsk = JubjubEngine::add_private_key(&self.nsk, nsk);
    let vk = ViewingKey {
      ak: JubjubEngine::add_public_key(&JubjubEngine::to_public_key(
        &self.ask.as_ref().expect("Key exchange occurring before generating keys")),
        ak
      ),
      nk: JubjubEngine::mul_by_proof_generation_generator(&self.nsk)
    };

    // Seemingly random, generated using common data so we don't need to send another mutual variable
    // Avoids the need for a more complicated method/a master secret
    // This should likely be improved to the algorithm described by the Sapling protocol documentation
    let mut diversifier = [0; 11];
    diversifier.copy_from_slice(&sha2::Sha256::new()
      // DST for extra safety. If for some reason H(self.nsk) must be kept secret, this ensures it
      // While we'd only leak 11 bytes, that's still a 88-bit reduction
      .chain("asmr diversifier")
      .chain(&JubjubEngine::private_key_to_bytes(&self.nsk))
      .finalize()[..11]
    );
    // Recursively hash the diversifier until a valid one is found
    // This is also somewhat mirrored by the protocol's definition of how to generate a diversifier
    // That also has multiple failure values and takes the first which works
    while vk.to_payment_address(Diversifier(diversifier)).is_none() {
      let diversifier_copy = diversifier;
      diversifier.copy_from_slice(&sha2::Sha256::digest(&diversifier_copy)[..11]);
    }

    self.vk = Some(vk);
    self.diversifier = Some(Diversifier(diversifier));
  }

  pub fn get_deposit_address(&mut self) -> String {
    encode_payment_address(
      HRP_SAPLING_PAYMENT_ADDRESS,
      &self
        .vk.as_ref().expect("Getting deposit address before sharing keys")
        // unwrap as it'd have the same expect message as above
        .to_payment_address(self.diversifier.clone().unwrap())
        .expect("Generated an invalid diversifier when sharing keys")
    )
  }

  async fn get_height(&self) -> isize {
    #[derive(Deserialize, Debug)]
    struct InfoResponse {
      blocks: isize
    }
    let info: InfoResponse = self.rpc_call("getinfo", &json!([])).await.expect("Couldn't get the network info");
    info.blocks
  }

  async fn get_transaction(&self, tx_hash_hex: &str, block_hash_hex: &str) -> anyhow::Result<Transaction> {
    let res: String = self.rpc_call("getrawtransaction", &json!([
      tx_hash_hex, 0, block_hash_hex
    ])).await?;
    let tx = Transaction::read(
      &*hex::decode(&res).expect("ZCashd returned a non-hex block")
    ).expect("ZCashd returned an invalid Transaction");
    Ok(tx)
  }

  async fn get_block_transactions(&self, height: isize) -> anyhow::Result<(Vec<Transaction>, String)> {
    #[derive(Deserialize, Debug)]
    struct BlockResponse {
      hash: String,
      tx: Vec<String>
    }

    let res: BlockResponse = self.rpc_call("getblock", &json!([height.to_string()])).await?;

    let mut result = vec![];
    for tx in res.tx {
      result.push(self.get_transaction(&tx, &res.hash).await?);
    }
    Ok((result, res.hash))
  }

  async fn get_confirmations(&self, tx_hash_hex: &str, block_hash_hex: &str) -> anyhow::Result<isize> {
    #[derive(Deserialize, Debug)]
    struct ConfirmationResponse {
      in_active_chain: bool,
      confirmations: isize
    }

    let res: ConfirmationResponse = self.rpc_call("getrawtransaction", &json!([
      tx_hash_hex, 1, block_hash_hex
    ])).await?;
    if !res.in_active_chain {
      anyhow::bail!("Transaction was reorganized off the chain");
    }
    Ok(res.confirmations)
  }

  pub async fn get_deposit(&mut self, vk: &ViewingKey, wait: bool) -> anyhow::Result<Option<u64>> {
    let mut block = self.height_at_start + 1;
    let mut block_hash = "".to_string();
    let mut tx_hash = "".to_string();
    let mut funds;
    'outer: loop {
      while self.get_height().await > block {
        let txs = self.get_block_transactions(block).await?;
        for tx in txs.0 {
          let data = &*tx;
          for output in data.shielded_outputs.clone() {
            let node = Node::new(output.cmu.into());
            self.tree.append(node).unwrap();
            if self.witness.is_some() {
              let mut witness = self.witness.clone().unwrap();
              witness.append(node).unwrap();
              self.witness = Some(witness);
            }

            if self.note.is_none() {
              funds = try_sapling_note_decryption(
                &RegtestParams(()),
                BlockHeight::from_u32(block as u32),
                &vk.ivk(),
                &output.ephemeral_key,
                &output.cmu,
                &output.enc_ciphertext
              );

              if funds.is_some() {
                self.note = Some(funds.unwrap().0);
                self.witness = Some(IncrementalWitness::from_tree(&self.tree));
                self.branch = Some(BranchId::for_height(&RegtestParams(()), BlockHeight::from_u32(block as u32)));
                // The TXID is stored in little endian, forcing this
                tx_hash = hex::encode(&tx.txid().0.to_vec().into_iter().rev().map(|x| x.to_owned()).collect::<Vec<u8>>());
                block_hash = txs.1.clone();
              }
            }
          }
        }

        #[derive(Deserialize, Debug)]
        struct BlockResponse {
          finalsaplingroot: String
        }
        let block_res: BlockResponse = self.rpc_call("getblock", &json!([block.to_string()])).await?;

        if dbg!(Node::new(
          hex::decode(block_res.finalsaplingroot).expect("Sapling root wasn't hex")
            .into_iter().rev().collect::<Vec<u8>>()[..].try_into().expect("Sapling root wasn't 32 bytes")
        )) != dbg!(self.tree.root()) {
          anyhow::bail!("Block root doesn't match");
        }

        // Only break once we finish this entire block
        if self.note.is_some() {
          break 'outer;
        }

        block += 1;
      }
      if !wait {
        return Ok(None);
      }
      tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
    }

    while self.get_confirmations(&tx_hash, &block_hash).await? < CONFIRMATIONS {
      if !wait {
        return Ok(None);
      }
      tokio::time::delay_for(std::time::Duration::from_secs(10)).await;
    }

    return Ok(Some(self.note.as_ref().unwrap().value));
  }

  pub async fn claim(
    &self,
    ask: <JubjubEngine as CryptEngine>::PrivateKey,
    destination: &str
  ) -> anyhow::Result<()> {
    let destination = decode_payment_address(HRP_SAPLING_PAYMENT_ADDRESS, destination)?.expect("Invalid destination address");

    // The below function only uses the expsk field of esk
    // We have a expsk; we don't have a esk
    // We also can't construct a dummy esk with the field we do have due to private fields
    // Constructs and overrides a legitimate esk with our custom keys to satisfy the below API
    let mut esk = ExtendedSpendingKey::master(&vec![0]);
    let mut stub_ovk = [0; 32];
    OsRng.fill_bytes(&mut stub_ovk);
    esk.expsk = ExpandedSpendingKey {
      ask: JubjubEngine::get_scalar(
        &JubjubEngine::add_private_key(&self.ask.as_ref().expect("Claiming despite never setting our key share"), &ask)
      ),
      nsk: JubjubEngine::get_scalar(&self.nsk),
      ovk: OutgoingViewingKey(stub_ovk)
    };

    let mut builder = Builder::new(RegtestParams(()), BlockHeight::from_u32(self.get_height().await as u32));
    builder.add_sapling_spend(
      esk,
      self.diversifier.clone().expect("Claiming despite never sharing keys"),
      self.note.clone().expect("Didn't set the note when funds were received"),
      self.witness.clone().expect("Didn't set the witness when funds were received").path().unwrap()
    )?;
    builder.add_sapling_output(
      None,
      destination,
      Amount::from_u64(self.note.as_ref().unwrap().value - 10000).expect("Invalid transaction amount; trying to swap < 10k sats?"),
      None
    )?;

    let tx = builder.build(self.branch.expect("Didn't set the branch when funds were received"), &self.prover)?.0;
    let mut raw = vec![];
    tx.write(&mut raw).unwrap();
    let _: String = self.rpc_call("sendrawtransaction", &json!([hex::encode(raw)])).await?;

    Ok(())
  }

  #[cfg(test)]
  pub async fn mine_block(&self) -> anyhow::Result<()> {
    for _ in 0 .. 10 {
      #[derive(Deserialize, Debug)]
      struct ShieldResponse {
        opid: String
      }
      let mut shield: anyhow::Result<ShieldResponse> = self.rpc_call("z_shieldcoinbase", &json!([
        "*", &self.wallet_address
      ])).await;

      if shield.is_ok() {
        #[derive(Deserialize, Debug)]
        struct StatusResponse {
          status: String
        }
        while {
          let status: Vec<StatusResponse> = self.rpc_call("z_getoperationstatus", &json!([[shield.as_ref().unwrap().opid]])).await?;
          if status[0].status == "failed" {
            tokio::time::delay_for(std::time::Duration::from_secs(1)).await;
            shield = self.rpc_call("z_shieldcoinbase", &json!([
              "*", &self.wallet_address
            ])).await;
          }
          status[0].status != "success"
        } {
          tokio::time::delay_for(std::time::Duration::from_secs(1)).await;
        }
      }
      let _: Vec<String> = self.rpc_call("generate", &json!([1])).await?;
    }

    Ok(())
  }

  #[cfg(test)]
  pub async fn send_from_wallet(&mut self) -> anyhow::Result<String> {
    for _ in 0 .. 11 {
      self.mine_block().await?;
    }

    let our_address = self.get_deposit_address();
    let send: String = self.rpc_call("z_sendmany", &json!([
      &self.wallet_address, [{"address": our_address, "amount": 1}]
    ])).await?;

    // This is needed for some reason
    // Given that we wait for the operation to succeed before mining blocks, and wait on that, I have no idea why
    // Potentially a delay in parsing the info relevant to our wallet out of the above sapling send
    // Therefore, this should be updated, yet for now, it works
    tokio::time::delay_for(std::time::Duration::from_secs(3)).await;

    #[derive(Deserialize, Debug)]
    struct StatusResponse {
      status: String
    }
    while {
      let status: Vec<StatusResponse> = self.rpc_call("z_getoperationstatus", &json!([[send]])).await?;
      if status[0].status == "failed" {
        anyhow::bail!("Send to wallet failed");
      }
      status[0].status != "success"
    } {
      tokio::time::delay_for(std::time::Duration::from_secs(1)).await;
    }
    self.mine_block().await?;

    Ok(send)
  }
}
