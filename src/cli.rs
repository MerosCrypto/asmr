use std::{
  str::FromStr,
  fmt,
  path::PathBuf,
  net::SocketAddr
};

use structopt::StructOpt;
use enum_utils::FromStr;
use derive_more::Display;

#[derive(FromStr, Clone, Copy, Debug, PartialEq, Eq)]
#[enumeration(rename_all = "kebab-case")]
pub enum HostOrClient {
  #[enumeration(alias = "h")]
  Host,
  #[enumeration(alias = "c")]
  Client,
  #[enumeration(alias = "hc")]
  HostAndClient,
}

impl HostOrClient {
  pub fn is_host(self) -> bool {
    match self {
      HostOrClient::Host => true,
      HostOrClient::Client => false,
      HostOrClient::HostAndClient => true,
    }
  }

  pub fn is_client(self) -> bool {
    match self {
      HostOrClient::Host => false,
      HostOrClient::Client => true,
      HostOrClient::HostAndClient => true,
    }
  }
}

#[derive(Debug, Display)]
#[display(fmt = "Expected host or client")]
struct HostOrClientError;

fn host_or_client_from_str(s: &str) -> Result<HostOrClient, HostOrClientError> {
  s.parse().map_err(|()| HostOrClientError)
}

#[derive(FromStr, Debug, Clone)]
#[enumeration(rename_all = "lowercase")]
pub enum ScriptedCoin {
  #[enumeration(alias = "btc")]
  Bitcoin,
}

#[derive(FromStr, Debug, Clone)]
#[enumeration(rename_all = "lowercase")]
pub enum UnscriptedCoin {
  #[enumeration(alias = "mr")]
  Meros,
  Nano,
}

enum AnyCoin {
  Scripted(ScriptedCoin),
  Unscripted(UnscriptedCoin),
}

impl FromStr for AnyCoin {
  type Err = CoinPairErr;

  fn from_str(s: &str) -> Result<Self, CoinPairErr> {
    ScriptedCoin::from_str(s).map(AnyCoin::Scripted)
      .or_else(|_| UnscriptedCoin::from_str(s).map(AnyCoin::Unscripted))
      .map_err(|_| CoinPairErr::UnknownCoin(s.into()))
  }
}

#[derive(Clone, Debug)]
pub struct CoinPair {
  pub scripted: ScriptedCoin,
  pub unscripted: UnscriptedCoin,
}

impl fmt::Display for CoinPair {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}-{:?}", self.scripted, self.unscripted)
  }
}

#[derive(Debug, Clone, Display)]
pub enum CoinPairErr {
  #[display(fmt = "Unknown coin {}", "_0")]
  UnknownCoin(String),
  #[display(fmt = "A scripted an unscripted coin are needed, not two coins of the same type")]
  CoinsSameType,
  #[display(fmt = "The two coins in the pair should be dash separated")]
  NotDashSeparated,
}

impl FromStr for CoinPair {
  type Err = CoinPairErr;

  fn from_str(s: &str) -> Result<Self, CoinPairErr> {
    let mut parts = s.splitn(2, '-');
    if let (Some(coin_a), Some(coin_b)) = (parts.next(), parts.next()) {
      let coin_a: AnyCoin = coin_a.parse()?;
      let coin_b: AnyCoin = coin_b.parse()?;
      match (coin_a, coin_b) {
        (AnyCoin::Scripted(scripted), AnyCoin::Unscripted(unscripted))
          | (AnyCoin::Unscripted(unscripted), AnyCoin::Scripted(scripted)) =>
        {
          Ok(CoinPair {
            scripted,
            unscripted,
          })
        }
        _ => Err(CoinPairErr::CoinsSameType),
      }
    } else {
      Err(CoinPairErr::NotDashSeparated)
    }
  }
}

#[derive(StructOpt, Clone)]
pub struct Cli {
  /// Host, trading a scripted coin for an unscripted coin, or client, the reverse.
  #[structopt(parse(try_from_str = host_or_client_from_str))]
  pub host_or_client: HostOrClient,
  /// The TCP address to listen on as the host, or connect to as the client.
  pub tcp_address: SocketAddr,
  /// The pair to trade, e.g. btc-mr.
  pub pair: CoinPair,
  /// The path to a JSON config file for the scripted coin. Defaults to `config/{coin}.json`.
  #[structopt(long)]
  pub scripted_config: Option<PathBuf>,
  /// The path to a JSON config file for the unscripted coin. Defaults to `config/{coin}.json`.
  #[structopt(long)]
  pub unscripted_config: Option<PathBuf>,
}
