mod jubjub;
mod dl_eq;
mod secp_dl_eq;
mod ves;
mod serialization;
mod coin_specific;

#[cfg_attr(not(feature = "test_bitcoin_node"), allow(dead_code))]
mod swap;
#[cfg(all(feature = "test_bitcoin_node", feature = "test_meros_node"))]
mod btc_and_meros;
#[cfg(all(feature = "test_bitcoin_node", feature = "test_nano_node"))]
mod btc_and_nano;
#[cfg(all(feature = "test_bitcoin_node", feature = "test_monero_node"))]
mod btc_and_xmr;
#[cfg(all(feature = "test_bitcoin_node", feature = "test_zcash_node"))]
mod btc_and_zec;
