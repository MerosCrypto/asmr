mod dl_eq;
mod secp_dl_eq;
mod ves;
mod serialization;
mod coin_specific;

#[cfg_attr(not(feature = "test_litecoin_node"), allow(dead_code))]
mod swap;
#[cfg(all(feature = "test_litecoin_node", feature = "test_nano_node"))]
mod ltc_and_nano;
#[cfg(all(feature = "test_litecoin_node", feature = "test_monero_node"))]
mod ltc_and_xmr;
