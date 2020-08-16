pub mod secp256k1_engine;
pub mod ed25519_engine;

use serde::{Serialize, Deserialize, de::DeserializeOwned};

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct KeyBundle {
  pub dl_eq: Vec<u8>,
  pub B: Vec<u8>,
  pub BR: Vec<u8>,
  pub scripted_destination: Vec<u8>
}

impl KeyBundle {
  pub fn serialize(&self) -> Vec<u8> {
    bincode::serialize(self).expect("Failed to serialize dleq proof")
  }

  pub fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
    Ok(bincode::deserialize(bytes)?)
  }
}

pub struct Commitment<Engine: CryptEngine> {
  pub blinding_key: Engine::PrivateKey,
  pub commitment: Engine::PublicKey,
  pub commitment_minus_one: Engine::PublicKey,
}

pub trait CryptEngine: Sized {
  type PrivateKey: PartialEq + Serialize + DeserializeOwned + Clone + Sized + Send + Sync + 'static;
  type PublicKey: PartialEq + Serialize + DeserializeOwned + Clone + Sized + Send + Sync + 'static;
  type Signature: PartialEq + Clone + Sized + Send + Sync + 'static;
  type EncryptedSignature: PartialEq + Clone + Sized + Send + Sync + 'static;

  fn new_private_key() -> Self::PrivateKey;
  fn to_public_key(key: &Self::PrivateKey) -> Self::PublicKey;

  fn bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey>;
  fn bytes_to_public_key(bytes: &[u8]) -> anyhow::Result<Self::PublicKey>;
  fn bytes_to_signature(bytes: &[u8]) -> anyhow::Result<Self::Signature>;
  fn bytes_to_encrypted_signature(bytes: &[u8]) -> anyhow::Result<Self::EncryptedSignature>;
  fn little_endian_bytes_to_private_key(bytes: [u8; 32]) -> anyhow::Result<Self::PrivateKey>;
  fn private_key_to_little_endian_bytes(key: &Self::PrivateKey) -> [u8; 32];

  fn dl_eq_generate_commitments(key: [u8; 32]) -> anyhow::Result<Vec<Commitment<Self>>>;
  fn dl_eq_compute_signature_s(nonce: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PrivateKey) -> anyhow::Result<Self::PrivateKey>;
  #[allow(non_snake_case)]
  fn dl_eq_compute_signature_R(s_value: &Self::PrivateKey, challenge: [u8; 32], key: &Self::PublicKey) -> anyhow::Result<Self::PublicKey>;
  fn dl_eq_commitment_sub_one(commitment: &Self::PublicKey) -> anyhow::Result<Self::PublicKey>;
  fn dl_eq_reconstruct_key<'a>(commitments: impl Iterator<Item = &'a Self::PublicKey>) -> anyhow::Result<Self::PublicKey>;
  fn dl_eq_blinding_key_to_public(key: &Self::PrivateKey) -> anyhow::Result<Self::PublicKey>;

  fn private_key_to_bytes(key: &Self::PrivateKey) -> [u8; 32];
  fn public_key_to_bytes(key: &Self::PublicKey) -> Vec<u8>;
  fn signature_to_bytes(sig: &Self::Signature) -> Vec<u8>;
  fn encrypted_signature_to_bytes(sig: &Self::EncryptedSignature) -> Vec<u8>;

  fn encrypted_sign(
    signing_key: &Self::PrivateKey,
    encryption_key: &Self::PublicKey,
    message: &[u8]
  ) -> anyhow::Result<Self::EncryptedSignature>;
  fn encrypted_verify(
    signing_key: &Self::PublicKey,
    encryption_key: &Self::PublicKey,
    ciphertext: &Self::EncryptedSignature,
    message: &[u8]
  ) -> anyhow::Result<()>;
  fn decrypt_signature(sig: &Self::EncryptedSignature, key: &Self::PrivateKey) -> anyhow::Result<Self::Signature>;
  /// Given the public encryption key, as well as the encrypted and decrypted signatures, extracts the private encryption key.
  fn recover_key(encryption_key: &Self::PublicKey, ciphertext: &Self::EncryptedSignature, sig: &Self::Signature) -> anyhow::Result<Self::PrivateKey>;
}
