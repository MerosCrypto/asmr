use group::Group;
use jubjub::{Fr, SubgroupPoint};

// SKG is used as the primary basepoint, as `ask` is what the atomic secret is, and `ask`'s public key is defined as its product
// JubJub's native generator is used as the alternate basepoint
use zcash_primitives::constants::SPENDING_KEY_GENERATOR;

use dleq::engines::{BasepointProvider, ff_group::FfGroupEngine, jubjub::JubjubConversions};

// DLEqEngine which uses custom basepoints, as explained above
pub struct JubjubBasepoints;
impl BasepointProvider for JubjubBasepoints {
  type Point = SubgroupPoint;

  fn basepoint() -> Self::Point {
    SPENDING_KEY_GENERATOR
  }

  fn alt_basepoint() -> Self::Point {
    SubgroupPoint::generator()
  }
}
// Called Sapling as despite being for the Jubjub curve, JubjubEngine exists using the Jubjub basepoint
pub type SaplingEngine = FfGroupEngine<Fr, SubgroupPoint, JubjubConversions, JubjubBasepoints>;

// While we'd generally still need adaptor signature code here, Jubjub is never used in a way where they're needed
// Therefore, it isn't implemented
