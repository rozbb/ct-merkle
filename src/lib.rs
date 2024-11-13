// The doc_cfg feature is only available in nightly. It lets us mark items in documentation as
// dependent on specific features.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![doc = include_str!("../README.md")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub use digest;

mod consistency;
mod error;
mod inclusion;
pub mod mem_backed_tree;
mod tree_util;

#[cfg(test)]
mod test_util;

pub use consistency::*;
pub use error::*;
pub use inclusion::*;
pub use tree_util::*;

use digest::Digest;
use subtle::ConstantTimeEq;

/// The root hash of a Merkle tree. This uniquely represents the tree.
#[derive(Clone, Debug)]
pub struct RootHash<H: Digest> {
    /// The root hash of the Merkle tree that this root represents
    root_hash: digest::Output<H>,

    /// The number of leaves in the Merkle tree that this root represents. That is, the number of
    /// items inserted into the [`CtMerkleTree`] that created with `RootHash`.
    num_leaves: u64,
}

impl<H: Digest> PartialEq for RootHash<H> {
    /// Compares this `RootHash` to another in constant time.
    fn eq(&self, other: &RootHash<H>) -> bool {
        self.num_leaves == other.num_leaves() && self.root_hash.ct_eq(&other.root_hash).into()
    }
}

impl<H: Digest> Eq for RootHash<H> {}

impl<H: Digest> RootHash<H> {
    /// Constructs a `RootHash` from the given hash digest and the number of leaves in the tree
    /// that created it.
    pub fn new(digest: digest::Output<H>, num_leaves: u64) -> RootHash<H> {
        RootHash {
            root_hash: digest,
            num_leaves,
        }
    }

    /// Returns the Merkle Tree Hash of the tree that created this `RootHash`.
    ///
    /// This is precisely the Merkle Tree Hash (MTH) of the tree that created it, as defined in [RFC
    /// 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1).
    pub fn as_bytes(&self) -> &digest::Output<H> {
        &self.root_hash
    }

    /// Returns the number of leaves in the tree that created this `RootHash`.
    pub fn num_leaves(&self) -> u64 {
        self.num_leaves
    }
}
