use crate::{
    leaf::{leaf_hash, CanonicalSerialize},
    tree_math::*,
};

use core::marker::PhantomData;
use std::io::Error as IoError;

use digest::Digest;
use thiserror::Error;

/// A merkle tree with methods and byte representations compatible Certificate Transparency logs
/// (RFC 6962)
#[derive(Clone, Debug)]
pub struct CtMerkleTree<H, T>
where
    H: Digest,
    T: CanonicalSerialize,
{
    /// The leaves of this tree. This contains all the items
    pub(crate) leaves: Vec<T>,
    /// The internal nodes of the tree. This contains all the hashes
    pub(crate) internal_nodes: Vec<digest::Output<H>>,

    _marker: PhantomData<H>,
}

impl<H, T> Default for CtMerkleTree<H, T>
where
    H: Digest,
    T: CanonicalSerialize,
{
    fn default() -> Self {
        CtMerkleTree {
            leaves: Vec::new(),
            internal_nodes: Vec::new(),
            _marker: PhantomData,
        }
    }
}

/// The root hash of a CT Merkle Tree
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RootHash<H: Digest> {
    pub(crate) root_hash: digest::Output<H>,
    pub(crate) num_leaves: u64,
}

/// An error returned during `CtMerkleTree::self_check()`
#[derive(Debug, Error)]
pub enum ConsistencyError {
    /// An item could not be serialized
    #[error("could not canonically serialize a item")]
    Io(#[from] IoError),

    /// An internal node is missing from the tree
    #[error("tree is missing an internal node")]
    MissingNode,

    /// An internal node has the wrong hash
    #[error("an internal hash is incorrect")]
    IncorrectHash,
}

impl<H, T> CtMerkleTree<H, T>
where
    H: Digest,
    T: CanonicalSerialize,
{
    pub fn new() -> Self {
        Self::default()
    }

    /// Attemtps to push the given item to the list. Errors only when item serialization fails.
    pub fn push(&mut self, new_val: T) -> Result<(), IoError> {
        // We push the new value, a node for its hash, and a node for its parent (assuming the tree
        // isn't a singleton). The hash and parent nodes will get overwritten by recalculate_path()
        self.leaves.push(new_val);
        self.internal_nodes.push(digest::Output::<H>::default());

        // If the tree is not a singleton, add a new parent node
        if self.internal_nodes.len() > 1 {
            self.internal_nodes.push(digest::Output::<H>::default());
        }

        // Recalculate the tree starting at the new leaf
        let num_leaves = self.leaves.len() as u64;
        let new_leaf_idx = LeafIdx::new(num_leaves - 1);
        self.recaluclate_path(new_leaf_idx)
    }

    /// Checks the consistency of this tree. This can take a while if the tree is large. Run this
    /// if you've deserialized this tree and don't trust the source. Other methods will panic or
    /// behave oddly if your are using a malformed tree.
    pub fn self_check(&self) -> Result<(), ConsistencyError> {
        // Go through every level of the tree, checking hashes
        let num_leaves = self.leaves.len() as u64;
        let num_nodes = num_internal_nodes(num_leaves);

        // Start on level 0. We check the leaf hashes
        for (leaf_idx, leaf) in self.leaves.iter().enumerate() {
            let leaf_hash_idx: InternalIdx = LeafIdx::new(leaf_idx as u64).into();

            // Compute the leaf hash and retrieve the stored leaf hash
            let expected_hash = leaf_hash::<H, T>(leaf)?;
            let stored_hash = match self.internal_nodes.get(leaf_hash_idx.usize()) {
                None => Err(ConsistencyError::MissingNode),
                Some(h) => Ok(h),
            }?;

            // If the hashes don't match, that's an error
            if stored_hash != &expected_hash {
                return Err(ConsistencyError::IncorrectHash);
            }
        }

        // Now go through the rest of the levels, checking that the current node equals the hash of
        // the children.
        for level in 1..=root_idx(num_leaves as u64).level() {
            // First index on level i is 2^i - 1. Each subsequent index at level i is at an offset
            // of 2^(i+1).
            let start_idx = 2u64.pow(level) - 1;
            let step_size = 2usize.pow(level + 1);
            for idx in (start_idx..num_nodes).step_by(step_size) {
                // Get the left and right children, erroring if they don't exist
                let idx = InternalIdx::new(idx);
                let left_child = self
                    .internal_nodes
                    .get(idx.left_child().usize())
                    .ok_or(ConsistencyError::MissingNode)?;
                let right_child = self
                    .internal_nodes
                    .get(idx.right_child(num_leaves).usize())
                    .ok_or(ConsistencyError::MissingNode)?;

                // Compute the expected hash and get the stored hash
                let expected_hash = parent_hash::<H>(left_child, right_child);
                let stored_hash = self
                    .internal_nodes
                    .get(idx.usize())
                    .ok_or(ConsistencyError::MissingNode)?;

                // If the hashes don't match, that's an error
                if stored_hash != &expected_hash {
                    return Err(ConsistencyError::IncorrectHash);
                }
            }
        }

        Ok(())
    }

    /// Recalculates the hashes on the path from `leaf_idx` to the root. The path MUST already
    /// exist, i.e., this tree cannot be missing internal nodes.
    fn recaluclate_path(&mut self, leaf_idx: LeafIdx) -> Result<(), IoError> {
        // First update the leaf hash
        let leaf = &self.leaves[leaf_idx.usize()];
        let mut cur_idx: InternalIdx = leaf_idx.into();
        self.internal_nodes[cur_idx.usize()] = leaf_hash::<H, T>(leaf)?;

        // Get some data for the upcoming loop
        let num_leaves = self.leaves.len() as u64;
        let root_idx = root_idx(num_leaves as u64);

        // Now iteratively update the parent of cur_idx
        while cur_idx != root_idx {
            let parent_idx = cur_idx.parent(num_leaves);

            // Get the values of the current node and its sibling
            let cur_node = &self.internal_nodes[cur_idx.usize()];
            let sibling = {
                let sibling_idx = &cur_idx.sibling(num_leaves);
                &self.internal_nodes[sibling_idx.usize()]
            };

            // Compute the parent hash. If cur_node is to the left of the parent, the hash is
            // H(0x01 || cur_node || sibling). Otherwise it's H(0x01 || sibling || cur_node).
            if cur_idx.is_left(num_leaves) {
                self.internal_nodes[parent_idx.usize()] = parent_hash::<H>(cur_node, sibling);
            } else {
                self.internal_nodes[parent_idx.usize()] = parent_hash::<H>(sibling, cur_node);
            }

            // Go up a level
            cur_idx = parent_idx;
        }

        // One the above loop is done, we've successfully updated the root node
        Ok(())
    }

    /// Returns the root hash of this tree. The value and type uniquely describe this tree.
    pub fn root(&self) -> RootHash<H> {
        let num_leaves = self.leaves.len() as u64;
        let root_idx = root_idx(num_leaves as u64);
        let hash = &self.internal_nodes[root_idx.usize()];

        RootHash {
            root_hash: hash.clone(),
            num_leaves,
        }
    }

    /// Tries to get the item at the given index
    pub fn get(&self, idx: u64) -> Option<&T> {
        self.leaves.get(idx as usize)
    }

    /// Returns the number of items
    pub fn len(&self) -> usize {
        self.leaves.len()
    }
}

const PARENT_HASH_PREFIX: &[u8] = &[0x01];

/// Computes the parent of the two given subtrees
pub(crate) fn parent_hash<H: Digest>(
    left: &digest::Output<H>,
    right: &digest::Output<H>,
) -> digest::Output<H> {
    let mut hasher = H::new_with_prefix(PARENT_HASH_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    use rand::{thread_rng, RngCore};
    use sha2::Sha256;

    // Leaves are 32-byte bytestrings
    pub(crate) type T = [u8; 32];
    // The hash is SHA-256
    pub(crate) type H = Sha256;

    // Creates a random T
    pub(crate) fn rand_val<R: RngCore>(mut rng: R) -> T {
        let mut val = T::default();
        rng.fill_bytes(&mut val);

        val
    }

    // Creates a random CtMerkleTree
    pub(crate) fn rand_tree<R: RngCore>(mut rng: R) -> CtMerkleTree<H, T> {
        let mut v = CtMerkleTree::<H, T>::default();

        // Add a bunch of items. This tree will not be a full tree.
        for i in 0..230 {
            let val = rand_val(&mut rng);
            v.push(val)
                .expect(&format!("push failed at iteration {}", i));
        }

        v
    }

    // Adds a bunch of elements to the tree and then tests the tree's consistency
    #[test]
    fn consistency() {
        let mut rng = thread_rng();
        let v = rand_tree(&mut rng);
        v.self_check().expect("self check failed");
    }

    // Tests that an honestly generated membership proof verifies
    #[test]
    fn membership_proof_correctness() {
        let mut rng = thread_rng();

        let v = rand_tree(&mut rng);

        // Check membership at every index
        for idx in 0..v.len() {
            let idx = idx as u64;
            let proof = v.membership_proof(idx);
            let elem = v.get(idx).unwrap();

            // Now check the proof
            let root = v.root();
            root.verify_membership(&elem, idx, &proof.as_ref()).unwrap();
        }
    }
}
