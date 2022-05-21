use crate::{
    error::SelfCheckError,
    leaf::{leaf_hash, CanonicalSerialize},
    tree_math::*,
};

use core::marker::PhantomData;
use std::io::Error as IoError;

use digest::Digest;

/// The domain separator used for calculating parent hashes
const PARENT_HASH_PREFIX: &[u8] = &[0x01];

/// An append-only data structure with support for succinct inclusion proofs and consistency
/// proofs. This is implemented as a Merkle tree with methods and byte representations compatible
/// Certificate Transparency logs (RFC 6962).
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

/// The root hash of a [`CtMerkleTree`]
#[derive(Clone, Debug)]
pub struct RootHash<H: Digest> {
    /// The root hash of the Merkle tree that this root represents
    pub root_hash: digest::Output<H>,

    /// The number of leaves in the Merkle tree that this root represents. That is, the number of
    /// items inserted into the [`CtMerkleTree`] that created with `RootHash`.
    pub num_leaves: u64,
}

impl<H: Digest> PartialEq for RootHash<H> {
    fn eq(&self, other: &RootHash<H>) -> bool {
        self.root_hash == other.root_hash
    }
}

impl<H: Digest> Eq for RootHash<H> {}

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

    /// Checks that this tree is well-formed. This can take a while if the tree is large. Run this
    /// if you've deserialized this tree and don't trust the source. If a tree is malformed, other
    /// methods will panic or behave oddly.
    pub fn self_check(&self) -> Result<(), SelfCheckError> {
        // Go through every level of the tree, checking hashes
        let num_leaves = self.leaves.len() as u64;
        let num_nodes = num_internal_nodes(num_leaves);

        // Start on level 0. We check the leaf hashes
        for (leaf_idx, leaf) in self.leaves.iter().enumerate() {
            let leaf_hash_idx: InternalIdx = LeafIdx::new(leaf_idx as u64).into();

            // Compute the leaf hash and retrieve the stored leaf hash
            let expected_hash = leaf_hash::<H, _>(leaf);
            let stored_hash = match self.internal_nodes.get(leaf_hash_idx.usize()) {
                None => Err(SelfCheckError::MissingNode(leaf_hash_idx.usize())),
                Some(h) => Ok(h),
            }?;

            // If the hashes don't match, that's an error
            if stored_hash != &expected_hash {
                return Err(SelfCheckError::IncorrectHash(leaf_hash_idx.usize()));
            }
        }

        // Now go through the rest of the levels, checking that the current node equals the hash of
        // the children.
        for level in 1..=root_idx(num_leaves as u64).level() {
            // First index on level i is 2^i - 1. Each subsequent index at level i is at an offset
            // of 2^(i+1).
            let start_idx = 2u64.pow(level) - 1;
            let step_size = 2usize.pow(level + 1);
            for parent_idx in (start_idx..num_nodes).step_by(step_size) {
                // Get the left and right children, erroring if they don't exist
                let parent_idx = InternalIdx::new(parent_idx);
                let left_child_idx = parent_idx.left_child();
                let right_child_idx = parent_idx.right_child(num_leaves);

                let left_child = self
                    .internal_nodes
                    .get(left_child_idx.usize())
                    .ok_or(SelfCheckError::MissingNode(left_child_idx.usize()))?;
                let right_child = self
                    .internal_nodes
                    .get(right_child_idx.usize())
                    .ok_or(SelfCheckError::MissingNode(right_child_idx.usize()))?;

                // Compute the expected hash and get the stored hash
                let expected_hash = parent_hash::<H>(left_child, right_child);
                let stored_hash = self
                    .internal_nodes
                    .get(parent_idx.usize())
                    .ok_or(SelfCheckError::MissingNode(parent_idx.usize()))?;

                // If the hashes don't match, that's an error
                if stored_hash != &expected_hash {
                    return Err(SelfCheckError::IncorrectHash(parent_idx.usize()));
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
        self.internal_nodes[cur_idx.usize()] = leaf_hash::<H, _>(leaf);

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

        // Root of an empty tree is H("")
        let root_hash = if num_leaves == 0 {
            H::digest(b"")
        } else {
            //  Otherwise it's the internal node at the root index
            let root_idx = root_idx(num_leaves as u64);
            self.internal_nodes[root_idx.usize()].clone()
        };

        RootHash {
            root_hash,
            num_leaves,
        }
    }

    /// Tries to get the item at the given index
    pub fn get(&self, idx: u64) -> Option<&T> {
        self.leaves.get(idx as usize)
    }

    /// Returns all the items
    pub fn items(&self) -> &[T] {
        &self.leaves
    }

    /// Returns the number of items
    pub fn len(&self) -> usize {
        self.leaves.len()
    }
}

/// Computes the parent of the two given subtrees. This is `H(0x01 || left || right)`.
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

    use rand::RngCore;
    use sha2::Sha256;

    // Leaves are 32-byte bytestrings
    pub(crate) type T = [u8; 32];
    // The hash function is SHA-256
    pub(crate) type H = Sha256;

    // Creates a random T
    pub(crate) fn rand_val<R: RngCore>(mut rng: R) -> T {
        let mut val = T::default();
        rng.fill_bytes(&mut val);

        val
    }

    // Creates a random CtMerkleTree with `size` items
    pub(crate) fn rand_tree<R: RngCore>(mut rng: R, size: usize) -> CtMerkleTree<H, T> {
        let mut t = CtMerkleTree::<H, T>::default();

        for i in 0..size {
            let val = rand_val(&mut rng);
            t.push(val)
                .expect(&format!("push failed at iteration {}", i));
        }

        t
    }

    // A nice not-round number. This will prodce a tree with multiple levels
    const NUM_ITEMS: usize = 230;

    // Adds a bunch of elements to the tree and then tests the tree's well-formedness
    #[test]
    fn self_check() {
        let mut rng = rand::thread_rng();
        let t = rand_tree(&mut rng, NUM_ITEMS);
        t.self_check().expect("self check failed");
    }
}
