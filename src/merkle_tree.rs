use crate::{
    error::SelfCheckError,
    leaf::{leaf_hash, CanonicalSerialize},
    tree_math::*,
};

use alloc::vec::Vec;

use digest::Digest;

#[cfg(feature = "serde")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

/// The domain separator used for calculating parent hashes
const PARENT_HASH_PREFIX: &[u8] = &[0x01];

/// An append-only data structure with support for succinct inclusion proofs and consistency
/// proofs. This is implemented as a Merkle tree with methods and byte representations compatible
/// Certificate Transparency logs (RFC 6962).
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
#[derive(Clone, Debug)]
pub struct CtMerkleTree<H, T>
where
    H: Digest,
    T: CanonicalSerialize,
{
    /// The leaves of this tree. This contains all the items
    pub(crate) leaves: Vec<T>,

    /// The internal nodes of the tree. This contains all the hashes
    // The serde bounds are "" here because every digest::Output is Serializable and
    // Deserializable, with no extra assumptions necessary
    #[cfg_attr(feature = "serde", serde(bound(deserialize = "", serialize = "")))]
    pub(crate) internal_nodes: Vec<digest::Output<H>>,
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
    pub num_leaves: usize,
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

    /// Appends the given item to the end of the list. Panics if `self.len() > usize::MAX / 2`.
    pub fn push(&mut self, new_val: T) {
        // Make sure we can push two elements to internal_nodes (two because every append involves
        // adding a parent node somewhere). usize::MAX is the max capacity of a vector, minus 1. So
        // usize::MAX-1 is the correct bound to use here.
        if self.internal_nodes.len() > usize::MAX - 1 {
            panic!("cannot push; tree is full");
        }

        // We push the new value, a node for its hash, and a node for its parent (assuming the tree
        // isn't a singleton). The hash and parent nodes will get overwritten by recalculate_path()
        self.leaves.push(new_val);
        self.internal_nodes.push(digest::Output::<H>::default());

        // If the tree is not a singleton, add a new parent node
        if self.internal_nodes.len() > 1 {
            self.internal_nodes.push(digest::Output::<H>::default());
        }

        // Recalculate the tree starting at the new leaf
        let num_leaves = self.leaves.len();
        let new_leaf_idx = LeafIdx::new(num_leaves - 1);
        self.recaluclate_path(new_leaf_idx)
    }

    /// Checks that this tree is well-formed. This can take a while if the tree is large. Run this
    /// if you've deserialized this tree and don't trust the source. If a tree is malformed, other
    /// methods will panic or behave oddly.
    pub fn self_check(&self) -> Result<(), SelfCheckError> {
        // Go through every level of the tree, checking hashes
        let num_leaves = self.leaves.len();
        let num_nodes = num_internal_nodes(num_leaves);

        // Start on level 0. We check the leaf hashes
        for (leaf_idx, leaf) in self.leaves.iter().enumerate() {
            let leaf_hash_idx: InternalIdx = LeafIdx::new(leaf_idx).into();

            // Compute the leaf hash and retrieve the stored leaf hash
            let expected_hash = leaf_hash::<H, _>(leaf);
            let stored_hash = match self.internal_nodes.get(leaf_hash_idx.as_usize()) {
                None => Err(SelfCheckError::MissingNode(leaf_hash_idx.as_usize())),
                Some(h) => Ok(h),
            }?;

            // If the hashes don't match, that's an error
            if stored_hash != &expected_hash {
                return Err(SelfCheckError::IncorrectHash(leaf_hash_idx.as_usize()));
            }
        }

        // Now go through the rest of the levels, checking that the current node equals the hash of
        // the children.
        for level in 1..=root_idx(num_leaves).level() {
            // First index on level i is 2^i - 1. Each subsequent index at level i is at an offset
            // of 2^(i+1).
            let start_idx = 2usize.pow(level) - 1;
            let step_size = 2usize.pow(level + 1);
            for parent_idx in (start_idx..num_nodes).step_by(step_size) {
                // Get the left and right children, erroring if they don't exist
                let parent_idx = InternalIdx::new(parent_idx);
                let left_child_idx = parent_idx.left_child();
                let right_child_idx = parent_idx.right_child(num_leaves);

                let left_child = self
                    .internal_nodes
                    .get(left_child_idx.as_usize())
                    .ok_or(SelfCheckError::MissingNode(left_child_idx.as_usize()))?;
                let right_child = self
                    .internal_nodes
                    .get(right_child_idx.as_usize())
                    .ok_or(SelfCheckError::MissingNode(right_child_idx.as_usize()))?;

                // Compute the expected hash and get the stored hash
                let expected_hash = parent_hash::<H>(left_child, right_child);
                let stored_hash = self
                    .internal_nodes
                    .get(parent_idx.as_usize())
                    .ok_or(SelfCheckError::MissingNode(parent_idx.as_usize()))?;

                // If the hashes don't match, that's an error
                if stored_hash != &expected_hash {
                    return Err(SelfCheckError::IncorrectHash(parent_idx.as_usize()));
                }
            }
        }

        Ok(())
    }

    /// Recalculates the hashes on the path from `leaf_idx` to the root. The path MUST already
    /// exist, i.e., this tree cannot be missing internal nodes.
    fn recaluclate_path(&mut self, leaf_idx: LeafIdx) {
        // First update the leaf hash
        let leaf = &self.leaves[leaf_idx.as_usize()];
        let mut cur_idx: InternalIdx = leaf_idx.into();
        self.internal_nodes[cur_idx.as_usize()] = leaf_hash::<H, _>(leaf);

        // Get some data for the upcoming loop
        let num_leaves = self.leaves.len();
        let root_idx = root_idx(num_leaves);

        // Now iteratively update the parent of cur_idx
        while cur_idx != root_idx {
            let parent_idx = cur_idx.parent(num_leaves);

            // Get the values of the current node and its sibling
            let cur_node = &self.internal_nodes[cur_idx.as_usize()];
            let sibling = {
                let sibling_idx = &cur_idx.sibling(num_leaves);
                &self.internal_nodes[sibling_idx.as_usize()]
            };

            // Compute the parent hash. If cur_node is to the left of the parent, the hash is
            // H(0x01 || cur_node || sibling). Otherwise it's H(0x01 || sibling || cur_node).
            if cur_idx.is_left(num_leaves) {
                self.internal_nodes[parent_idx.as_usize()] = parent_hash::<H>(cur_node, sibling);
            } else {
                self.internal_nodes[parent_idx.as_usize()] = parent_hash::<H>(sibling, cur_node);
            }

            // Go up a level
            cur_idx = parent_idx;
        }
    }

    /// Returns the root hash of this tree. The value and type uniquely describe this tree.
    pub fn root(&self) -> RootHash<H> {
        let num_leaves = self.leaves.len();

        // Root of an empty tree is H("")
        let root_hash = if num_leaves == 0 {
            H::digest(b"")
        } else {
            //  Otherwise it's the internal node at the root index
            let root_idx = root_idx(num_leaves);
            self.internal_nodes[root_idx.as_usize()].clone()
        };

        RootHash {
            root_hash,
            num_leaves,
        }
    }

    /// Tries to get the item at the given index
    pub fn get(&self, idx: usize) -> Option<&T> {
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

        for _ in 0..size {
            let val = rand_val(&mut rng);
            t.push(val);
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

    // Checks that a serialization round trip doesn't affect the tree
    #[cfg(feature = "serde")]
    #[test]
    fn ser_deser() {
        let mut rng = rand::thread_rng();
        let t1 = rand_tree(&mut rng, NUM_ITEMS);

        // Serialize and deserialize the tree
        let s = serde_json::to_string(&t1).unwrap();
        let t2: CtMerkleTree<H, T> = serde_json::from_str(&s).unwrap();

        // Run a self-check and ensure the root hasn't changed
        t2.self_check().unwrap();
        assert_eq!(t1.root(), t2.root());
    }
}
