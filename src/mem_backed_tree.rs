use crate::{
    error::SelfCheckError,
    leaf::{leaf_hash, CanonicalSerialize},
    tree_math::*,
};

use alloc::vec::Vec;

use digest::Digest;
use subtle::ConstantTimeEq;

#[cfg(feature = "serde")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

/// The domain separator used for calculating parent hashes
const PARENT_HASH_PREFIX: &[u8] = &[0x01];

/// An append-only data structure with support for succinct inclusion proofs and consistency
/// proofs. This is implemented as a Merkle tree with methods and byte representations compatible
/// Certificate Transparency logs (RFC 6962).
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
#[derive(Clone, Debug)]
pub struct MemoryBackedTree<H, T>
where
    H: Digest,
    T: CanonicalSerialize,
{
    /// The leaves of this tree. This contains all the items
    pub(crate) leaves: Vec<T>,

    /// The internal nodes of the tree. This contains all the hashes of the leaves and parents, etc.
    // The serde bounds are "" here because every digest::Output is Serializable and
    // Deserializable, with no extra assumptions necessary
    #[cfg_attr(feature = "serde", serde(bound(deserialize = "", serialize = "")))]
    pub(crate) internal_nodes: Vec<digest::Output<H>>,
}

impl<H, T> Default for MemoryBackedTree<H, T>
where
    H: Digest,
    T: CanonicalSerialize,
{
    fn default() -> Self {
        MemoryBackedTree {
            leaves: Vec::new(),
            internal_nodes: Vec::new(),
        }
    }
}

/// The root hash of a [`CtMerkleTree`]. This uniquely represents the tree. The [`Self::as_bytes`]
/// representation of this struct is equal to the Merkle Tree Hash (MTH) of the tree that created
/// it, as defined in RFC 6962 §2.1.
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
#[derive(Clone, Debug)]
pub struct RootHash<H: Digest> {
    /// The root hash of the Merkle tree that this root represents
    // The serde bounds are "" here because every digest::Output is Serializable and
    // Deserializable, with no extra assumptions necessary
    #[cfg_attr(feature = "serde", serde(bound(deserialize = "", serialize = "")))]
    pub(crate) root_hash: digest::Output<H>,

    /// The number of leaves in the Merkle tree that this root represents. That is, the number of
    /// items inserted into the [`CtMerkleTree`] that created with `RootHash`.
    pub(crate) num_leaves: u64,
}

impl<H: Digest> PartialEq for RootHash<H> {
    /// Compares this `RootHash` to another in constant time.
    fn eq(&self, other: &RootHash<H>) -> bool {
        self.root_hash.ct_eq(&other.root_hash).into()
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
    pub fn as_bytes(&self) -> &digest::Output<H> {
        &self.root_hash
    }

    /// Returns the number of leaves in the tree that created this `RootHash`.
    pub fn num_leaves(&self) -> u64 {
        self.num_leaves
    }
}

impl<H, T> MemoryBackedTree<H, T>
where
    H: Digest,
    T: CanonicalSerialize,
{
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends the given item to the end of the list.
    ///
    /// # Panics
    /// Panics if `self.len() > usize::MAX / 2`.
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
        let num_leaves = self.len();
        let new_leaf_idx = LeafIdx::new(num_leaves - 1);
        // recalculate_path() requires its leaf idx to be less than usize::MAX. This is guaranteed
        // because it's self.len() - 1.
        self.recaluclate_path(new_leaf_idx)
    }

    /// Checks that this tree is well-formed. This can take a while if the tree is large. Run this
    /// if you've deserialized this tree and don't trust the source. If a tree is malformed, other
    /// methods will panic or behave oddly.
    pub fn self_check(&self) -> Result<(), SelfCheckError> {
        // If the number of leaves is more than an in-memory tree could support, return an error
        let num_leaves = self.len();
        if num_leaves > (usize::MAX / 2) as u64 {
            return Err(SelfCheckError::TooManyLeaves);
        }

        // If the number of internal nodes is less than the necessary size of the tree, return an error
        let num_nodes = num_internal_nodes(num_leaves);
        if (self.internal_nodes.len() as u64) < num_nodes {
            return Err(SelfCheckError::MissingNode(self.internal_nodes.len() as u64));
        }
        // If the number of internal nodes exceeds the necessary size of the tree, return an error
        if (self.internal_nodes.len() as u64) > num_nodes {
            return Err(SelfCheckError::TooManyInternalNodes);
        }

        // Start on level 0. We check the leaf hashes
        for (leaf_idx, leaf) in self.leaves.iter().enumerate() {
            let leaf_hash_idx: InternalIdx = LeafIdx::new(leaf_idx as u64).into();

            // Compute the leaf hash and retrieve the stored leaf hash
            let expected_hash = leaf_hash::<H, _>(leaf);
            // We can unwrap() because we checked above that the number of nodes necessary for this
            // tree fits in memory
            let stored_hash = match self.internal_nodes.get(leaf_hash_idx.as_usize().unwrap()) {
                None => Err(SelfCheckError::MissingNode(leaf_hash_idx.as_u64())),
                Some(h) => Ok(h),
            }?;

            // If the hashes don't match, that's an error
            if stored_hash != &expected_hash {
                return Err(SelfCheckError::IncorrectHash(leaf_hash_idx.as_u64()));
            }
        }

        // Now go through the rest of the levels, checking that the current node equals the hash of
        // the children.
        for level in 1..=root_idx(num_leaves).level() {
            // First index on level i is 2^i - 1. Each subsequent index at level i is at an offset
            // of 2^(i+1).
            let start_idx = 2u64.pow(level) - 1;
            let step_size = 2usize.pow(level + 1);
            for parent_idx in (start_idx..num_nodes).step_by(step_size) {
                // Get the left and right children, erroring if they don't exist
                let parent_idx = InternalIdx::new(parent_idx);
                let left_child_idx = parent_idx.left_child();
                let right_child_idx = parent_idx.right_child(num_leaves);

                // We may unwrap the .as_usize() computations because we alreayd know from the check
                // above that self.internal_nodes.len() == num_nodes, i.e., the total number of
                // nodes in the tree fits in memory, and therefore all the indices are at most
                // `usize::MAX`.

                let left_child = self
                    .internal_nodes
                    .get(left_child_idx.as_usize().unwrap())
                    .ok_or(SelfCheckError::MissingNode(left_child_idx.as_u64()))?;
                let right_child = self
                    .internal_nodes
                    .get(right_child_idx.as_usize().unwrap())
                    .ok_or(SelfCheckError::MissingNode(right_child_idx.as_u64()))?;

                // Compute the expected hash and get the stored hash
                let expected_hash = parent_hash::<H>(left_child, right_child);
                let stored_hash = self
                    .internal_nodes
                    .get(parent_idx.as_usize().unwrap())
                    .ok_or(SelfCheckError::MissingNode(parent_idx.as_u64()))?;

                // If the hashes don't match, that's an error
                if stored_hash != &expected_hash {
                    return Err(SelfCheckError::IncorrectHash(parent_idx.as_u64()));
                }
            }
        }

        Ok(())
    }

    /// Recalculates the hashes on the path from `leaf_idx` to the root. Panics if the path doesn't
    /// exist. In other words, this tree MUST NOT be missing internal nodes or leaves. Also panics
    /// if the given leaf index exceeds `usize::MAX`.
    fn recaluclate_path(&mut self, leaf_idx: LeafIdx) {
        // First update the leaf hash
        let leaf = &self.leaves[leaf_idx.as_usize().unwrap()];
        let mut cur_idx: InternalIdx = leaf_idx.into();
        self.internal_nodes[cur_idx.as_usize().unwrap()] = leaf_hash::<H, _>(leaf);

        // Get some data for the upcoming loop
        let num_leaves = self.len();
        let root_idx = root_idx(num_leaves);

        // Now iteratively update the parent of cur_idx
        while cur_idx != root_idx {
            let parent_idx = cur_idx.parent(num_leaves);

            // We can unwrap() the .as_usize() computations because we assumed the tree is not
            // missing any internal nodes, i.e., it fits in memory, i.e., all the indices are at
            // most usize::MAX

            // Get the values of the current node and its sibling
            let cur_node = &self.internal_nodes[cur_idx.as_usize().unwrap()];
            let sibling = {
                let sibling_idx = &cur_idx.sibling(num_leaves);
                &self.internal_nodes[sibling_idx.as_usize().unwrap()]
            };

            // Compute the parent hash. If cur_node is to the left of the parent, the hash is
            // H(0x01 || cur_node || sibling). Otherwise it's H(0x01 || sibling || cur_node).
            if cur_idx.is_left(num_leaves) {
                self.internal_nodes[parent_idx.as_usize().unwrap()] =
                    parent_hash::<H>(cur_node, sibling);
            } else {
                self.internal_nodes[parent_idx.as_usize().unwrap()] =
                    parent_hash::<H>(sibling, cur_node);
            }

            // Go up a level
            cur_idx = parent_idx;
        }
    }

    /// Returns the root hash of this tree. The value and type uniquely describe this tree.
    pub fn root(&self) -> RootHash<H> {
        let num_leaves = self.len();

        // Root of an empty tree is H("")
        let root_hash = if num_leaves == 0 {
            H::digest(b"")
        } else {
            //  Otherwise it's the internal node at the root index
            let root_idx = root_idx(num_leaves);
            // We can unwrap() because we assume we're not missing any internal nodes. That is,
            // self.internal_nodes.len() <= usize::MAX, which implies that root_idx <= usize::MAX
            self.internal_nodes[root_idx.as_usize().unwrap()].clone()
        };

        RootHash {
            root_hash,
            num_leaves,
        }
    }

    /// Tries to get the item at the given index
    pub fn get(&self, idx: usize) -> Option<&T> {
        self.leaves.get(idx)
    }

    /// Returns all the items
    pub fn items(&self) -> &[T] {
        &self.leaves
    }

    /// Returns the number of items
    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Returns true if this tree has no items
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    use crate::test_util::{Hash, Leaf};

    use rand::{Rng, RngCore};

    // Creates a random T
    pub(crate) fn rand_val<R: RngCore>(mut rng: R) -> Leaf {
        let mut val = Leaf::default();
        rng.fill_bytes(&mut val);

        val
    }

    // Creates a random CtMerkleTree with `size` items
    pub(crate) fn rand_tree<R: RngCore>(mut rng: R, size: usize) -> MemoryBackedTree<Hash, Leaf> {
        let mut t = MemoryBackedTree::<Hash, Leaf>::default();

        for _ in 0..size {
            let val = rand_val(&mut rng);
            t.push(val);
        }

        t
    }

    // Adds a bunch of elements to the tree and then tests the tree's well-formedness
    #[test]
    fn self_check() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let num_items = rng.gen_range(0..230);
            let tree = rand_tree(&mut rng, num_items);
            tree.self_check().expect("self check failed");
        }
    }

    // Checks that a serialization round trip doesn't affect trees or roots
    #[cfg(feature = "serde")]
    #[test]
    fn ser_deser() {
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let num_items = rng.gen_range(0..230);
            let tree = rand_tree(&mut rng, num_items);

            // Serialize and deserialize the tree
            let roundtrip_tree = crate::test_util::serde_roundtrip(tree.clone());

            // Run a self-check and ensure the root hasn't changed
            roundtrip_tree.self_check().unwrap();
            assert_eq!(tree.root(), roundtrip_tree.root());

            // Now check that a serialization round trip doesn't affect roots
            let root = tree.root();
            let roundtrip_root = crate::test_util::serde_roundtrip(root.clone());
            assert_eq!(root, roundtrip_root);
        }
    }
}
