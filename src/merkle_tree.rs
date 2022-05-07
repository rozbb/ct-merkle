use crate::leaf::{leaf_hash, CanonicalSerialize};

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
    /// The nodes of this tree. We use array-based trees, described in
    /// https://www.ietf.org/archive/id/draft-ietf-mls-protocol-14.html#array-based-trees
    leaves: Vec<T>,
    internal_nodes: Vec<digest::Output<H>>,

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

pub struct MembershipProof<H: Digest> {
    proof: Vec<u8>,
    _marker: PhantomData<H>,
}

pub struct MembershipProofRef<'a, H: Digest> {
    proof: &'a [u8],
    _marker: PhantomData<H>,
}

impl<H: Digest> MembershipProof<H> {
    fn as_ref(&self) -> MembershipProofRef<H> {
        MembershipProofRef {
            proof: self.proof.as_slice(),
            _marker: self._marker,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConsistencyError {
    #[error("could not canonically serialize a item")]
    Io(#[from] IoError),
    #[error("tree is missing an internal node")]
    MissingNode,
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

    /// Attemtps to push the given leaf to the end of
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
        let new_leaf_idx = LeafIdx(num_leaves - 1);
        eprintln!("New leaf is at {:?}", new_leaf_idx);
        eprintln!("Num internal nodes is {}", self.internal_nodes.len());
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
            let leaf_hash_idx: InternalIdx = LeafIdx(leaf_idx as u64).into();

            // Compute the leaf hash and retrieve the stored leaf hash
            let expected_hash = leaf_hash::<H, T>(leaf)?;
            let stored_hash = match self.internal_nodes.get(leaf_hash_idx.0 as usize) {
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
                let idx = InternalIdx(idx);
                let left_child = self
                    .internal_nodes
                    .get(idx.left_child().0 as usize)
                    .ok_or(ConsistencyError::MissingNode)?;
                let right_child = self
                    .internal_nodes
                    .get(idx.right_child(num_leaves).0 as usize)
                    .ok_or(ConsistencyError::MissingNode)?;

                // Compute the expected hash and get the stored hash
                let expected_hash = parent_hash::<H>(left_child, right_child);
                let stored_hash = self
                    .internal_nodes
                    .get(idx.0 as usize)
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
        let leaf = &self.leaves[dbg!(leaf_idx).0 as usize];
        let mut cur_idx: InternalIdx = leaf_idx.into();
        self.internal_nodes[cur_idx.0 as usize] = leaf_hash::<H, T>(leaf)?;

        // Get some data for the upcoming loop
        let num_leaves = self.leaves.len() as u64;
        let root_idx = root_idx(num_leaves as u64);

        // Now iteratively update the parent of cur_idx
        while cur_idx != dbg!(root_idx) {
            let parent_idx = cur_idx.parent(num_leaves);

            // Get the values of the current node and its sibling
            let cur_node = &self.internal_nodes[cur_idx.0 as usize];
            let sibling = {
                let sibling_idx = dbg!(&cur_idx).sibling(num_leaves);
                &self.internal_nodes[dbg!(sibling_idx.0) as usize]
            };

            // Compute the parent hash. If cur_node is to the left of the parent, the hash is
            // H(0x01 || cur_node || sibling). Otherwise it's H(0x01 || sibling || cur_node).
            if cur_idx.is_left(num_leaves) {
                self.internal_nodes[parent_idx.0 as usize] = parent_hash::<H>(cur_node, sibling);
            } else {
                self.internal_nodes[parent_idx.0 as usize] = parent_hash::<H>(sibling, cur_node);
            }

            // Go up a level
            cur_idx = parent_idx;
        }

        // One the above loop is done, we've successfully updated the root node
        Ok(())
    }

    fn root(&self) -> InternalIdx {
        let num_leaves = self.leaves.len() as u64;
        root_idx(num_leaves as u64)
    }

    pub fn membership_proof(&self, leaf_idx: u64) -> MembershipProof<H> {
        let num_leaves = self.leaves.len() as u64;
        let root_idx = root_idx(num_leaves as u64);

        // Collect the hashes of the siblings on the way up the tree
        let mut parent_idx = InternalIdx::from(LeafIdx(leaf_idx)).parent(num_leaves);
        let mut sibling_hashes = Vec::new();
        while parent_idx != root_idx {
            let sibling_idx = parent_idx.sibling(num_leaves);
            sibling_hashes.extend_from_slice(&self.internal_nodes[sibling_idx.0 as usize]);

            // Go up a level
            parent_idx = parent_idx.parent(num_leaves);
        }

        MembershipProof {
            proof: sibling_hashes,
            _marker: PhantomData,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct LeafIdx(u64);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct InternalIdx(u64);

impl From<LeafIdx> for usize {
    fn from(idx: LeafIdx) -> usize {
        idx.0 as usize
    }
}

impl From<LeafIdx> for InternalIdx {
    fn from(leaf: LeafIdx) -> InternalIdx {
        InternalIdx(2 * leaf.0)
    }
}

fn log2(x: u64) -> u64 {
    // Pick log2 of 0 == 0
    if x == 0 {
        0
    } else {
        let mut k = 0;
        while (x >> k) > 0 {
            k += 1;
        }
        k - 1
    }
}

/// The number of internal nodes necessary to represent a tree with `num_leaves` leaves.
fn num_internal_nodes(num_leaves: u64) -> u64 {
    if num_leaves < 2 {
        0
    } else {
        2 * (num_leaves - 1) + 1
    }
}

fn root_idx(num_leaves: u64) -> InternalIdx {
    let w = dbg!(num_internal_nodes(dbg!(num_leaves)));
    InternalIdx((1 << log2(w)) - 1)
}

impl InternalIdx {
    // The level of an internal node is how "odd" it is, i.e., how many trailing ones it has in its
    // binary representation
    fn level(&self) -> u32 {
        self.0.trailing_ones()
    }

    // Returns whether this node is to the left of its parent
    fn is_left(&self, num_leaves: u64) -> bool {
        let p = self.parent(num_leaves);
        self.0 < p.0
    }

    // The rest of the functions are a direct translation of the array-tree math in
    /// https://www.ietf.org/archive/id/draft-ietf-mls-protocol-14.html#array-based-trees

    fn parent(&self, num_leaves: u64) -> InternalIdx {
        fn parent_step(idx: InternalIdx) -> InternalIdx {
            let k = idx.level();
            let b = (idx.0 >> (k + 1)) & 0x01;
            InternalIdx((idx.0 | (1 << k)) ^ (b << (k + 1)))
        }

        if *self == root_idx(num_leaves) {
            panic!("root has no parent");
        }

        let mut p = parent_step(*self);
        while p.0 >= num_internal_nodes(num_leaves) {
            p = parent_step(p);
        }

        p
    }

    fn left_child(&self) -> InternalIdx {
        let k = self.level();
        assert_ne!(k, 0, "cannot compute the child of a level-0 node");

        InternalIdx(self.0 ^ (0x01 << (k - 1)))
    }

    fn right_child(&self, num_leaves: u64) -> InternalIdx {
        let k = self.level();
        assert_ne!(k, 0, "cannot compute the child of a level-0 node");

        let mut r = InternalIdx(self.0 ^ (0x03 << (k - 1)));
        while r.0 >= num_internal_nodes(num_leaves) {
            r = r.left_child();
        }

        r
    }

    fn sibling(&self, num_leaves: u64) -> InternalIdx {
        let p = dbg!(self.parent(num_leaves));
        if self.0 < p.0 {
            p.right_child(num_leaves)
        } else {
            p.left_child()
        }
    }
}

impl From<InternalIdx> for usize {
    fn from(idx: InternalIdx) -> usize {
        idx.0 as usize
    }
}

const PARENT_HASH_PREFIX: &[u8] = &[0x01];

/// Computes the parent of the two given subtrees
fn parent_hash<H: Digest>(
    left: &digest::Output<H>,
    right: &digest::Output<H>,
) -> digest::Output<H> {
    let mut hasher = H::new_with_prefix(PARENT_HASH_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::{thread_rng, RngCore};
    use sha2::Sha256;

    // Leaves are 32-byte bytestrings
    type T = [u8; 32];
    // The hash is SHA-256
    type H = Sha256;

    // Adds a bunch of elements to the tree and then tests the tree's consistency
    #[test]
    fn consistency() {
        let mut rng = thread_rng();
        let mut v = CtMerkleTree::<H, T>::default();

        // Add a bunch of items
        for i in 0..100 {
            let mut val = T::default();
            rng.fill_bytes(&mut val);
            v.push(val)
                .expect(&format!("push failed at iteration {}", i));
        }

        v.self_check().expect("self check failed");
    }
}
