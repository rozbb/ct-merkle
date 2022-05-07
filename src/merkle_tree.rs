use crate::leaf::{leaf_hash, CanonicalSerialize};

use core::marker::PhantomData;
use std::io::Error as IoError;

use digest::{typenum::Unsigned, Digest};
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
    leaves: Vec<T>,
    /// The internal nodes of the tree. This contains all the hashes
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

/// A proof of membership in some tree. The byte representation of this is identical to that of
/// `PATH(m, D[n])` described in RFC 6962.
pub struct MembershipProof<H: Digest> {
    proof: Vec<u8>,
    _marker: PhantomData<H>,
}

/// A reference to a [`MembershipProof`]
pub struct MembershipProofRef<'a, H: Digest> {
    proof: &'a [u8],
    _marker: PhantomData<H>,
}

impl<H: Digest> AsRef<[u8]> for MembershipProof<H> {
    fn as_ref(&self) -> &[u8] {
        self.proof.as_slice()
    }
}

impl<H: Digest> MembershipProof<H> {
    pub fn as_ref(&self) -> MembershipProofRef<H> {
        MembershipProofRef {
            proof: self.proof.as_slice(),
            _marker: self._marker,
        }
    }

    /// Returns the RFC 6962-compatible byte representation of this membership proof
    pub fn as_bytes(&self) -> &[u8] {
        self.proof.as_slice()
    }

    /// Constructs a `MembershipProof` from the given bytes. Panics when `bytes.len()` is not a
    /// multiple of `H::OutputSize::USIZE`, i.e., when `bytes` is not a concatenated sequence of
    /// hash digests.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() % H::OutputSize::USIZE != 0 {
            panic!("malformed membership proof");
        } else {
            MembershipProof {
                proof: bytes.to_vec(),
                _marker: PhantomData,
            }
        }
    }
}

/// The root hash of a CT Merkle Tree
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RootHash<H: Digest> {
    root_hash: digest::Output<H>,
    num_leaves: u64,
}

/// An error representing what went wrong during membership verification
#[derive(Debug, Error)]
pub enum VerificationError {
    /// An error occurred when serializing the item whose memberhsip is being checked
    #[error("could not canonically serialize a item")]
    Io(#[from] IoError),

    /// The proof is malformed
    #[error("proof size is not a multiple of the hash digest size")]
    MalformedProof,

    /// The provided root hash does not match the proof's root hash w.r.t the item
    #[error("memberhsip verificaiton failed")]
    Failure,
}

impl<H: Digest> RootHash<H> {
    /// Verifies that `val` occurs at index `idx` in the tree described by this `RootHash`.
    pub fn verify_membership<T: CanonicalSerialize>(
        &self,
        val: &T,
        idx: u64,
        proof: &MembershipProofRef<H>,
    ) -> Result<(), VerificationError> {
        // Check that the proof isn't too big, and is made up of a sequence of hash digests
        let MembershipProofRef { proof, .. } = proof;
        let max_proof_size = {
            let tree_height = root_idx(self.num_leaves).level();
            (tree_height * H::OutputSize::U32) as usize
        };
        if proof.len() > max_proof_size || proof.len() % H::OutputSize::USIZE != 0 {
            return Err(VerificationError::MalformedProof);
        }

        // If the proof is empty, then the leaf hash is the root hash
        let leaf_hash = leaf_hash::<H, T>(val)?;
        if proof.len() == 0 && leaf_hash == self.root_hash {
            return Ok(());
        }

        // Otherwise, start hashing up the tree
        let mut cur_idx: InternalIdx = LeafIdx(idx).into();
        let mut cur_hash = leaf_hash;
        for hash_slice in proof.chunks(H::OutputSize::USIZE) {
            // Hash the current node with its provided sibling
            let sibling_hash = digest::Output::<H>::from_slice(hash_slice);
            if cur_idx.is_left(self.num_leaves) {
                cur_hash = parent_hash::<H>(&cur_hash, sibling_hash);
            } else {
                cur_hash = parent_hash::<H>(sibling_hash, &cur_hash);
            }

            // Step up the tree
            cur_idx = cur_idx.parent(self.num_leaves);
        }

        // Now compare the final hash with the root hash
        if cur_hash == self.root_hash {
            Ok(())
        } else {
            Err(VerificationError::Failure)
        }
    }
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
        let new_leaf_idx = LeafIdx(num_leaves - 1);
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
        let leaf = &self.leaves[leaf_idx.0 as usize];
        let mut cur_idx: InternalIdx = leaf_idx.into();
        self.internal_nodes[cur_idx.0 as usize] = leaf_hash::<H, T>(leaf)?;

        // Get some data for the upcoming loop
        let num_leaves = self.leaves.len() as u64;
        let root_idx = root_idx(num_leaves as u64);

        // Now iteratively update the parent of cur_idx
        while cur_idx != root_idx {
            let parent_idx = cur_idx.parent(num_leaves);

            // Get the values of the current node and its sibling
            let cur_node = &self.internal_nodes[cur_idx.0 as usize];
            let sibling = {
                let sibling_idx = &cur_idx.sibling(num_leaves);
                &self.internal_nodes[sibling_idx.0 as usize]
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

    /// Returns the root hash of this tree. The value and type uniquely describe this tree.
    pub fn root(&self) -> RootHash<H> {
        let num_leaves = self.leaves.len() as u64;
        let root_idx = root_idx(num_leaves as u64);
        let hash = &self.internal_nodes[root_idx.0 as usize];

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

    /// Returns a proof of membership of the item at the given index. Panics if `idx` exceeds
    /// `Self::len()`.
    pub fn membership_proof(&self, idx: u64) -> MembershipProof<H> {
        let num_leaves = self.leaves.len() as u64;
        let root_idx = root_idx(num_leaves as u64);

        // If this is the singleton tree, the proof is empty
        if self.leaves.len() == 1 {
            return MembershipProof {
                proof: Vec::new(),
                _marker: PhantomData,
            };
        }

        // Start the proof with the sibling hash
        let start_idx = InternalIdx::from(LeafIdx(idx));
        let leaf_sibling_hash = {
            let sibling_idx = start_idx.sibling(num_leaves);
            &self.internal_nodes[sibling_idx.0 as usize]
        };
        let mut sibling_hashes = leaf_sibling_hash.to_vec();

        // Collect the hashes of the siblings on the way up the tree
        let mut parent_idx = start_idx.parent(num_leaves);
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

///
/// Below is tree math definitions. We use array-based trees, described in
/// <https://www.ietf.org/archive/id/draft-ietf-mls-protocol-14.html#array-based-trees>
///

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
    // We set log2(0) == 0
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
    let w = num_internal_nodes(num_leaves);
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
        let p = self.parent(num_leaves);
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

    // Creates a random CtMerkleTree
    fn rand_tree<R: RngCore>(mut rng: R) -> CtMerkleTree<H, T> {
        let mut v = CtMerkleTree::<H, T>::default();

        // Add a bunch of items. This tree will not be a full tree.
        for i in 0..230 {
            let mut val = T::default();
            rng.fill_bytes(&mut val);
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
