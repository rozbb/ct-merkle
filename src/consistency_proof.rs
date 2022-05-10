//! Types and traits for Merkle consistency proofs

use crate::{
    leaf::CanonicalSerialize,
    merkle_tree::{parent_hash, CtMerkleTree, RootHash},
    tree_math::*,
};

use core::marker::PhantomData;
use std::io::Error as IoError;

use digest::{typenum::Unsigned, Digest};
use thiserror::Error;

/// An error representing what went wrong during consistency verification
#[derive(Debug, Error)]
pub enum ConsistencyVerifError {
    /// The provided root hash does not match the proof's root hash w.r.t the item
    #[error("memberhsip verificaiton failed")]
    Failure,
}

/// A proof that one [`CtMerkleTree`] is a prefix of another. In other words, tree #2 is the result
/// of appending some number of items to the end of tree #1. The byte representation of a
/// [`ConsistencyProof`] is identical to that of `PROOF(m, D[n])` described in RFC 6962 §2.1.2.
#[derive(Clone, Debug)]
pub struct ConsistencyProof<H: Digest> {
    proof: Vec<u8>,
    _marker: PhantomData<H>,
}

/// A reference to a [`ConsistencyProof`]
#[derive(Clone, Debug)]
pub struct ConsistencyProofRef<'a, H: Digest> {
    proof: &'a [u8],
    _marker: PhantomData<H>,
}

impl<H: Digest> ConsistencyProof<H> {
    pub fn as_ref(&self) -> ConsistencyProofRef<H> {
        ConsistencyProofRef {
            proof: self.proof.as_slice(),
            _marker: self._marker,
        }
    }

    /// Returns the RFC 6962-compatible byte representation of this membership proof
    pub fn as_bytes(&self) -> &[u8] {
        self.proof.as_slice()
    }

    /// Constructs a `ConsistencyProof` from the given bytes.
    ///
    /// Panics when `bytes.len()` is not a multiple of `H::OutputSize::USIZE`, i.e., when `bytes`
    /// is not a concatenated sequence of hash digests.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() % H::OutputSize::USIZE != 0 {
            panic!("malformed consistency proof");
        } else {
            ConsistencyProof {
                proof: bytes.to_vec(),
                _marker: PhantomData,
            }
        }
    }
}

impl<H, T> CtMerkleTree<H, T>
where
    H: Digest,
    T: CanonicalSerialize,
{
    /// Produces a proof that this `CtMerkleTree` is the result of appending to a tree containing
    /// the same first `slice_size` items.
    ///
    /// Panics if `slice_size == 0` or `slice_size > self.len()`.
    pub fn consistency_proof(&self, slice_size: usize) -> ConsistencyProof<H> {
        if slice_size == 0 {
            panic!("cannot produce a consistency proof starting from an empty tree");
        }
        if slice_size > self.len() {
            panic!("proposed slice is greater than the tree itself");
        }

        let num_tree_leaves = self.leaves.len() as u64;
        let num_oldtree_leaves = slice_size as u64;
        let tree_root_idx = root_idx(num_tree_leaves as u64);
        let oldtree_root_idx = root_idx(num_oldtree_leaves as u64);
        let starting_idx: InternalIdx = LeafIdx::new(slice_size as u64 - 1).into();

        // We have starting_idx in a current tree and a old tree. starting_idx occurs in a subtree
        // which is both a subtree of the current tree and of the old tree.
        // We want to find the largest such subtree, and start logging the copath after that.

        let mut proof = Vec::new();

        // We have a special case when the old tree is a subtree of the current tree. This happens
        // when the old tree is a complete binary tree OR when the old tree equals this tree (i.e.,
        // nothing changed between the trees).
        let oldtree_is_subtree =
            slice_size.is_power_of_two() || slice_size == num_tree_leaves as usize;

        // If the old tree is a subtree, then the starting idx for the path is the subtree root
        let mut path_idx = if oldtree_is_subtree {
            oldtree_root_idx
        } else {
            // If the old tree isn't a subtree, find the first place that the ancestors of the
            // starting index diverge
            let ancestor_in_tree =
                last_common_ancestor(starting_idx, num_tree_leaves, num_oldtree_leaves);
            // Record the point just before divergences
            proof.extend_from_slice(&self.internal_nodes[ancestor_in_tree.usize()]);

            ancestor_in_tree
        };

        // Now collect the copath, just like in the membership proof
        while path_idx != tree_root_idx {
            let sibling_idx = path_idx.sibling(num_tree_leaves);
            proof.extend_from_slice(&self.internal_nodes[sibling_idx.usize()]);

            // Go up a level
            path_idx = path_idx.parent(num_tree_leaves);
        }

        ConsistencyProof {
            proof,
            _marker: PhantomData,
        }
    }
}

impl<H: Digest> RootHash<H> {
    /// Verifies that the tree described by `old_root` is a prefix of the tree described by `self`.
    ///
    /// Panics if `old_root.num_leaves == 0` or `old_root.num_leaves > self.num_leaves`.
    pub fn verify_consistency(
        &self,
        old_root: &RootHash<H>,
        proof: &ConsistencyProofRef<H>,
    ) -> Result<(), ConsistencyVerifError> {
        let starting_idx: InternalIdx = LeafIdx::new(old_root.num_leaves - 1).into();
        let num_tree_leaves = self.num_leaves;
        let num_oldtree_leaves = old_root.num_leaves;
        let oldtree_root_idx = root_idx(num_oldtree_leaves);

        if num_oldtree_leaves == 0 {
            panic!("consistency proofs cannot exist wrt the empty tree");
        }
        if num_oldtree_leaves > num_tree_leaves {
            panic!("consistency proof is from a bigger tree than this one");
        }

        // We have a special case when the old tree is a subtree of the current tree. This happens
        // when the old tree is a complete binary tree OR when the old tree equals this tree (i.e.,
        // nothing changed between the trees).
        let oldtree_is_subtree = old_root.num_leaves.is_power_of_two() || old_root == self;

        let mut digests = proof
            .proof
            .chunks(H::OutputSize::USIZE)
            .map(digest::Output::<H>::from_slice);

        // We compute both old and new tree hashes. This procedure will succeed iff the oldtree
        // hash matches old_root and the tree hash matches self
        let (mut running_oldtree_idx, mut running_oldtree_hash) = if oldtree_is_subtree {
            (oldtree_root_idx, old_root.root_hash.clone())
        } else {
            let first_hash = digests.next().unwrap().clone();
            let ancestor_in_tree =
                last_common_ancestor(starting_idx, num_tree_leaves, num_oldtree_leaves);
            (ancestor_in_tree, first_hash)
        };
        let mut running_tree_hash = running_oldtree_hash.clone();
        let mut running_tree_idx = running_oldtree_idx;

        for sibling_hash in digests {
            let sibling_idx = running_tree_idx.sibling(num_tree_leaves);

            if running_tree_idx.is_left(num_tree_leaves) {
                running_tree_hash = parent_hash::<H>(&running_tree_hash, sibling_hash);
            } else {
                running_tree_hash = parent_hash::<H>(sibling_hash, &running_tree_hash);
            }
            // Step up the tree
            running_tree_idx = running_tree_idx.parent(num_tree_leaves);

            // Now do the same with the old tree. If the current copath node is the sibling of
            // running_oldtree_idx, then we can update the oldtree hash
            if running_oldtree_idx != oldtree_root_idx
                && sibling_idx == running_oldtree_idx.sibling(num_oldtree_leaves)
            {
                if running_oldtree_idx.is_left(num_oldtree_leaves) {
                    running_oldtree_hash = parent_hash::<H>(&running_oldtree_hash, sibling_hash);
                } else {
                    running_oldtree_hash = parent_hash::<H>(sibling_hash, &running_oldtree_hash);
                }
                // Step up the oldtree
                running_oldtree_idx = running_oldtree_idx.parent(num_oldtree_leaves);
            }
        }

        // At the end, the old hash should be the old root, and the new hash should be the new root
        if (running_oldtree_hash != old_root.root_hash) || (running_tree_hash != self.root_hash) {
            Err(ConsistencyVerifError::Failure)
        } else {
            Ok(())
        }
    }
}

/// Given an index `idx` that appears in two trees (num_leaves1 and num_leaves2), find the first
/// ancestor of `idx` whose parent in tree1 is not the same as the parent in tree2.
fn last_common_ancestor(mut idx: InternalIdx, num_leaves1: u64, num_leaves2: u64) -> InternalIdx {
    while idx.parent(num_leaves1) == idx.parent(num_leaves2) {
        idx = idx.parent(num_leaves1);
    }

    idx
}

#[cfg(test)]
pub(crate) mod test {
    use crate::merkle_tree::test::{rand_tree, rand_val};

    use rand::thread_rng;

    // Tests that an honestly generated membership proof verifies
    #[test]
    fn consistency_proof_correctness() {
        let mut rng = thread_rng();

        for initial_size in 1..50 {
            for num_to_add in 0..50 {
                let mut v = rand_tree(&mut rng, initial_size);
                let initial_root = v.root();

                // Now add to v
                for _ in 0..num_to_add {
                    let val = rand_val(&mut rng);
                    v.push(val).unwrap();
                }
                let new_root = v.root();

                // Now make a consistency proof and check it
                let proof = v.consistency_proof(initial_size);
                new_root
                    .verify_consistency(&initial_root, &proof.as_ref())
                    .expect(&format!(
                        "Consistency check failed for {} -> {} leaves",
                        initial_size,
                        initial_size + num_to_add
                    ));
            }
        }
    }
}
