//! Types and traits for Merkle consistency proofs

use crate::{
    error::ConsistencyVerifError, mem_backed_tree::MemoryBackedTree, tree_util::*, RootHash,
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use digest::{typenum::Unsigned, Digest};
use subtle::ConstantTimeEq;

/// A proof that one Merkle tree is a prefix of another. In other words, tree #2 is the result of
/// appending some number of items to the end of tree #1.
#[derive(Clone, Debug)]
pub struct ConsistencyProof<H: Digest> {
    proof: Vec<u8>,
    _marker: PhantomData<H>,
}

impl<H: Digest> ConsistencyProof<H> {
    /// Returns the byte representation of this consistency proof.
    ///
    /// This is precisely `PROOF(m, D[n])`, described in [RFC 6962
    /// §2.1.2](https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1.2), where `n` is the number
    /// of leaves and `m` is the leaf index being proved.
    pub fn as_bytes(&self) -> &[u8] {
        self.proof.as_slice()
    }

    /// Constructs a `ConsistencyProof` from the given bytes.
    ///
    /// # Errors
    ///
    /// If when `bytes.len()` is not a multiple of `H::OutputSize::USIZE`, i.e., when `bytes` is not
    /// a concatenated sequence of hash digests.
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, ConsistencyVerifError> {
        if bytes.len() % H::OutputSize::USIZE != 0 {
            Err(ConsistencyVerifError::MalformedProof)
        } else {
            Ok(ConsistencyProof {
                proof: bytes,
                _marker: PhantomData,
            })
        }
    }

    /// Constructs a `ConsistencyProof` from a sequence of digests.
    // This is identical to `InclusionProof::from_digests`, since proofs are just sequences of
    // digests.
    pub fn from_digests<'a>(digests: impl IntoIterator<Item = &'a digest::Output<H>>) -> Self {
        // The proof is just a concatenation of hashes
        let concatenated_hashes = digests.into_iter().flatten().cloned().collect();

        ConsistencyProof {
            proof: concatenated_hashes,
            _marker: PhantomData,
        }
    }
}

impl<H, T> MemoryBackedTree<H, T>
where
    H: Digest,
    T: HashableLeaf,
{
    /// Produces a proof that this `MemoryBackedTree` is the result of appending `num_additions` items
    /// to a prefix of this tree.
    ///
    /// # Panics
    /// Panics if `num_additions >= self.len()`.
    pub fn prove_consistency(&self, num_additions: usize) -> ConsistencyProof<H> {
        let num_leaves = self.len();
        let num_additions = num_additions as u64;
        assert!(
            num_leaves > num_additions,
            "num_additions must be smaller than self.len()"
        );

        let idxs = indices_for_consistency_proof(num_leaves - num_additions, num_additions);
        // We can unwrap() below because all the given indices are in the tree, which we are storing
        // in memory
        let proof = idxs
            .iter()
            .flat_map(|&i| &self.internal_nodes[usize::try_from(i).unwrap()])
            .cloned()
            .collect();
        ConsistencyProof {
            proof,
            _marker: PhantomData,
        }
    }
}

/// Given a tree size and number of additions, produces a list of tree node indices whose values in
/// the new tree (i.e., including the additions) are needed to build the consistency proof.
///
/// This is useful when we don't have the entire tree in memory, e.g., when it is stored on disk or
/// stored in tiles on a remote server. Once the digests are retreived, they can be used in the same
/// order in [`ConsistencyProof::from_digests`].
///
/// # Panics
/// Panics if `num_oldtree_leaves == 0` `num_oldtree_leaves + num_additions - 1 > ⌊u64::MAX / 2⌋`.
pub fn indices_for_consistency_proof(num_oldtree_leaves: u64, num_additions: u64) -> Vec<u64> {
    if num_oldtree_leaves == 0 {
        panic!("cannot produce a consistency proof starting from an empty tree");
    }
    if (num_oldtree_leaves - 1)
        .checked_add(num_additions)
        .map_or(false, |s| s > u64::MAX / 2)
    {
        panic!("too many leaves")
    }

    let mut out = Vec::new();

    // The root_idx() and LeafIdx::new() calls below cannot panic, because `num_newtree_leaves`, and
    // hence `num_oldtree_leaves` are guaranteed to be within range from the checks above.
    let num_newtree_leaves = num_oldtree_leaves + num_additions;
    let newtree_root_idx = root_idx(num_newtree_leaves);
    let oldtree_root_idx = root_idx(num_oldtree_leaves);

    // We have starting_idx in a current tree and a old tree. starting_idx occurs in a subtree
    // which is both a subtree of the current tree and of the old tree.
    // We want to find the largest such subtree, and start logging the copath after that.

    // We have a special case when the old tree is a subtree of the current tree. This happens
    // when the old tree is a complete binary tree OR when the old tree equals this tree (i.e.,
    // nothing changed between the trees).
    let oldtree_is_subtree =
        num_oldtree_leaves.is_power_of_two() || num_oldtree_leaves == num_newtree_leaves;

    // If the old tree is a subtree, then the starting idx for the path is the subtree root
    let mut path_idx = if oldtree_is_subtree {
        oldtree_root_idx
    } else {
        // If the old tree isn't a subtree, find the first place that the ancestors of the
        // starting index diverge. This cannot panic because `num_newtree_leaves >
        // num_oldtree_leaves` from the `oldtree_is_subtree` branch above, and `num_oldtree_leaves
        // != 0` due to the check at the very beginning.
        let ancestor_in_tree =
            first_node_with_diverging_parents(num_newtree_leaves, num_oldtree_leaves);
        // Record the point just before divergences
        out.push(ancestor_in_tree.as_u64());

        ancestor_in_tree
    };

    // Now collect the copath, just like in the inclusion proof
    while path_idx != newtree_root_idx {
        // The sibling() and parent() computations cannot panic because 1) the computations above
        // are guaranteed to set path_idx to a valid index in the new tree (and calling .parent() is
        // a valid transform), and 2) if we're in this loop, then path_idx is not the root yet.
        let sibling_idx = path_idx.sibling(num_newtree_leaves);
        out.push(sibling_idx.as_u64());

        // Go up a level
        path_idx = path_idx.parent(num_newtree_leaves);
    }

    out
}

impl<H: Digest> RootHash<H> {
    /// Verifies a proof that the tree described by `old_root` is a prefix of the tree described by
    /// `self`.
    pub fn verify_consistency(
        &self,
        old_root: &RootHash<H>,
        proof: &ConsistencyProof<H>,
    ) -> Result<(), ConsistencyVerifError> {
        let num_newtree_leaves = self.num_leaves;
        let num_oldtree_leaves = old_root.num_leaves;
        if num_oldtree_leaves == 0 {
            return Err(ConsistencyVerifError::OldTreeEmpty);
        }
        if num_oldtree_leaves > num_newtree_leaves {
            return Err(ConsistencyVerifError::OldTreeLarger);
        }
        if num_newtree_leaves - 1 > u64::MAX / 2 {
            return Err(ConsistencyVerifError::NewTreeTooBig);
        }

        // Check that the proof is the right size
        // This cannot panic because we check that num_newtree_leaves >= num_old_tree_leaves
        let num_additions = num_newtree_leaves - num_oldtree_leaves;
        let expected_proof_size = {
            // This cannot panic because we check that num_old_tree_leaves > 0 above, and that
            // `num_oldtree_leaves + num_additions - 1 <= u64::MAX``
            let num_hashes = indices_for_consistency_proof(num_oldtree_leaves, num_additions).len();
            H::OutputSize::USIZE * num_hashes
        };
        if expected_proof_size != proof.proof.len() {
            return Err(ConsistencyVerifError::MalformedProof);
        }

        // We have a special case when the old tree is a subtree of the current tree. This happens
        // when the old tree is a complete binary tree OR when the old tree is the same size as this
        // tree
        let oldtree_is_subtree =
            old_root.num_leaves.is_power_of_two() || old_root.num_leaves == self.num_leaves;

        // Split the proof into digest-sized chunks
        let mut digests = proof
            .proof
            .chunks(H::OutputSize::USIZE)
            .map(digest::Output::<H>::from_slice);

        // We compute both old and new tree hashes. This procedure will succeed iff the oldtree
        // hash matches old_root and the tree hash matches self
        // The root_idx() cannot panic because `num_oldtree_leaves < num_newtree_leaves` is in range
        let oldtree_root_idx = root_idx(num_oldtree_leaves);
        let (mut running_oldtree_idx, mut running_oldtree_hash) = if oldtree_is_subtree {
            (oldtree_root_idx, old_root.root_hash.clone())
        } else {
            // We can unwrap here because the proof size cannot be 0. Proof size is 0 iff the old
            // root has the same number of leaves as the new one, and that handled in the branche
            // above
            let first_hash = digests.next().unwrap().clone();
            // Our starting point will be a node common to both trees, but whose parents differ
            // between the two trees.
            // This cannot panic because `0 < num_oldtree_leaves`, and `num_oldtree_leaves <
            // num_newtree_leaves` via the `oldtree_is_subtree` check above, and
            // `num_newtree_leaves` is in range.
            let starting_idx =
                first_node_with_diverging_parents(num_newtree_leaves, num_oldtree_leaves);
            (starting_idx, first_hash)
        };
        let mut running_tree_hash = running_oldtree_hash.clone();
        let mut running_newtree_idx = running_oldtree_idx;

        for sibling_hash in digests {
            // The sibling(), parent(), and is_left() computations cannot panic because the
            // computations above are guaranteed to set running_newtree_idx to a valid non-root
            // index in the new tree (and calling .parent() is a valid transform) not the root yet.
            let sibling_idx = running_newtree_idx.sibling(num_newtree_leaves);

            if running_newtree_idx.is_left(num_newtree_leaves) {
                running_tree_hash = parent_hash::<H>(&running_tree_hash, sibling_hash);
            } else {
                running_tree_hash = parent_hash::<H>(sibling_hash, &running_tree_hash);
            }
            // Step up the tree
            running_newtree_idx = running_newtree_idx.parent(num_newtree_leaves);

            // Now do the same with the old tree. If the current copath node is the sibling of
            // running_oldtree_idx, then we can update the oldtree hash

            // We can do the sibling(), is_left(), and parent() computations here for the same
            // reason as above. Namely, running_oldtree_idx is guaranteed to be a valid index,
            // .parent() is a valid transform, and the check below ensure it's not the root
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
        let oldtree_eq = running_oldtree_hash.ct_eq(&old_root.root_hash);
        let tree_eq = running_tree_hash.ct_eq(&self.root_hash);
        if !bool::from(oldtree_eq & tree_eq) {
            Err(ConsistencyVerifError::VerificationFailure)
        } else {
            Ok(())
        }
    }
}

/// Given two trees `num_leaves1 > num_leaves2`, finds the lowest node in the rightmost path-to-root
/// of `num_leaves2` whose parent in `num_leaves2` is not the same as the parent in `num_leaves1`.
/// This is guaranteed to exist as long as `num_leaves2` is not a subtree of `num_leaves1`.
///
/// # Panics
/// Panics when `num_leaves1 <= num_leaves2` or `num_leaves2 == 0`. Also panics when `num_leaves2` is
/// a subtree of `num_leaves1`, which occurs when `num_leaves2.is_power_of_two()`. Also panics when
/// `num_leaves1 - 1 > ⌊u64::MAX / 2⌋`.
fn first_node_with_diverging_parents(num_leaves1: u64, num_leaves2: u64) -> InternalIdx {
    assert!(num_leaves1 > num_leaves2);
    assert_ne!(num_leaves2, 0);
    assert!(num_leaves1 - 1 <= u64::MAX / 2);

    let mut idx = InternalIdx::from(LeafIdx::new(num_leaves2 - 1));
    while idx.parent(num_leaves1) == idx.parent(num_leaves2) {
        idx = idx.parent(num_leaves1);
    }

    idx
}

#[cfg(test)]
pub(crate) mod test {
    use crate::{
        mem_backed_tree::test::{rand_tree, rand_val},
        RootHash,
    };
    use sha2::Sha256;

    // Tests that an honestly generated consistency proof verifies, and that a valid proof wrt one
    // or two modified roots does not
    #[test]
    fn consistency_proof() {
        let mut rng = rand::thread_rng();

        for initial_size in 1..25 {
            for num_to_add in 0..25 {
                let mut t = rand_tree(&mut rng, initial_size);
                let initial_root = t.root();

                // Now add to v
                for _ in 0..num_to_add {
                    let val = rand_val(&mut rng);
                    t.push(val);
                }
                let new_root = t.root();

                // Now make a consistency proof and check it
                let proof = t.prove_consistency(num_to_add);
                new_root
                    .verify_consistency(&initial_root, &proof)
                    .unwrap_or_else(|e| {
                        panic!(
                            "Consistency check failed for {} -> {} leaves: {e}",
                            initial_size,
                            initial_size + num_to_add
                        )
                    });

                // Make new roots with a different levels and make sure it fails
                let modified_new_root =
                    RootHash::<Sha256>::new(new_root.root_hash, new_root.num_leaves() * 2);
                assert!(
                    modified_new_root
                        .verify_consistency(&initial_root, &proof)
                        .is_err(),
                    "proof verified wrt modified new root"
                );
                let modified_new_root =
                    RootHash::<Sha256>::new(new_root.root_hash, new_root.num_leaves() / 2);
                assert!(
                    modified_new_root
                        .verify_consistency(&initial_root, &proof)
                        .is_err(),
                    "proof verified wrt modified new root"
                )
            }
        }
    }
}
