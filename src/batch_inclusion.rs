//! Types and traits for batch inclusion proofs

use crate::{
    error::InclusionVerifError,
    leaf::{leaf_hash, CanonicalSerialize},
    merkle_tree::{parent_hash, CtMerkleTree, RootHash},
    tree_math::*,
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use digest::{typenum::Unsigned, Digest};
use subtle::ConstantTimeEq;

#[cfg(feature = "serde")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

/// A proof that a value appears in a [`CtMerkleTree`]. The byte representation of a
/// [`BatchInclusionProof`] is identical to that of `PATH(m, D[n])` described in RFC 6962 §2.1.1.
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
#[derive(Clone, Debug)]
pub struct BatchInclusionProof<H: Digest> {
    proof: Vec<u8>,
    _marker: PhantomData<H>,
}

impl<H: Digest> BatchInclusionProof<H> {
    /// Returns the RFC 6962-compatible byte representation of this inclusion proof
    pub fn as_bytes(&self) -> &[u8] {
        self.proof.as_slice()
    }

    /// Constructs a `BatchInclusionProof` from the given bytes.
    ///
    /// Panics when `bytes.len()` is not a multiple of `H::OutputSize::USIZE`, i.e., when `bytes`
    /// is not a concatenated sequence of hash digests.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        if bytes.len() % H::OutputSize::USIZE != 0 {
            panic!("malformed batch inclusion proof");
        } else {
            BatchInclusionProof {
                proof: bytes,
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
    /// Returns a batched proof of inclusion of the items at the given indices. Ordering of `idxs`
    /// does not matter.
    ///
    /// Panics if `idxs.is_empty()` or if `idxs[i] >= self.len()` for any `i`.
    pub fn prove_batch_inclusion(&self, idxs: &[usize]) -> BatchInclusionProof<H> {
        assert!(!idxs.is_empty(), "idxs is empty");

        // Convert the leaf idxs to internal node idxs and sort
        let mut idxs: Vec<InternalIdx> = idxs
            .iter()
            .map(|&idx| InternalIdx::from(LeafIdx::new(idx)))
            .collect();
        idxs.sort();

        // Check that no indices are out of range. Since they're sorted, it suffices to check that
        // the last one is within range. The first unwrap() is OK because we checked idxs isn't
        // empty. The second unwrap() is OK because we know that everything in idxs is a leaf.
        let num_leaves = self.leaves.len();
        let largest_idx = idxs.last().unwrap().as_leaf().unwrap().as_usize();
        assert!(
            largest_idx < num_leaves,
            "idx {largest_idx} is out of range",
        );

        // If this is the singleton tree, the proof is empty
        if self.leaves.len() == 1 {
            return BatchInclusionProof {
                proof: Vec::new(),
                _marker: PhantomData,
            };
        }

        // This is the running list of subtrees. We will grow and merge these subtrees until they
        // converge to the root
        let mut cur_subtrees = idxs;
        // Buffer for the proof
        let mut proof = Vec::new();

        // We grow the subtrees until they converge to the root
        let root_idx = root_idx(num_leaves);
        while cur_subtrees[0] != root_idx {
            // We attempt to make progress in the list of subtrees. Progress means merging
            // siblings in the list, or appending to the proof.
            for i in 0..cur_subtrees.len() {
                let idx = cur_subtrees[i];
                let sibling_idx = idx.sibling(num_leaves);

                // Get the next subtree in the list, if it exists
                let next_subtree = cur_subtrees.get(i + 1);

                // If the next subtree is a descendent of this tree's sibling, then we need to
                // build up that subtree first. Go to the next subtree.
                if next_subtree
                    .map(|&idx2| sibling_idx.is_ancestor(idx2))
                    .unwrap_or(false)
                {
                    continue;
                }

                // The next subtree isn't a descendent of this subtree's sibling. We can make
                // progress.

                // If the next node is this node's sibling, merge them into their parent
                if next_subtree
                    .map(|&idx2| idx2 == sibling_idx)
                    .unwrap_or(false)
                {
                    cur_subtrees.remove(i + 1);
                    cur_subtrees[i] = idx.parent(num_leaves);
                } else {
                    // If the next node is not the sibling, then we need to add the sibling to the
                    // proof. Also update this index to the parent.
                    proof.extend_from_slice(&self.internal_nodes[sibling_idx.as_usize()]);
                    cur_subtrees[i] = idx.parent(num_leaves);
                }

                // We made progress. Start from the beginning of the subtree list again.
                break;
            }
        }

        BatchInclusionProof {
            proof,
            _marker: PhantomData,
        }
    }
}

impl<H: Digest> RootHash<H> {
    /// For all `i`, verifies that `val[i]` occurs at index `idx[i]` in the tree described by this
    /// `RootHash`. Ordering of `vals` and `idxs` does not matter, so long as `idxs[i]` corresponds
    /// to `vals[i]` for all `i`.
    ///
    /// Panics if `vals.len() != idxs.len()` or if `idxs[i] >= self.len()` for any `i`.
    pub fn verify_batch_inclusion<T: CanonicalSerialize>(
        &self,
        vals: &[T],
        idxs: &[usize],
        proof: &BatchInclusionProof<H>,
    ) -> Result<(), InclusionVerifError> {
        // Check that there as many vals as idxs
        assert_eq!(
            vals.len(),
            idxs.len(),
            "length mismatch: given {} values but {} indices",
            vals.len(),
            idxs.len()
        );

        // Check that the proof is made up of a sequence of hash digests
        let BatchInclusionProof { proof, .. } = proof;
        if proof.len() % H::OutputSize::USIZE != 0 {
            return Err(InclusionVerifError::MalformedProof);
        }

        // Sort the pairs of indices with their value's hash
        let mut leaf_kv: Vec<(InternalIdx, digest::Output<H>)> = idxs
            .iter()
            .map(|&idx| InternalIdx::from(LeafIdx::new(idx)))
            .zip(vals.iter().map(leaf_hash::<H, _>))
            .collect();
        leaf_kv.sort_by_key(|(idx, _)| *idx);

        // Check that no indices are out of range. Since they're sorted, it suffices to check that
        // the last one is within range. The first unwrap() is OK because we checked idxs isn't
        // empty. The second unwrap() is OK because we know that everything in idxs is a leaf.
        let largest_idx = leaf_kv.last().unwrap().0.as_leaf().unwrap().as_usize();
        assert!(
            largest_idx < self.num_leaves,
            "idx {largest_idx} is out of range",
        );

        // This is the running list of subtrees. We will grow and merge these subtrees until they
        // converge to the root
        let mut cur_subtrees = leaf_kv;
        // Make the proof into an interator we can take digest-sized chunks from
        let mut sibling_hashes = proof.chunks(H::OutputSize::USIZE);

        // We grow the subtrees until they converge to the root
        let root_idx = root_idx(self.num_leaves);
        while cur_subtrees[0].0 != root_idx {
            // We attempt to make progress in the list of subtrees. Progress means merging
            // siblings in the list, or using bytes from the proof.
            for i in 0..cur_subtrees.len() {
                let (cur_idx, cur_hash) = cur_subtrees[i].clone();
                let sibling_idx = cur_idx.sibling(self.num_leaves);
                let parent_idx = cur_idx.parent(self.num_leaves);

                // Get the next subtree in the list (or None)
                let next_subtree = cur_subtrees.get(i + 1);

                // If the next subtree is a descendent of this tree's sibling, then we need to
                // build up that subtree first. Go to the next subtree.
                if next_subtree
                    .map(|(idx2, _)| sibling_idx.is_ancestor(*idx2))
                    .unwrap_or(false)
                {
                    continue;
                }

                // The next subtree isn't a descendent of this subtree's sibling. We can make
                // progress.

                // If the next node is this node's sibling, then use its hash directly. If not,
                // then the sibling hash must be the next hash in the proof, so use that.
                let sibling_hash = if cur_subtrees
                    .get(i + 1)
                    .map(|(idx2, _)| *idx2 == sibling_idx)
                    .unwrap_or(false)
                {
                    // Get the hash of the next subtree, ie the sibling subtree. We also delete the
                    // sibling, since we're merging into the parent
                    cur_subtrees.remove(i + 1).1
                } else {
                    // If the sibling hash isn't already known, then it must be in the proof. If
                    // it's not, then the proof is malformed
                    let sibling_hash_slice = if let Some(h) = sibling_hashes.next() {
                        h
                    } else {
                        return Err(InclusionVerifError::MalformedProof);
                    };
                    digest::Output::<H>::clone_from_slice(sibling_hash_slice)
                };

                // Compute the parent hash and save it in the current index
                let parent_hash = if cur_idx.is_left(self.num_leaves) {
                    parent_hash::<H>(&cur_hash, &sibling_hash)
                } else {
                    parent_hash::<H>(&sibling_hash, &cur_hash)
                };
                cur_subtrees[i] = (parent_idx, parent_hash);

                // We made progress. Start again from the beginning
                break;
            }
        }

        // Finally compare the final hash with the root hash
        if cur_subtrees[0].1.ct_eq(&self.root_hash).into() {
            Ok(())
        } else {
            Err(InclusionVerifError::VerificationFailure)
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::{
        merkle_tree::test::rand_tree,
        test_util::{Hash, Leaf},
    };

    use alloc::vec::Vec;
    use digest::Digest;
    use rand::{seq::SliceRandom, Rng};

    // Tests that an honestly generated inclusion proof verifies
    #[test]
    fn batch_inclusion_proof_correctness() {
        let mut rng1 = rand::thread_rng();
        let mut rng2 = rand::thread_rng();
        let num_leaves = 1000;

        let t = rand_tree(&mut rng1, num_leaves);

        //
        // Generate a bunch of index sets to test on
        //

        // Pick 100 random subsets of {0, ..., num_leaves}
        let random_subsets = (0..100).map(|_| {
            let batch_size = rng1.gen_range(1..num_leaves);
            let mut all_idxs: Vec<_> = (0..num_leaves).collect();
            let (shuffled_set, _) = all_idxs.partial_shuffle(&mut rng1, batch_size);
            shuffled_set.to_vec()
        });
        // Pick 100 random contiguous ranges within {0, ..., num_leaves}
        let random_ranges = (0..100).map(|_| {
            let batch_size = rng2.gen_range(1..num_leaves);
            let start_idx = rng2.gen_range(0..num_leaves);
            let max_end_idx = core::cmp::min(start_idx + batch_size, num_leaves);
            let end_idx = rng2.gen_range(start_idx + 1..=max_end_idx);
            (start_idx..end_idx).collect::<Vec<_>>()
        });

        // Run all the tests vectors
        for idxs in random_subsets.chain(random_ranges) {
            let vals: Vec<_> = idxs
                .iter()
                .map(|&idx| t.get(idx).unwrap())
                .cloned()
                .collect();

            // Do the batch proof and record the proof size
            let proof = t.prove_batch_inclusion(&idxs);

            // Now check the proof
            let root = t.root();
            root.verify_batch_inclusion(&vals, &idxs, &proof).unwrap();

            // Do a round trip and check that the byte representations match at the end
            let roundtrip_proof = crate::test_util::serde_roundtrip(proof.clone());
            assert_eq!(proof.as_bytes(), roundtrip_proof.as_bytes());

            // Make sure the proof doesn't have any unnecessary repetition
            let mut proof_hashes: Vec<&[u8]> = proof.proof.chunks(Hash::output_size()).collect();
            // Note the proof size, deduplicate the hashes, and check that the proof size didn't
            // decrease
            let orig_num_hashes = proof_hashes.len();
            proof_hashes.dedup();
            assert_eq!(orig_num_hashes, proof_hashes.len());
        }

        // If println! is defined, log the size difference between a batched and unbatched proof
        // for indices 0..100
        #[cfg(feature = "std")]
        {
            let batch_size = 100;

            // The naive proving method is to do `batch_size` many inclusion proofs
            let naive_proof_size = t.prove_inclusion(0).as_bytes().len() * batch_size;
            let batch_proof_size = {
                let idxs: Vec<_> = (0..100).collect();
                let proof = t.prove_batch_inclusion(&idxs);
                proof.as_bytes().len()
            };

            std::println!(
                "For indices [0,100), proof size is {}B / {}B (batch/naive)",
                batch_proof_size,
                naive_proof_size
            );
        }
    }

    // Tests that an out of range index makes batch proving panic
    #[test]
    #[should_panic]
    fn batch_proof_idx_out_of_range() {
        let mut rng = rand::thread_rng();
        let num_leaves = 1000;
        let batch_size = 100;

        // Make a random tree and pick some arbitrary indices to batch prove
        let t = rand_tree(&mut rng, num_leaves);
        let mut idxs: Vec<_> = (34..34 + batch_size).collect();
        // Set the 14th index to be out of range
        idxs[14] = num_leaves + 1;

        // This should panic with an out of range error
        let proof = t.prove_batch_inclusion(&idxs);

        let root = t.root();
        let vals: Vec<_> = idxs
            .iter()
            .map(|&idx| {
                t.get(idx)
                    .cloned()
                    .unwrap_or(crate::test_util::Leaf::default())
            })
            .collect();

        let _ = root.verify_batch_inclusion(&vals, &idxs, &proof);
    }

    // Tests that an out of range index makes batch verification panic
    #[test]
    #[should_panic]
    fn batch_verif_idx_out_of_range() {
        let mut rng = rand::thread_rng();
        let num_leaves = 1000;
        let batch_size = 100;

        // Make a random tree and pick some arbitrary indices to batch prove
        let t = rand_tree(&mut rng, num_leaves);
        let mut idxs: Vec<_> = (34..34 + batch_size).collect();
        let proof = t.prove_batch_inclusion(&idxs);

        // Now set the 14th index to be out of range
        idxs[14] = num_leaves + 1;

        // Get some placeholder values for the verification
        let root = t.root();
        let vals: Vec<_> = idxs
            .iter()
            .map(|&idx| t.get(idx).cloned().unwrap_or(Leaf::default()))
            .collect();

        // Check that verification panics. Not errors, but panics.
        let _ = root.verify_batch_inclusion(&vals, &idxs, &proof);
    }
}
