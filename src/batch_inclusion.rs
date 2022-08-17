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

/// Splits `v`, returning the vector containing the elements at indices `[0, at)` and
/// mutating `v` to contain the elements indices `[at, len)`. In other words, this is the
/// opposite of `Vec::split_off`
fn multipop<T>(v: &mut Vec<T>, at: usize) -> Vec<T> {
    let suffix = v.split_off(at);
    core::mem::replace(v, suffix)
}

impl<H, T> CtMerkleTree<H, T>
where
    H: Digest,
    T: CanonicalSerialize,
{
    /// Returns a batched proof of inclusion of the items at the given indices.
    ///
    /// Panics if `idxs[i] >= self.len()` for any `i`.
    pub fn prove_batch_inclusion(&self, idxs: &[usize]) -> BatchInclusionProof<H> {
        // Sort the indices
        let idxs: Vec<InternalIdx> = {
            let mut buf: Vec<_> = idxs
                .iter()
                .map(|&idx| InternalIdx::from(LeafIdx::new(idx)))
                .collect();
            buf.sort();
            buf
        };
        let num_leaves = self.leaves.len();

        // If this is the singleton tree, the proof is empty
        if self.leaves.len() == 1 {
            return BatchInclusionProof {
                proof: Vec::new(),
                _marker: PhantomData,
            };
        }

        // We start at the maximum rlevel and decrease with every round. Not every leaf is at the
        // same rlevel, so we need to keep some aside to add at the appropriate iteration. This vec
        // is already reverse-sorted by rlevel because i < j implies rlevel(i) ≥ rlevel(j) in any
        // complete binary tree.
        let mut unadded_leaves = idxs;

        // Start with the deepest set of leaves
        let mut cur_rlevel = (&unadded_leaves[0]).rlevel(num_leaves);
        // INVARIANT: cur_subtrees will always be sorted (ascending) by index
        let mut cur_subtrees = {
            // Find the next deepest leaf and cut the vec off there
            let split = unadded_leaves
                .iter()
                .position(|idx| idx.rlevel(num_leaves) < cur_rlevel)
                .unwrap_or(unadded_leaves.len());
            multipop(&mut unadded_leaves, split)
        };

        let mut proof = Vec::new();

        // We grow the subtrees until they converge to the root
        while cur_rlevel > 0 {
            let mut next_subtrees = Vec::new();
            let mut i = 0;

            // Go through the current subtree set, computing parents and merging any adjacent
            // subtrees which happen to be siblings
            while i < cur_subtrees.len() {
                let idx = &cur_subtrees[i];
                next_subtrees.push(idx.parent(num_leaves));
                let sibling_idx = idx.sibling(num_leaves);

                // If the next node is this node's sibling, skip the next iteration. They have been
                // merged into their parent.
                if cur_subtrees
                    .get(i + 1)
                    .map(|&idx2| idx2 == sibling_idx)
                    .unwrap_or(false)
                {
                    i += 1;
                } else {
                    // If the next node is not the sibling, then we need to add the sibling to the
                    // proof
                    proof.extend_from_slice(&self.internal_nodes[sibling_idx.as_usize()]);
                }

                i += 1;
            }

            // We're done with this level. Find all the unadded leaves from the next level and add
            // them.
            cur_rlevel -= 1;
            let leaves_to_add = {
                // Find the next deepest leaf and cut the vec off there
                let split = unadded_leaves
                    .iter()
                    .position(|idx| idx.rlevel(num_leaves) < cur_rlevel)
                    .unwrap_or(unadded_leaves.len());
                multipop(&mut unadded_leaves, split)
            };
            next_subtrees.extend_from_slice(&leaves_to_add);

            // INVARIANT: next_subtrees is sorted (ascending).
            // We can prove this quickly. After the above line, next_subtrees is of the form
            // [parent(idx1), ..., parent(idxk), idx(k+1), ..., idxn] for some integers k, n. By
            // induction, cur_subtrees is sorted, because the first cur_subtrees came from idxs
            // which is sorted, and cur_subtrees is the previous next_subtrees. Since parent() of a
            // sorted list is sorted, the LHS of next_subtrees is sorted. Further, since the RHS
            // comes from unadded_leaves, which is sorted by idx (as well as rlevel), the RHS is
            // sorted.
            // It remains only to prove that parent(idxk) ≤ idx(k+1). Well, we know
            // rlevel(idx(k+1)) < rlevel(parent(idxk)), otherwise idx(k+1) would have been taken
            // from leaves_to_add already. Recall that i < j implies rlevel(i) ≥ rlevel(j) in any
            // complete binary tree. By contrapositive, idx(k+1) ≥ parent(idxk).

            // Update the current subtrees
            core::mem::swap(&mut cur_subtrees, &mut next_subtrees);
        }

        BatchInclusionProof {
            proof,
            _marker: PhantomData,
        }
    }
}

impl<H: Digest> RootHash<H> {
    /// For all `i`, verifies that `val[i]` occurs at index `idx[i]` in the tree described by this
    /// `RootHash`.
    ///
    /// Panics if `vals.len() != idxs.len()`.
    pub fn verify_batch_inclusion<T: CanonicalSerialize>(
        &self,
        vals: &[T],
        idxs: &[usize],
        proof: &BatchInclusionProof<H>,
    ) -> Result<(), InclusionVerifError> {
        // Check that there as many vals as idxs
        assert_eq!(vals.len(), idxs.len());

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

        // We start at the maximum rlevel and decrease with every round. Not every leaf is at the
        // same rlevel, so we need to keep some aside to add at the appropriate iteration. This vec
        // is already reverse-sorted by rlevel because i < j implies rlevel(i) ≥ rlevel(j) in any
        // complete binary tree.
        let mut unadded_leaves = leaf_kv;

        // Start with the deepest set of leaves
        let mut cur_rlevel = (&unadded_leaves[0]).0.rlevel(self.num_leaves);
        // INVARIANT: cur_subtrees will always be sorted (ascending) by index
        let mut cur_subtrees = {
            // Find the next deepest leaf and cut the vec off there
            let split = unadded_leaves
                .iter()
                .position(|(idx, _)| idx.rlevel(self.num_leaves) < cur_rlevel)
                .unwrap_or(unadded_leaves.len());
            multipop(&mut unadded_leaves, split)
        };

        let mut sibling_hashes = proof.chunks(H::OutputSize::USIZE);

        // We grow the subtrees until they converge to the root
        while cur_rlevel > 0 {
            let mut next_subtrees = Vec::new();
            let mut i = 0;

            while i < cur_subtrees.len() {
                let (cur_idx, cur_hash) = &cur_subtrees[i];
                let sibling_idx = cur_idx.sibling(self.num_leaves);
                let parent_idx = cur_idx.parent(self.num_leaves);

                // If the next node is this node's sibling, then use its hash directly. If not,
                // then the sibling hash must be the next hash in the proof, so use that.
                let sibling_hash = if cur_subtrees
                    .get(i + 1)
                    .map(|(idx2, _)| *idx2 == sibling_idx)
                    .unwrap_or(false)
                {
                    // Get the hash of the next subtree, ie the sibling subtree
                    let hash = &cur_subtrees[i + 1].1;

                    // Skip processing the sibling, since we're now merging it into the parent
                    i += 1;

                    hash
                } else {
                    // If the sibling hash isn't already known, then it must be in the proof. If
                    // it's not, then the proof is malformed
                    let sibling_hash_slice = if let Some(h) = sibling_hashes.next() {
                        h
                    } else {
                        return Err(InclusionVerifError::MalformedProof);
                    };
                    digest::Output::<H>::from_slice(sibling_hash_slice)
                };

                // Compute the parent hash and save it for the next iteration
                let parent_hash = if cur_idx.is_left(self.num_leaves) {
                    parent_hash::<H>(&cur_hash, sibling_hash)
                } else {
                    parent_hash::<H>(sibling_hash, &cur_hash)
                };
                next_subtrees.push((parent_idx, parent_hash));

                i += 1;
            }

            // We're done with this level. Find all the unadded leaves from the next level and add
            // them.
            cur_rlevel -= 1;
            let nodes_to_add = {
                // Find the next deepest leaf and cut the vec off there
                let split = unadded_leaves
                    .iter()
                    .position(|(idx, _)| idx.rlevel(self.num_leaves) < cur_rlevel)
                    .unwrap_or(unadded_leaves.len());
                multipop(&mut unadded_leaves, split)
            };
            next_subtrees.extend_from_slice(&nodes_to_add);

            // INVARIANT: next_subtrees is sorted (ascending) by index.
            // This is proved in the comments of prove_batch_inclusion

            // Update the current subtrees
            core::mem::swap(&mut cur_subtrees, &mut next_subtrees);
        }

        // Now compare the final hash with the root hash
        if cur_subtrees[0].1.ct_eq(&self.root_hash).into() {
            Ok(())
        } else {
            Err(InclusionVerifError::VerificationFailure)
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::{merkle_tree::test::rand_tree, test_util::Hash};

    use alloc::vec::Vec;
    use digest::Digest;

    // Tests that an honestly generated inclusion proof verifies
    #[test]
    fn batch_inclusion_proof_correctness() {
        let mut rng = rand::thread_rng();
        let num_leaves = 1000;
        let batch_size = 100;

        let t = rand_tree(&mut rng, num_leaves);

        // We keep track of the largest observed proof size
        let mut max_proof_size = 0;

        // Check inclusion at every index
        for idx in 0..200 {
            let idxs: Vec<_> = (idx..(idx + batch_size)).collect();
            let vals: Vec<_> = idxs
                .iter()
                .map(|&idx| t.get(idx).unwrap())
                .cloned()
                .collect();

            // Do the batch proof and record the proof size
            let proof = t.prove_batch_inclusion(&idxs);
            max_proof_size = core::cmp::max(max_proof_size, proof.as_bytes().len());

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

        // The naive proving method is to do `batch_size` many inclusion proofs
        let _naive_proof_size = t.prove_inclusion(0).as_bytes().len() * batch_size;

        #[cfg(feature = "std")]
        std::println!("Proof sizes were {max_proof_size}B / {_naive_proof_size}B (batch / naive)");
    }

    // Tests that an out of range index makes batch proving panic
    #[test]
    #[should_panic]
    fn idx_out_of_range() {
        let mut rng = rand::thread_rng();
        let num_leaves = 1000;
        let batch_size = 100;

        // Make a random tree and pick some arbitrary indices to batch prove
        let t = rand_tree(&mut rng, num_leaves);
        let mut idxs: Vec<_> = (34..34 + batch_size).collect();
        // Set the 14th index to be out of range
        idxs[14] = num_leaves + 1;

        // This should panic with an out of range error
        t.prove_batch_inclusion(&idxs);
    }
}
