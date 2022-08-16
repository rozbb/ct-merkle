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
    /// Returns a proof of inclusion of the item at the given index. Panics if `idx >= self.len()`.
    pub fn prove_batch_inclusion(&self, idxs: &[usize]) -> BatchInclusionProof<H> {
        // Sort the indices
        let idxs = {
            let mut buf: Vec<InternalIdx> = idxs
                .iter()
                .map(|&idx| InternalIdx::from(LeafIdx::new(idx)))
                .collect();
            buf.sort();
            buf
        };
        let num_leaves = self.leaves.len();
        let root_idx = root_idx(num_leaves);

        // If this is the singleton tree, the proof is empty
        if self.leaves.len() == 1 {
            return BatchInclusionProof {
                proof: Vec::new(),
                _marker: PhantomData,
            };
        }

        // We start at the maximum rlevel and decrease with every round. Not every idx is at the
        // same rlevel, so we need to keep some aside to add at the appropriate level. This vec is
        // already reverse-sorted by rlevel because idx1 < idx2 implies rlevel(idx1) ≥
        // rlevel(idx2) in any complete binary tree.
        let unadded_idxs = idxs;

        let mut cur_rlevel = (&unadded_idxs[0]).rlevel(num_leaves);
        let (mut cur_subtrees, mut unadded_idxs) = {
            let split = unadded_idxs
                .iter()
                .position(|idx| idx.rlevel(num_leaves) < cur_rlevel)
                .unwrap_or(unadded_idxs.len());
            let (l, r) = unadded_idxs.split_at(split);
            (l.to_vec(), r.to_vec())
        };

        let mut proof = Vec::new();

        while cur_rlevel > 0 {
            let mut next_subtrees = Vec::new();
            let mut i = 0;

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

            cur_rlevel -= 1;
            let (nodes_to_add, mut next_unadded_idxs) = {
                let split = unadded_idxs
                    .iter()
                    .position(|idx| idx.rlevel(num_leaves) < cur_rlevel)
                    .unwrap_or(unadded_idxs.len());
                let (l, r) = unadded_idxs.split_at(split);
                (l.to_vec(), r.to_vec())
            };
            next_subtrees.extend_from_slice(&nodes_to_add);
            next_subtrees.sort();
            core::mem::swap(&mut unadded_idxs, &mut next_unadded_idxs);
            core::mem::swap(&mut cur_subtrees, &mut next_subtrees);
        }

        // Sanity check, the last value of cur_subtrees should be the root of the whole tree
        assert_eq!(&cur_subtrees, &[root_idx]);

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
    /// # Panics
    /// Panics if `vals.len() != idxs.len()`
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

        let unadded_leaves = leaf_kv;

        let mut cur_rlevel = (&unadded_leaves[0]).0.rlevel(self.num_leaves);
        let (mut cur_subtrees, mut unadded_idxs) = {
            let split = unadded_leaves
                .iter()
                .position(|(idx, _)| idx.rlevel(self.num_leaves) < cur_rlevel)
                .unwrap_or(unadded_leaves.len());
            let (l, r) = unadded_leaves.split_at(split);
            (l.to_vec(), r.to_vec())
        };

        let mut proof_chunks = proof.chunks(H::OutputSize::USIZE);

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
                    let hash = &cur_subtrees[i + 1].1;
                    // Skip processing the sibling, since we're now merging it into the parent
                    i += 1;

                    hash
                } else {
                    // If the sibling hash isn't already known, then it must be in the proof
                    let sibling_hash_slice = proof_chunks.next().unwrap();
                    digest::Output::<H>::from_slice(sibling_hash_slice)
                };

                // Compute the parent hash and save it for the next iteration
                let par_hash = if cur_idx.is_left(self.num_leaves) {
                    parent_hash::<H>(&cur_hash, sibling_hash)
                } else {
                    parent_hash::<H>(sibling_hash, &cur_hash)
                };
                next_subtrees.push((parent_idx, par_hash));

                i += 1;
            }

            cur_rlevel -= 1;
            let (nodes_to_add, mut next_unadded_idxs) = {
                let split = unadded_idxs
                    .iter()
                    .position(|(idx, _)| idx.rlevel(self.num_leaves) < cur_rlevel)
                    .unwrap_or(unadded_idxs.len());
                let (l, r) = unadded_idxs.split_at(split);
                (l.to_vec(), r.to_vec())
            };
            next_subtrees.extend_from_slice(&nodes_to_add);
            next_subtrees.sort_by_key(|(idx, _)| *idx);
            core::mem::swap(&mut unadded_idxs, &mut next_unadded_idxs);
            core::mem::swap(&mut cur_subtrees, &mut next_subtrees);
        }

        // Sanity check, the last value of cur_subtrees should be the root of the whole tree
        assert_eq!(cur_subtrees.len(), 1);
        assert_eq!(cur_subtrees[0].0, root_idx(self.num_leaves));

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
    use crate::merkle_tree::test::rand_tree;

    use alloc::vec::Vec;

    // Tests that an honestly generated inclusion proof verifies
    #[test]
    fn batch_inclusion_proof_correctness() {
        let mut rng = rand::thread_rng();
        let num_leaves = 1000;
        let batch_size = 100;

        let t = rand_tree(&mut rng, num_leaves);

        let mut max_proof_size = 0;

        // Check inclusion at every index
        for idx in 0..200 {
            let idxs: Vec<_> = (idx..(idx + batch_size)).collect();
            let vals: Vec<_> = idxs
                .iter()
                .map(|&idx| t.get(idx).unwrap())
                .cloned()
                .collect();

            let proof = t.prove_batch_inclusion(&idxs);
            max_proof_size = core::cmp::max(max_proof_size, proof.as_bytes().len());

            // Now check the proof
            let root = t.root();
            root.verify_batch_inclusion(&vals, &idxs, &proof).unwrap();

            // Do a round trip and check that the byte representations match at the end
            let roundtrip_proof = crate::test_util::serde_roundtrip(proof.clone());
            assert_eq!(proof.as_bytes(), roundtrip_proof.as_bytes());
        }

        let _naive_proof_size = t.prove_inclusion(0).as_bytes().len() * batch_size;

        #[cfg(feature = "std")]
        std::println!("Proof sizes were {max_proof_size}B / {_naive_proof_size}B (batch / naive)");
    }
}
