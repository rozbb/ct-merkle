//! Types and traits for inclusion proofs, a.k.a., Merkle Audit Paths

use crate::{
    error::InclusionVerifError,
    leaf::{leaf_hash, CanonicalSerialize},
    merkle_tree::{parent_hash, CtMerkleTree, RootHash},
    tree_math::*,
};

use core::marker::PhantomData;

use digest::{typenum::Unsigned, Digest};

/// A proof that a value appears in a [`CtMerkleTree`]. The byte representation of a
/// [`InclusionProof`] is identical to that of `PATH(m, D[n])` described in RFC 6962 §2.1.1.
pub struct InclusionProof<H: Digest> {
    proof: Vec<u8>,
    _marker: PhantomData<H>,
}

/// A reference to a [`InclusionProof`]
pub struct InclusionProofRef<'a, H: Digest> {
    proof: &'a [u8],
    _marker: PhantomData<H>,
}

impl<H: Digest> AsRef<[u8]> for InclusionProof<H> {
    fn as_ref(&self) -> &[u8] {
        self.proof.as_slice()
    }
}

impl<H: Digest> InclusionProof<H> {
    pub fn as_ref(&self) -> InclusionProofRef<H> {
        InclusionProofRef {
            proof: self.proof.as_slice(),
            _marker: self._marker,
        }
    }

    /// Returns the RFC 6962-compatible byte representation of this inclusion proof
    pub fn as_bytes(&self) -> &[u8] {
        self.proof.as_slice()
    }

    /// Constructs a `InclusionProof` from the given bytes. Panics when `bytes.len()` is not a
    /// multiple of `H::OutputSize::USIZE`, i.e., when `bytes` is not a concatenated sequence of
    /// hash digests.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() % H::OutputSize::USIZE != 0 {
            panic!("malformed inclusion proof");
        } else {
            InclusionProof {
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
    /// Returns a proof of inclusion of the item at the given index. Panics if `idx` exceeds
    /// `Self::len()`.
    pub fn inclusion_proof(&self, idx: u64) -> InclusionProof<H> {
        let num_leaves = self.leaves.len() as u64;
        let root_idx = root_idx(num_leaves as u64);

        // If this is the singleton tree, the proof is empty
        if self.leaves.len() == 1 {
            return InclusionProof {
                proof: Vec::new(),
                _marker: PhantomData,
            };
        }

        // Start the proof with the sibling hash
        let start_idx = InternalIdx::from(LeafIdx::new(idx));
        let leaf_sibling_hash = {
            let sibling_idx = start_idx.sibling(num_leaves);
            &self.internal_nodes[sibling_idx.usize()]
        };
        let mut sibling_hashes = leaf_sibling_hash.to_vec();

        // Collect the hashes of the siblings on the way up the tree
        let mut parent_idx = start_idx.parent(num_leaves);
        while parent_idx != root_idx {
            let sibling_idx = parent_idx.sibling(num_leaves);
            sibling_hashes.extend_from_slice(&self.internal_nodes[sibling_idx.usize()]);

            // Go up a level
            parent_idx = parent_idx.parent(num_leaves);
        }

        InclusionProof {
            proof: sibling_hashes,
            _marker: PhantomData,
        }
    }
}

impl<H: Digest> RootHash<H> {
    /// Verifies that `val` occurs at index `idx` in the tree described by this `RootHash`.
    pub fn verify_inclusion<T: CanonicalSerialize>(
        &self,
        val: &T,
        idx: u64,
        proof: &InclusionProofRef<H>,
    ) -> Result<(), InclusionVerifError> {
        // Check that the proof isn't too big, and is made up of a sequence of hash digests
        let InclusionProofRef { proof, .. } = proof;
        let max_proof_size = {
            let tree_height = root_idx(self.num_leaves).level();
            (tree_height * H::OutputSize::U32) as usize
        };
        // If the proof is too big or the proof length isn't a multiple of the digest size, that's
        // an error
        if proof.len() > max_proof_size || proof.len() % H::OutputSize::USIZE != 0 {
            return Err(InclusionVerifError::MalformedProof);
        }

        // If the proof is empty, then the leaf hash is the root hash
        let leaf_hash = leaf_hash::<H, _>(val);
        if proof.len() == 0 && leaf_hash == self.root_hash {
            return Ok(());
        }

        // Otherwise, start hashing up the tree
        let mut cur_idx: InternalIdx = LeafIdx::new(idx).into();
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
            Err(InclusionVerifError::VerificationFailure)
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::merkle_tree::test::rand_tree;

    // Tests that an honestly generated inclusion proof verifies
    #[test]
    fn inclusion_proof_correctness() {
        let mut rng = rand::thread_rng();

        let t = rand_tree(&mut rng, 100);

        // Check inclusion at every index
        for idx in 0..t.len() {
            let idx = idx as u64;
            let proof = t.inclusion_proof(idx);
            let elem = t.get(idx).unwrap();

            // Now check the proof
            let root = t.root();
            root.verify_inclusion(&elem, idx, &proof.as_ref()).unwrap();
        }
    }
}
