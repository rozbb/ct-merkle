//! Types and traits for inclusion proofs, a.k.a., Merkle Audit Paths

use crate::{
    error::InclusionVerifError, mem_backed_tree::MemoryBackedTree, tree_util::*, RootHash,
};

use alloc::vec::Vec;
use core::marker::PhantomData;

use digest::{typenum::Unsigned, Digest};
use subtle::ConstantTimeEq;

/// A proof that a value appears in a Merkle tree
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof<H: Digest> {
    proof: Vec<u8>,
    _marker: PhantomData<H>,
}

impl<H: Digest> InclusionProof<H> {
    /// Returns the byte representation of this inclusion proof.
    ///
    /// This is precisely `PATH(m, D[n])`, described in [RFC 6962
    /// §2.1.1](https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1.1), where `n` is the number
    /// of leaves and `m` is the leaf index being proved.
    pub fn as_bytes(&self) -> &[u8] {
        self.proof.as_slice()
    }

    /// Constructs an `InclusionProof` from its serialized form.
    ///
    /// # Panics
    /// Panics when `bytes.len()` is not a multiple of `H::OutputSize::USIZE`, i.e., when `bytes` is
    /// not a concatenated sequence of hash digests.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        if bytes.len() % H::OutputSize::USIZE != 0 {
            panic!("malformed inclusion proof");
        } else {
            InclusionProof {
                proof: bytes,
                _marker: PhantomData,
            }
        }
    }

    /// Constructs an `InclusionProof` from a sequence of digests.
    pub fn from_digests<'a>(digests: impl IntoIterator<Item = &'a digest::Output<H>>) -> Self {
        // The proof is just a concatenation of hashes
        let concatenated_hashes = digests.into_iter().flatten().cloned().collect();

        InclusionProof {
            proof: concatenated_hashes,
            _marker: PhantomData,
        }
    }

    /// Constructs a `InclusionProof` from the given bytes.
    ///
    /// # Errors
    ///
    /// If when `bytes.len()` is not a multiple of `H::OutputSize::USIZE`, i.e., when `bytes`
    /// is not a concatenated sequence of hash digests.
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, InclusionVerifError> {
        if bytes.len() % H::OutputSize::USIZE != 0 {
            return Err(InclusionVerifError::MalformedProof);
        }

        Ok(InclusionProof {
            proof: bytes,
            _marker: PhantomData,
        })
    }
}

impl<H, T> MemoryBackedTree<H, T>
where
    H: Digest,
    T: HashableLeaf,
{
    /// Returns a proof of inclusion of the item at the given index.
    ///
    /// # Panics
    /// Panics if `idx >= self.len()`.
    pub fn prove_inclusion(&self, idx: usize) -> InclusionProof<H> {
        let num_leaves = self.len();

        // Get the indices we need to make the proof
        let idxs = indices_for_inclusion_proof(num_leaves, idx as u64);
        // Get the hashes at those indices. We can unwrap below because the indices are guaranteed
        // to be in the tree, which is stored in memory
        let sibling_hashes = idxs
            .iter()
            .map(|&i| &self.internal_nodes[usize::try_from(i).unwrap()]);

        // Make the proof
        InclusionProof::from_digests(sibling_hashes)
    }
}

/// Given a tree size and index, produces a list of tree node indices whose values we need in order
/// to build the inclusion proof.
///
/// This is useful when we don't have the entire tree in memory, e.g., when it is stored on disk or
/// stored in tiles on a remote server. Once the digests are retreived, they can be used in the same
/// order in [`InclusionProof::from_digests`].
///
/// # Panics
/// Panics if `num_leaves == 0`, if `idx >= num_leaves`, or if `idx > ⌊u64::MAX / 2⌋`.
pub fn indices_for_inclusion_proof(num_leaves: u64, idx: u64) -> Vec<u64> {
    if num_leaves == 0 {
        panic!("cannot create an inclusion proof for an empty tree")
    }
    if idx >= num_leaves {
        panic!("cannot create an inclusion proof for an index that's not in the tree")
    }
    if idx > u64::MAX / 2 {
        panic!("leaf index is too high")
    }

    let mut out = Vec::new();
    let root_idx = root_idx(num_leaves);

    // If this is the singleton tree, the proof is empty, and we need no values
    if num_leaves == 1 {
        return out;
    }

    // Start the proof with the sibling hash
    let start_idx = InternalIdx::from(LeafIdx::new(idx));
    let sibling_idx = start_idx.sibling(num_leaves);
    out.push(sibling_idx.as_u64());

    // Collect the hashes of the siblings on the way up the tree
    let mut parent_idx = start_idx.parent(num_leaves);
    while parent_idx != root_idx {
        let sibling_idx = parent_idx.sibling(num_leaves);
        out.push(sibling_idx.as_u64());

        // Go up a level
        parent_idx = parent_idx.parent(num_leaves);
    }

    out
}

impl<H: Digest> RootHash<H> {
    /// Verifies that `val` occurs at index `idx` in the tree described by this `RootHash`. This
    /// does not panic.
    ///
    /// # Note
    /// Verification success does NOT imply that the size of the tree that produced the proof equals
    /// `self.num_leaves()`. For any given proof, there are multiple tree sizes that could have
    /// produced it.
    pub fn verify_inclusion<T: HashableLeaf>(
        &self,
        val: &T,
        idx: u64,
        proof: &InclusionProof<H>,
    ) -> Result<(), InclusionVerifError> {
        if idx >= self.num_leaves {
            return Err(InclusionVerifError::IndexOutOfRange);
        }
        if self.num_leaves == 0 {
            return Err(InclusionVerifError::TreeEmpty);
        }

        // Check that the proof is the right size. If not, return an error
        let InclusionProof { proof, .. } = proof;
        // We can call indices_for_inclusion_proof without panicking because we checked that
        // idx < self.num_leaves and self.num_leaves != 0 above
        let expected_proof_size = {
            let num_hashes = indices_for_inclusion_proof(self.num_leaves, idx).len();
            H::OutputSize::USIZE * num_hashes
        };
        if proof.len() != expected_proof_size {
            return Err(InclusionVerifError::MalformedProof);
        }

        // If the proof is empty, then the leaf hash is the root hash
        let leaf_hash = leaf_hash::<H, _>(val);
        if proof.is_empty() && leaf_hash.ct_eq(&self.root_hash).into() {
            return Ok(());
        }

        // Otherwise, start hashing up the tree
        let mut cur_idx: InternalIdx = LeafIdx::new(idx).into();
        let mut cur_hash = leaf_hash;
        // Invariant: hash_slice is always H::OutputSize::USIZE because we checked above that
        // proof.len() is the correct length, which calculated as a multiple of the digest len
        for hash_slice in proof.chunks(H::OutputSize::USIZE) {
            // Hash the current node with its provided sibling
            let sibling_hash = digest::Output::<H>::from_slice(hash_slice);
            if cur_idx.is_left(self.num_leaves) {
                cur_hash = parent_hash::<H>(&cur_hash, sibling_hash);
            } else {
                cur_hash = parent_hash::<H>(sibling_hash, &cur_hash);
            }

            // Step up the tree
            // This panics if `cur_idx` is the root index. This cannot happen because have checked
            // that `idx < self.num_leaves`, and the proof is the correct length, i.e., precisely
            // long enough for the *final* value of `cur_idx` to be the root index.
            cur_idx = cur_idx.parent(self.num_leaves);
        }

        // Now compare the final hash with the root hash
        if cur_hash.ct_eq(&self.root_hash).into() {
            Ok(())
        } else {
            Err(InclusionVerifError::IncorrectHash)
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::{mem_backed_tree::test::rand_tree, RootHash};

    // Tests that an honestly generated inclusion proof verifies
    #[test]
    fn inclusion_proof_correctness() {
        let mut rng = rand::thread_rng();

        let t = rand_tree(&mut rng, 100);

        // Check inclusion at every index
        for idx in 0..t.len() as usize {
            let proof = t.prove_inclusion(idx);
            let elem = t.get(idx).unwrap();

            // Now check the proof
            let root = t.root();
            root.verify_inclusion(&elem, idx as u64, &proof).unwrap();

            // Make two roots whose tree heights are different from the original. This should
            // trigger a "proof isn't the correct length" error.
            let modified_root = RootHash::new(*root.as_bytes(), 2 * root.num_leaves());
            assert!(modified_root
                .verify_inclusion(&elem, idx as u64, &proof)
                .is_err());
            let modified_root = RootHash::new(*root.as_bytes(), root.num_leaves() / 2);
            assert!(modified_root
                .verify_inclusion(&elem, idx as u64, &proof)
                .is_err());
        }
    }
}
