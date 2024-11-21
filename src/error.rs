//! Error types for inclusion proofs, consistency proofs, and self-checks

use core::fmt;

/// An error representing what went wrong when verifying an inclusion proof
#[derive(Copy, Clone, Debug)]
pub enum InclusionVerifError {
    /// The proof is malformed, meaning it's either too big for the tree, or its length is not a
    /// multiple of the hash function's digest size.
    MalformedProof,

    /// The index of the leaf being verified exceeds the number of leaves in the tree
    IndexOutOfRange,

    /// This root hash belongs to an empty tree. Empty trees cannot have proofs.
    TreeEmpty,

    /// This root hash does not match the proof's root hash
    IncorrectHash,
}

impl fmt::Display for InclusionVerifError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let msg = match self {
            InclusionVerifError::MalformedProof => {
                "proof is either too big for this tree, or not a multiole of the hash digest size"
            }

            InclusionVerifError::IndexOutOfRange => {
                "the index of the leaf being verified exceeds the number of leaves in the tree"
            }

            InclusionVerifError::TreeEmpty => {
                "root hash belongs to an empty tree, and empty trees cannot have proofs"
            }

            InclusionVerifError::IncorrectHash => {
                "this root hash doesn't match the proof's root hash"
            }
        };

        f.write_str(msg)
    }
}

/// An error representing what went wrong when verifying a consistency proof
#[derive(Copy, Clone, Debug)]
pub enum ConsistencyVerifError {
    /// Either this root hash or the old root hash doesn't match the root hashes calculated from
    /// the proof
    VerificationFailure,

    /// The proof is either not a multiple of the hash digest size, or not the right multiple
    MalformedProof,

    /// The number of leaves in the old tree is greater than the number of leaves in the new tree.
    /// Since the new one is supposed to be the old one plus some number of additions, this makes no
    /// sense.
    OldTreeLarger,

    /// The given number of leaves in the old tree is 0, which is not allowed
    OldTreeEmpty,

    /// The given number of leaves in the new tree is exceeds the max of `⌊u64::MAX / 2⌋`
    NewTreeTooBig,
}

impl fmt::Display for ConsistencyVerifError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let msg = match self {
            ConsistencyVerifError::VerificationFailure => {
                "(root, old_root) doesn't match the root hashes calculated from the proof"
            }
            ConsistencyVerifError::MalformedProof => {
                "proof is either not a multiple of the hash digest size, or not the right multiple"
            }
            ConsistencyVerifError::OldTreeLarger => "Old tree has more leaves than the new one",
            Self::OldTreeEmpty => {
                "The given number of leaves in the old tree is 0, which is not allowed"
            }
            Self::NewTreeTooBig => {
                "the given number of leaves in the new tree is exceeds the max of `⌊u64::MAX / 2⌋`"
            }
        };

        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InclusionVerifError {}

#[cfg(feature = "std")]
impl std::error::Error for ConsistencyVerifError {}
