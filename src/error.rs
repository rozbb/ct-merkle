//! Error types for inclusion proofs, consistency proofs, and self-checks

use core::fmt;

/// An error representing what went wrong when verifying an inclusion proof
#[derive(Copy, Clone, Debug)]
pub enum InclusionVerifError {
    /// The proof is malformed, meaning it's either too big for the tree, or its length is not a
    /// multiple of the hash function's digest size.
    MalformedProof,

    /// This root hash does not match the proof's root hash w.r.t. the item
    VerificationFailure,
}

impl fmt::Display for InclusionVerifError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let msg = match self {
            InclusionVerifError::MalformedProof => {
                "proof is either too big for this tree, or not a multiole of the hash digest size"
            }

            InclusionVerifError::VerificationFailure => {
                "this root hash doesn't match the proof's root hash w.r.t. the given item"
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
}

impl fmt::Display for ConsistencyVerifError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let msg = match self {
            ConsistencyVerifError::VerificationFailure => {
                "(root, old_root) doesn't match the root hashes calculated from the proof"
            }
        };

        f.write_str(msg)
    }
}

/// An error representing what went wrong when running `MemoryBackedTree::self_check`.
#[derive(Debug)]
pub enum SelfCheckError {
    /// The node at the given index is missing
    MissingNode(u64),

    /// The node at the given index has the wrong hash
    IncorrectHash(u64),

    /// The number of internal nodes in this struct exceeds the number of nodes that a tree with
    /// this many leaves would hold.
    TooManyInternalNodes,

    /// There are so many leaves that the full tree could not possibly fit in memory
    TooManyLeaves,
}

impl fmt::Display for SelfCheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            SelfCheckError::MissingNode(idx) => write!(f, "the node at index {} is missing", idx),
            SelfCheckError::IncorrectHash(idx) => {
                write!(f, "the node at index {} has the wrong hash", idx)
            }
            SelfCheckError::TooManyInternalNodes => {
                write!(
                    f,
                    "the number of internal nodes in this struct exceedsc the number of nodes \
                    that a tree with this many leaves would hold"
                )
            }
            SelfCheckError::TooManyLeaves => {
                write!(
                    f,
                    "there are so many leaves that the full tree could not possibly fit in memory"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InclusionVerifError {}

#[cfg(feature = "std")]
impl std::error::Error for ConsistencyVerifError {}

#[cfg(feature = "std")]
impl std::error::Error for SelfCheckError {}
