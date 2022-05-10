use std::io::{Error as IoError, Write};

use digest::Digest;

const LEAF_HASH_PREFIX: &[u8] = &[0x00];

/// A trait impl'd by types that have a canonical byte representation. This MUST be implemented by
/// any type you want to insert into a [`CtMerkleTree`](crate::merkle_tree::CtMerkleTree).
pub trait CanonicalSerialize {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), IoError>;
}

// Blanket serialization impl for anything that resembles a bag of bytes
impl<T: AsRef<[u8]>> CanonicalSerialize for T {
    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), IoError> {
        writer.write_all(self.as_ref())
    }
}

// A writer that hashes everything it receives. We compute the hashes of leaves by requiring them
// to impl CanonicalSerialize, and calling serialize(LeafHasher::new())
struct LeafHasher<H: Digest>(H);

impl<H: Digest> LeafHasher<H> {
    fn new() -> Self {
        LeafHasher(H::new_with_prefix(LEAF_HASH_PREFIX))
    }

    fn finalize(self) -> digest::Output<H> {
        self.0.finalize()
    }
}

impl<H: Digest> Write for LeafHasher<H> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, IoError> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        Ok(())
    }
}

/// Computes the hash of the given leaf's canonical byte representation
pub(crate) fn leaf_hash<H, L>(leaf: &L) -> Result<digest::Output<H>, IoError>
where
    H: Digest,
    L: CanonicalSerialize,
{
    let mut hasher = LeafHasher::<H>::new();
    leaf.serialize(&mut hasher)?;
    Ok(hasher.finalize())
}
