//! Types, functions, and traits for hashing leaves

use digest::Digest;

/// The domain separator used for calculating leaf hashes
const LEAF_HASH_PREFIX: &[u8] = &[0x00];

// The only reason this trait is defined is so that users don't have direct access to the hash
// function being used. To keep things simple, we abstract the hasher in `LeafHasher` as a
// `SimpleWriter`.
/// A very small subset of `std::io::Write`. All this does is unconditionally accept bytes.
pub trait SimpleWriter {
    fn write(&mut self, buf: &[u8]);
}

impl<W: SimpleWriter + ?Sized> SimpleWriter for &mut W {
    fn write(&mut self, buf: &[u8]) {
        (**self).write(buf)
    }
}

/// A trait impl'd by types that have a canonical byte representation. This MUST be implemented by
/// any type you want to insert into a [`CtMerkleTree`](crate::merkle_tree::CtMerkleTree).
pub trait CanonicalSerialize {
    fn serialize<W: SimpleWriter>(&self, writer: W);
}

// Blanket serialization impl for anything that resembles a bag of bytes
impl<T: AsRef<[u8]>> CanonicalSerialize for T {
    fn serialize<W: SimpleWriter>(&self, mut writer: W) {
        writer.write(self.as_ref())
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

impl<H: Digest> SimpleWriter for LeafHasher<H> {
    fn write(&mut self, buf: &[u8]) {
        self.0.update(buf);
    }
}

/// Computes the hash of the given leaf's canonical byte representation
pub(crate) fn leaf_hash<H, L>(leaf: &L) -> digest::Output<H>
where
    H: Digest,
    L: CanonicalSerialize,
{
    let mut hasher = LeafHasher::<H>::new();
    leaf.serialize(&mut hasher);
    hasher.finalize()
}
