use digest::Digest;

/// The domain separator used for calculating leaf hashes
const LEAF_HASH_PREFIX: &[u8] = &[0x00];

/// The domain separator used for calculating parent hashes
const PARENT_HASH_PREFIX: &[u8] = &[0x01];

// We make opaque types for leaf and internal node indices so that we don't accidentally confuse
// them in the math

/// An index to a leaf of the tree
// INVARIANT: self.0 <= floor(u64::MAX / 2)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeafIdx(u64);

/// An index to an "internal" node of the tree, i.e., a leaf hash or parent node. If there are N
/// leaves, then there are 2*(N - 1) + 1 internal nodes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct InternalIdx(u64);

impl LeafIdx {
    /// # Panics
    /// Panics if `idx > ⌊u64::MAX / 2⌋`
    pub(crate) fn new(idx: u64) -> Self {
        assert!(idx <= u64::MAX / 2);
        LeafIdx(idx)
    }

    /// Returns this index as a `usize` if it fits
    pub(crate) fn as_usize(&self) -> Option<usize> {
        self.0.try_into().ok()
    }
}

// I know I could just expose the underlying u64. But making it an opaque type with a
// constructor and a getter seems safer
impl InternalIdx {
    pub(crate) fn new(idx: u64) -> Self {
        InternalIdx(idx)
    }

    /// Returns this index as a `u64`
    pub(crate) fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns this index as a `usize`
    pub(crate) fn as_usize(&self) -> Option<usize> {
        self.0.try_into().ok()
    }
}

/// Represents a leaf that can be included in a Merkle tree. This only requires that the leaf have a
/// unique hash representation.
pub trait HashableLeaf {
    fn hash<H: digest::Update>(&self, hasher: &mut H);
}

// Blanket hasher impl for anything that resembles a bag of bytes
impl<T: AsRef<[u8]>> HashableLeaf for T {
    fn hash<H: digest::Update>(&self, hasher: &mut H) {
        hasher.update(self.as_ref())
    }
}

/// A hasher that prepends the leaf-hash prefix
struct LeafHasher<H: Digest>(H);

impl<H: Digest> LeafHasher<H> {
    fn new() -> Self {
        LeafHasher(H::new_with_prefix(LEAF_HASH_PREFIX))
    }

    fn finalize(self) -> digest::Output<H> {
        self.0.finalize()
    }
}

impl<H: Digest> digest::Update for LeafHasher<H> {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
}

/// Computes the hash of the given leaf's canonical byte representation
pub(crate) fn leaf_hash<H, L>(leaf: &L) -> digest::Output<H>
where
    H: Digest,
    L: HashableLeaf,
{
    let mut hasher = LeafHasher::<H>::new();
    leaf.hash(&mut hasher);
    hasher.finalize()
}

/// Computes the parent of the two given subtrees. This is `H(0x01 || left || right)`.
pub(crate) fn parent_hash<H: Digest>(
    left: &digest::Output<H>,
    right: &digest::Output<H>,
) -> digest::Output<H> {
    let mut hasher = H::new_with_prefix(PARENT_HASH_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()
}

//
// Below is tree math definitions. We use array-based trees, described in
// https://www.rfc-editor.org/rfc/rfc9420.html#name-array-based-trees
//

impl From<LeafIdx> for InternalIdx {
    fn from(leaf: LeafIdx) -> InternalIdx {
        InternalIdx(2 * leaf.0)
    }
}

impl InternalIdx {
    // The level of an internal node is how "odd" it is, i.e., how many trailing ones it has in its
    // binary representation
    pub(crate) fn level(&self) -> u32 {
        self.0.trailing_ones()
    }

    // Returns whether this node is to the left of its parent
    pub(crate) fn is_left(&self, num_leaves: u64) -> bool {
        let p = self.parent(num_leaves);
        self.0 < p.0
    }

    // The rest of the functions are a direct translation of the array-tree math in
    /// https://www.ietf.org/archive/id/draft-ietf-mls-protocol-14.html#array-based-trees

    /// Returns the parent of this node, in a tree of `num_leaves` leaves
    ///
    /// # Panics
    /// Panics if this is the root
    pub(crate) fn parent(&self, num_leaves: u64) -> InternalIdx {
        fn parent_step(idx: InternalIdx) -> InternalIdx {
            let k = idx.level();
            let b = (idx.0 >> (k + 1)) & 0x01;
            InternalIdx((idx.0 | (1 << k)) ^ (b << (k + 1)))
        }

        if *self == root_idx(num_leaves) {
            panic!("root has no parent");
        }

        let mut p = parent_step(*self);
        while p.0 >= num_internal_nodes(num_leaves) {
            p = parent_step(p);
        }

        p
    }

    /// Returns the left child of this node, in a tree of `num_leaves` leaves
    ///
    /// # Panics
    /// Panics if this is a leaf
    pub(crate) fn left_child(&self) -> InternalIdx {
        let k = self.level();
        assert_ne!(k, 0, "cannot compute the child of a leaf");

        InternalIdx(self.0 ^ (0x01 << (k - 1)))
    }

    /// Returns the right child of this node, in a tree of `num_leaves` leaves
    ///
    /// # Panics
    /// Panics if this is a leaf
    pub(crate) fn right_child(&self, num_leaves: u64) -> InternalIdx {
        let k = self.level();
        assert_ne!(k, 0, "cannot compute the child of a leaf");

        let mut r = InternalIdx(self.0 ^ (0x03 << (k - 1)));
        while r.0 >= num_internal_nodes(num_leaves) {
            r = r.left_child();
        }

        r
    }

    /// Returns the sibling of this node, in a tree of `num_leaves` leaves
    ///
    /// # Panics
    /// Panics if this is the root
    pub(crate) fn sibling(&self, num_leaves: u64) -> InternalIdx {
        let p = self.parent(num_leaves);
        // *_child cannot panic because p is guaranteed to not be a leaf
        if self.0 < p.0 {
            p.right_child(num_leaves)
        } else {
            p.left_child()
        }
    }
}

/// Computes log2(x), with log2(0) := 0
fn log2(x: u64) -> u64 {
    x.checked_ilog2().unwrap_or(0) as u64 // casting u32 -> u64
}

/// The number of internal nodes necessary to represent a tree with `num_leaves` leaves.
///
/// # Panics
/// Panics when `num_leaves > ⌊u64::MAX / 2⌋ + 1`
pub(crate) fn num_internal_nodes(num_leaves: u64) -> u64 {
    if num_leaves == 0 {
        0
    } else {
        2 * (num_leaves - 1) + 1
    }
}

/// Returns the root index of a tree with `num_leaves` leaves
///
/// # Panics
/// Panics when `num_leaves > ⌊u64::MAX / 2⌋ + 1`
pub(crate) fn root_idx(num_leaves: u64) -> InternalIdx {
    let w = num_internal_nodes(num_leaves);
    InternalIdx((1 << log2(w)) - 1)
}
