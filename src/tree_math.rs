// We make opaque types for leaf and internal node indices so that we don't accidentally confuse
// them in the math

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeafIdx(u64);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct InternalIdx(u64);

impl LeafIdx {
    pub(crate) fn new(idx: u64) -> Self {
        LeafIdx(idx)
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

// I know I could just expose the underlying usize. But making it an opaque type with a
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

///
/// Below is tree math definitions. We use array-based trees, described in
/// <https://www.ietf.org/archive/id/draft-ietf-mls-protocol-14.html#array-based-trees>
///

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

    pub(crate) fn left_child(&self) -> InternalIdx {
        let k = self.level();
        assert_ne!(k, 0, "cannot compute the child of a level-0 node");

        InternalIdx(self.0 ^ (0x01 << (k - 1)))
    }

    pub(crate) fn right_child(&self, num_leaves: u64) -> InternalIdx {
        let k = self.level();
        assert_ne!(k, 0, "cannot compute the child of a level-0 node");

        let mut r = InternalIdx(self.0 ^ (0x03 << (k - 1)));
        while r.0 >= num_internal_nodes(num_leaves) {
            r = r.left_child();
        }

        r
    }

    pub(crate) fn sibling(&self, num_leaves: u64) -> InternalIdx {
        let p = self.parent(num_leaves);
        if self.0 < p.0 {
            p.right_child(num_leaves)
        } else {
            p.left_child()
        }
    }
}

/// Computes log2(x), with log2(0) set to 0
fn log2(x: u64) -> u64 {
    x.checked_ilog2().unwrap_or(0) as u64 // casting u32 -> u64
}

/// The number of internal nodes necessary to represent a tree with `num_leaves` leaves.
pub(crate) fn num_internal_nodes(num_leaves: u64) -> u64 {
    if num_leaves < 2 {
        0
    } else {
        2 * (num_leaves - 1) + 1
    }
}

pub(crate) fn root_idx(num_leaves: u64) -> InternalIdx {
    let w = num_internal_nodes(num_leaves);
    InternalIdx((1 << log2(w)) - 1)
}
