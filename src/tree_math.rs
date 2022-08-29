#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeafIdx(usize);

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct InternalIdx(usize);

// I know I could just expose the underlying usize. But making it an opaque type with a
// constructor and a getter seems safer
impl LeafIdx {
    pub(crate) fn new(idx: usize) -> Self {
        LeafIdx(idx)
    }

    pub(crate) fn as_usize(&self) -> usize {
        self.0
    }
}

// I know I could just expose the underlying usize. But making it an opaque type with a
// constructor and a getter seems safer
impl InternalIdx {
    pub(crate) fn new(idx: usize) -> Self {
        InternalIdx(idx)
    }

    pub(crate) fn as_usize(&self) -> usize {
        self.0
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
    /// If this internal index is a leaf, returns its `LeafIdx`. Otherwise returns `None`.
    pub(crate) fn as_leaf(&self) -> Option<LeafIdx> {
        if self.0 % 2 == 0 {
            Some(LeafIdx::new(self.0 / 2))
        } else {
            None
        }
    }

    // The level of an internal node is how "odd" it is, i.e., how many trailing ones it has in its
    // binary representation
    pub(crate) fn level(&self) -> u32 {
        self.0.trailing_ones()
    }

    // Returns whether this node is to the left of its parent
    pub(crate) fn is_left(&self, num_leaves: usize) -> bool {
        let p = self.parent(num_leaves);
        self.0 < p.0
    }

    // The rest of the functions are a direct translation of the array-tree math in
    /// https://www.ietf.org/archive/id/draft-ietf-mls-protocol-14.html#array-based-trees

    pub(crate) fn parent(&self, num_leaves: usize) -> InternalIdx {
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

    pub(crate) fn right_child(&self, num_leaves: usize) -> InternalIdx {
        let k = self.level();
        assert_ne!(k, 0, "cannot compute the child of a level-0 node");

        let mut r = InternalIdx(self.0 ^ (0x03 << (k - 1)));
        while r.0 >= num_internal_nodes(num_leaves) {
            r = r.left_child();
        }

        r
    }

    pub(crate) fn sibling(&self, num_leaves: usize) -> InternalIdx {
        let p = self.parent(num_leaves);
        if self.0 < p.0 {
            p.right_child(num_leaves)
        } else {
            p.left_child()
        }
    }

    pub(crate) fn is_ancestor(&self, other: InternalIdx) -> bool {
        if self.level() <= other.level() {
            return false;
        }

        // Normalize the indices, shifting to the leftmost subtree
        let my_level = self.level();
        let normalized_self = 2usize.pow(my_level) - 1;
        let diff = self.0 - normalized_self;
        let normalized_other = other.0 - diff;

        normalized_other <= 2 * (normalized_self)
    }
}

fn log2(x: usize) -> usize {
    // We set log2(0) == 0
    if x == 0 {
        0
    } else {
        let mut k = 0;
        while (x >> k) > 0 {
            k += 1;
        }
        k - 1
    }
}

/// The number of internal nodes necessary to represent a tree with `num_leaves` leaves.
pub(crate) fn num_internal_nodes(num_leaves: usize) -> usize {
    if num_leaves < 2 {
        0
    } else {
        2 * (num_leaves - 1) + 1
    }
}

pub(crate) fn root_idx(num_leaves: usize) -> InternalIdx {
    let w = num_internal_nodes(num_leaves);
    InternalIdx((1 << log2(w)) - 1)
}
