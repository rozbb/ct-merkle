//! This file copies the known-answer tests from the transparency-dev/merkle project. Vectors from
//! https://github.com/transparency-dev/merkle/blob/e739733c8ca2b89cfc49f35b161e81e16b5957d7/testonly/reference_test.go

use ct_merkle::CtMerkleTree;
use sha2::Sha256;

/// An inclusion test vector specifies the size of the tree, the index whose inclusion is being
/// proved, and the expected serialized proof. The leaves of the tree are determined by `LEAVES`.
struct InclusionTestVector {
    num_leaves: usize,
    idx: u64,
    expected_proof: &'static str,
}

/// A consistency test vector specifies the size of the starting tree, the size of the ending tree,
/// and the expected serialized proof. The leaves of the tree are determined by `LEAVES`.
struct ConsistencyTestVector {
    num_leaves1: usize,
    num_leaves2: usize,
    expected_proof: &'static str,
}

const LEAVES: &[&str] = &[
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
];

const INCLUSION_VECS: &[InclusionTestVector] = &[
    InclusionTestVector {
        num_leaves: 1,
        idx: 0,
        expected_proof: "",
    },
    InclusionTestVector {
        num_leaves: 2,
        idx: 0,
        expected_proof: "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
    },
    InclusionTestVector {
        num_leaves: 2,
        idx: 1,
        expected_proof: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    },
    InclusionTestVector {
        num_leaves: 3,
        idx: 2,
        expected_proof: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    },
    InclusionTestVector {
        num_leaves: 5,
        idx: 1,
        expected_proof: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d\
            5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e\
            bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
    },
    InclusionTestVector {
        num_leaves: 8,
        idx: 0,
        expected_proof: "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7\
            5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e\
            6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
    },
    InclusionTestVector {
        num_leaves: 8,
        idx: 5,
        expected_proof: "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b\
            ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0\
            d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    },
];

const CONSISTENCY_VECS: &[ConsistencyTestVector] = &[
    ConsistencyTestVector {
        num_leaves1: 1,
        num_leaves2: 1,
        expected_proof: "",
    },
    ConsistencyTestVector {
        num_leaves1: 1,
        num_leaves2: 8,
        expected_proof: "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7\
			5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e\
			6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
    },
    ConsistencyTestVector {
        num_leaves1: 2,
        num_leaves2: 5,
        expected_proof: "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e\
			bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
    },
    ConsistencyTestVector {
        num_leaves1: 6,
        num_leaves2: 8,
        expected_proof: "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a\
			ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0\
			d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    },
];

/// Appends the first num_leaves items from LEAVES to an empty tree
fn tree_with_size(num_leaves: usize) -> CtMerkleTree<Sha256, Vec<u8>> {
    let mut t = CtMerkleTree::<Sha256, Vec<u8>>::new();
    LEAVES
        .iter()
        .take(num_leaves)
        .map(|l| hex::decode(l).unwrap())
        .for_each(|l| t.push(l).unwrap());

    t
}

#[test]
fn inclusion_kat() {
    for InclusionTestVector {
        num_leaves,
        idx,
        expected_proof,
    } in INCLUSION_VECS
    {
        // Construct an inclusion proof for the given tree and index
        let t = tree_with_size(*num_leaves);
        let proof = t.membership_proof(*idx);

        // Check that the proof is what we expected
        assert_eq!(proof.as_bytes(), hex::decode(expected_proof).unwrap());
    }
}

#[test]
fn consistency_kat() {
    for ConsistencyTestVector {
        num_leaves1,
        num_leaves2,
        expected_proof,
    } in CONSISTENCY_VECS
    {
        // Construct a consistency proof between the smaller and larger tree
        let t = tree_with_size(*num_leaves2);
        let proof = t.consistency_proof(*num_leaves1);

        // Check that the proof is what we expected
        assert_eq!(proof.as_bytes(), hex::decode(expected_proof).unwrap());
    }
}
