use std::fs::File;

use byteorder::{BigEndian, WriteBytesExt};
use ct_merkle::CtMerkleTree;
use serde::{de::Error as SError, Deserialize, Deserializer};
use sha2::Sha256;

/// An inclusion test vector specifies the size of the tree, the index whose inclusion is being
/// proved, and the expected serialized proof. The leaves of the tree are determined by `LEAVES`.
#[derive(Deserialize)]
struct BatchInclusionTestVector {
    num_leaves: u16,
    idxs: Vec<usize>,
    #[serde(deserialize_with = "bytes_from_hex")]
    batch_inclusion_proof: Vec<u8>,
}

// Tells serde how to deserialize bytes from hex
fn bytes_from_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut hex_str = String::deserialize(deserializer)?;
    // Prepend a 0 if it's not even length
    if hex_str.len() % 2 == 1 {
        hex_str.insert(0, '0');
    }
    hex::decode(hex_str).map_err(|e| SError::custom(format!("{:?}", e)))
}

type Leaf = [u8; 2];

/// Generates a tree whose `i`-th leaf is the two-bytes big-endian encoding of `i`
fn tree_with_size(num_leaves: u16) -> CtMerkleTree<Sha256, Leaf> {
    let mut t = CtMerkleTree::new();

    (0..num_leaves).for_each(|i| {
        let mut leaf = Leaf::default();
        let mut cur = &mut leaf[..];
        cur.write_u16::<BigEndian>(i).unwrap();
        t.push(leaf);
    });

    t
}

// Helper for debugging KAT mismatches
fn fmt_proof(proof: &[u8]) -> Vec<String> {
    proof.chunks(16).map(hex::encode).collect()
}

#[test]
fn batch_inclusion_kat() {
    let file = File::open("tests/bpath.json").unwrap();
    let vecs: Vec<BatchInclusionTestVector> = serde_json::from_reader(file).unwrap();

    for BatchInclusionTestVector {
        num_leaves,
        idxs,
        batch_inclusion_proof,
    } in vecs
    {
        // Construct an inclusion proof for the given tree and index
        let t = tree_with_size(num_leaves);
        let proof = t.prove_batch_inclusion(&idxs);

        // Check that the proof is what we expected
        assert!(
            proof.as_bytes() == batch_inclusion_proof,
            "\nexpected: {:?}\n     got {:?}",
            fmt_proof(&batch_inclusion_proof),
            fmt_proof(proof.as_bytes()),
        );
    }
}
