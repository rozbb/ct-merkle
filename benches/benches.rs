use ct_merkle::CtMerkleTree;

use byteorder::{BigEndian, WriteBytesExt};
use criterion::{criterion_group, criterion_main, Criterion};
use sha2::Sha256;

type Leaf = [u8; 2];

// The various numbers of leaves we will test
const TREE_SIZES: &[usize] = &[10, 100, 1_000, 10_000];

// The various batch sizes we will test
const BATCH_SIZES: &[usize] = &[1, 5, 50, 500, 5_000];

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

fn bench_inclusion(c: &mut Criterion) {
    for &num_leaves in TREE_SIZES {
        // Make a tree of the appropriate size
        let t = tree_with_size(num_leaves as u16);

        // Now go through all the batch sizes smaller than num_leaves
        for &batch_size in BATCH_SIZES.into_iter().filter(|&&size| size <= num_leaves) {
            // Prove inclusion of the range [0, batch_size) in the tree
            let idxs: Vec<_> = (0..batch_size).collect();

            // First prove using the batched inclusion proof
            c.bench_function(
                &format!("Proving batched inclusion of [0, {batch_size}) in [0, {num_leaves})"),
                |b| {
                    b.iter(|| {
                        t.prove_batch_inclusion(&idxs);
                    });
                },
            );
            // Now prove naively using batch_size individual inclusion proofs
            c.bench_function(
                &format!("Proving naive inclusion of [0, {batch_size}) in [0, {num_leaves})"),
                |b| {
                    b.iter(|| {
                        for &idx in &idxs {
                            t.prove_inclusion(idx);
                        }
                    });
                },
            );

            //
            // Now do verification
            //

            // Collect the necessary values for the verifier
            let batch_proof = t.prove_batch_inclusion(&idxs);
            let naive_proofs: Vec<_> = idxs.iter().map(|&i| t.prove_inclusion(i)).collect();
            let root = t.root();
            let vals: Vec<_> = idxs
                .iter()
                .map(|&idx| t.get(idx).cloned().unwrap_or(Leaf::default()))
                .collect();

            // Run the benches
            c.bench_function(
                &format!("Verifying batched inclusion of [0, {batch_size}) in [0, {num_leaves})"),
                |b| {
                    b.iter(|| {
                        root.verify_batch_inclusion(&vals, &idxs, &batch_proof)
                            .unwrap();
                    });
                },
            );
            c.bench_function(
                &format!("Verifying naive inclusion of [0, {batch_size}) in [0, {num_leaves})"),
                |b| {
                    b.iter(|| {
                        naive_proofs
                            .iter()
                            .zip(idxs.iter())
                            .zip(vals.iter())
                            .for_each(|((proof, &idx), val)| {
                                root.verify_inclusion(&val, idx, &proof).unwrap();
                            })
                    });
                },
            );
        }
    }
}

criterion_group!(benches, bench_inclusion);
criterion_main!(benches);
