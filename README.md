CT Merkle
=========
[![Crate](https://img.shields.io/crates/v/ct-merkle.svg)](https://crates.io/crates/ct-merkle)
[![Docs](https://docs.rs/ct-merkle/badge.svg)](https://docs.rs/ct-merkle)
[![CI](https://github.com/rozbb/ct-merkle/workflows/CI/badge.svg)](https://github.com/rozbb/ct-merkle/actions)

This is an implementation of the Merkle tree functionality described in the [Certificate Transparency specification (RFC 6962)](https://datatracker.ietf.org/doc/html/rfc6962).
Two properties can be proven about trees:

1. **Inclusion proofs** state that a a particular item appears in a given tree.
2. **Consistency proofs** state that one tree is a prefix of another tree, i.e., that tree #2 is the result of appending some number of items to the end of tree #1.

This crate provides an append-only memory-backed Merkle tree with inclusion and consistency proof functionality, as well as functions for proof verification.
In addition, this crate provides functions for building proofs when the full tree does not fit in memory, e.g., in Certificate Transparency.

Crate Features
--------------

Default feature flags: none

Feature flag list:

* `std` - Implements `std::error::Error` for all error types
* `serde` - Implements `serde::Serialize` and `serde::Deserialize` for `MemoryBackedTree`


License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.


Warning
-------

This code has not been audited in any sense of the word. Use it at your own peril.


Example usage
-------------
Below is an example of two ways to construct an inclusion proof.
```rust
# extern crate alloc;
# use alloc::{
#     string::{String, ToString},
#     vec::Vec,
# };
use ct_merkle::{
    indices_for_inclusion_proof, InclusionProof,
    mem_backed_tree::MemoryBackedTree
};
use sha2::Sha256;

# fn main() {
// Make a new tree whose leaves are strings
let mut tree = MemoryBackedTree::<Sha256, String>::new();
tree.push("hello".to_string());
tree.push("world".to_string());
let root = tree.root();

// Prove inclusion of the last item in the tree
let items_pushed = tree.len();
let item_to_prove = items_pushed - 1;
let inclusion_proof = tree.prove_inclusion(item_to_prove as usize);
// Verify the inclusion
assert!(root
    .verify_inclusion(&"world", item_to_prove, &inclusion_proof)
    .is_ok());

// Now imagine we don't have a memory-backed tree. We will get the indices for
// the hashes to fetch and then build the proof
let indices_to_fetch = indices_for_inclusion_proof(items_pushed, item_to_prove);

//
// Imagine here we fetch the indices in order and place them into `digests`...
//

# let digests: Vec<&digest::Output<Sha256>> = inclusion_proof
#     .as_bytes()
#     .chunks(32)
#     .map(Into::into)
#     .collect();
let inclusion_proof = InclusionProof::from_digests(digests);
// Verify the inclusion
assert!(root
    .verify_inclusion(&"world", item_to_prove, &inclusion_proof)
    .is_ok());
# }
```
