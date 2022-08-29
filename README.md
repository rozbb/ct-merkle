CT Merkle
=========
[![Crate](https://img.shields.io/crates/v/ct-merkle.svg)](https://crates.io/crates/ct-merkle)
[![Docs](https://docs.rs/ct-merkle/badge.svg)](https://docs.rs/ct-merkle)
[![CI](https://github.com/rozbb/ct-merkle/workflows/CI/badge.svg)](https://github.com/rozbb/ct-merkle/actions)

This is an implementation of the append-only log described in the [Certificate Transparency specification (RFC 6962)](https://datatracker.ietf.org/doc/html/rfc6962). The log is a Merkle tree, and its leaves are the items it contains.

The log has two important features:

1. **Inclusion proofs.** You can construct a succinct proof that a particular item appears in a given tree.
2. **Consistency proofs.** You can construct a succinct proof that one tree is a prefix of another tree, i.e., that tree #2 is the result of appending some number of items to the end of tree #1.


Crate Features
--------------

Default feature flags: none

Feature flag list:

* `serde` - Implements `serde::Serialize` and `serde::Deserialize` for: `CtMerkleTree`, `RootHash`, `InclusionProof`, `BatchInclusionProof`, and `ConsistencyProof`
* `std` - Implements `std::error::Error` for all the error types. Also enables known-answer tests in `cargo test`.


License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.


Warning
-------

This code has not been audited in any sense of the word. Use it at your own peril.
