CT Merkle
=========

This is an implementation of the append-only log described in the [Certificate Transparency specification (RFC 6962)](https://datatracker.ietf.org/doc/html/rfc6962). The log is a Merkle tree, and its leaves are the items it contains.

The log has two important features:

1. **Membership proofs.** You can construct a succinct proof that a particular item appears in a given tree.
2. **Consistency proofs.** You can construct a succinct proof that one tree is a prefix of another tree, i.e., that tree #2 is the result of appending some number of items to the end of tree #1.


TODO
----

* Implement `serde` traits for all the types
* Think about how to make this portable to <64-bit architectures (can't use `u64` for indexing anymore)
* Think about what it'd take to make this `no_std`


License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.


Warning
-------

This code has not been audited in any sense of the word. Use it at your own peril.
