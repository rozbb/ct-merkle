# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Additions

* Added `indices_for_inclusion_proof()` and `indices_for_consistency_proof()` methods. These allow the construction of inclusion proofs for trees which do not fit into memory.
* Relatedly, added `InclusionProof::from_digests()` and `ConsistencyProof::from_digests()`

### Removals

* Removed `SimpleWriter` trait in favor of the pre-existing `digest::Update`
* Removed `serde` trait impls from `InclusionProof`, `ConsistencyProof`, and `RootHash`

### Changes

* Renamed the `CtMerkleTree` struct to `MemoryBackedTree`
* Renamed the `CanonicalSerialize` trait to `HashableLeaf`
* Changed argument to `MemoryBackedTree::prove_consistency` to be the number of additions, rather than the size of the prefix
* Made all verification methods panic-free
