#![no_std]

#[cfg(any(
    target_pointer_width = "32",
    target_pointer_width = "16",
    target_pointer_width = "8"
))]
compile_error!("CT Merkle requires that the architecture's pointers be at least 64 bits");

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod consistency;
pub mod error;
pub mod inclusion;
mod leaf;
mod merkle_tree;
mod tree_math;

pub use leaf::*;
pub use merkle_tree::*;
