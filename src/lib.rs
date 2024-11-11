#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod consistency;
pub mod error;
pub mod inclusion;
mod leaf;
mod mem_backed_tree;
mod tree_math;

#[cfg(test)]
mod test_util;

pub use consistency::*;
pub use inclusion::*;
pub use leaf::*;
pub use mem_backed_tree::*;
