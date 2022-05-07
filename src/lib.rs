mod leaf;
pub mod merkle_tree;

#[cfg(any(
    target_pointer_width = "32",
    target_pointer_width = "16",
    target_pointer_width = "8"
))]
compile_error!("CT Merkle requires that the architecture's pointers be at least 64 bits");

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
