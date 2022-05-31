#[cfg(feature = "serde")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

// Leaves are 32-byte bytestrings
pub(crate) type Leaf = [u8; 32];

// The hash function is SHA-256
pub(crate) type Hash = sha2::Sha256;

// If we have serde, do a round trip through serialization and deserialization
#[cfg(feature = "serde")]
pub(crate) fn serde_roundtrip<T: SerdeSerialize + for<'a> SerdeDeserialize<'a>>(val: T) -> T {
    let s = serde_json::to_string(val).unwrap();
    serde_json::from_str(&s).unwrap()
}

// If we don't have serde, just return the input
#[cfg(not(feature = "serde"))]
pub(crate) fn serde_roundtrip<T>(val: T) -> T {
    val
}
