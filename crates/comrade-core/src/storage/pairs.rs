use crate::Value;
use std::fmt::Debug;

/// Trait to a key-value storage mechanism
pub trait Pairs: Debug {
    /// get a value associated with the key
    fn get(&self, key: &str) -> Option<Value>;

    /// add a key-value pair to the storage, returns the previous value if the
    /// key already exists in the data structure
    fn put(&mut self, key: &str, value: &Value) -> Option<Value>;
}
