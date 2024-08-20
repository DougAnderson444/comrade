use crate::Value;

/// Trait to a key-value storage mechanism
pub trait Pairs {
    /// get a value associated with the key
    fn get(&self, key: String) -> Option<Value>;

    /// add a key-value pair to the storage, returns the previous value if the
    /// key already exists in the data structure
    fn put(&mut self, key: String, value: &Value) -> Option<Value>;
}
