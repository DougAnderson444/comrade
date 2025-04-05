#![doc = include_str!("../README.md")]
#![doc = include_str!("../../../README.md")]

pub mod context;
mod error;
pub mod storage;

pub use context::ContextPairs;
pub use context::Current;
pub use context::Proposed;
pub use storage::pairs::Pairs;
pub use storage::stack::Stack;
pub use storage::stack::Stk;
pub use storage::value::Value;

pub use context::Context;
use std::fmt::Debug;

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// Comrade goes starts at [Initial] Stage, then goes to [Unlocked] Stage.
#[derive(Debug)]
pub struct Initial;

/// Comrade goes starts at [Initial] Stage, then goes to [Unlocked] Stage.
#[derive(Debug)]
pub struct Unlocked;

/// Trait Pairable is: [Pairs], [Default], [Debug], and [Clone]
pub trait Pairable: Pairs + Default + Clone + Debug {}

impl<P: Pairs + Default + Clone> Pairable for P {}

#[derive(Debug, Clone)]
pub enum Either<C: Pairable, P: Pairable> {
    Curr(C),
    Prop(P),
}

impl<C: Pairable, P: Pairable> Default for Either<C, P> {
    fn default() -> Self {
        Either::Prop(P::default())
    }
}
impl<C: Pairable, P: Pairable> Pairs for Either<C, P> {
    fn get(&self, key: &str) -> Option<Value> {
        match self {
            Either::Curr(c) => c.get(key),
            Either::Prop(p) => p.get(key),
        }
    }

    fn put(&mut self, key: &str, value: &Value) -> Option<Value> {
        match self {
            Either::Curr(c) => c.put(key, value),
            Either::Prop(p) => p.put(key, value),
        }
    }
}
