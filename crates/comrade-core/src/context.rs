//! Context module
use super::Pairable;
use crate::storage::pairs::Pairs;
use crate::storage::stack::Stack as _;
use crate::storage::{stack::Stk, value::Value};
use crate::Either;
use multihash::{mh, Multihash};
use multikey::{Multikey, Views as _};
use multisig::Multisig;
use multiutil::CodecInfo;
use std::collections::HashMap;
use std::ops::Deref;
use tracing::{debug, info, warn};

/// A simple key-value store that implement [Pairs] uses a HashMap to store the key-value pairs.
/// Used for examples and testing.
#[derive(Clone, Default, Debug)]
pub struct ContextPairs {
    pairs: HashMap<String, Value>,
}

impl Pairs for ContextPairs {
    fn get(&self, key: &str) -> Option<Value> {
        self.pairs.get(key).cloned()
    }

    fn put(&mut self, key: &str, value: &Value) -> Option<Value> {
        self.pairs.insert(key.to_string(), value.clone())
    }
}

#[derive(Debug)]
pub struct Context<C: Pairable, P: Pairable> {
    /// The current key-value store for the key-pairs. Can be any type that implements the [Pairs] trait
    pub(crate) current: Either<C, P>,

    /// The proposed key-value store for the Context keypairs
    pub proposed: P,

    /// The number of times a check_* operation has been executed
    pub check_count: usize,

    /// The Return stack
    pub rstack: Stk,

    /// The Parameters stack
    pub(crate) pstack: Stk,

    /// Optional domain segment of the /branch/leaf/ key-path. Defaults to "/".
    pub domain: String,
}

impl<C: Pairable, P: Pairable> Clone for Context<C, P> {
    fn clone(&self) -> Self {
        Context {
            current: self.current.clone(),
            proposed: self.proposed.clone(),
            check_count: self.check_count,
            rstack: self.rstack.clone(),
            pstack: self.pstack.clone(),
            domain: self.domain.clone(),
        }
    }
}

/// NewType wrapper to ensure Current key-value is used for the Context
#[derive(Debug, Default, Clone)]
pub struct Current<P: Pairable>(pub P);

// impl for smart pointer [Current] such that it acts a <P>
impl<P: Pairable> Deref for Current<P> {
    type Target = P;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<P: Pairable> From<P> for Current<P> {
    fn from(p: P) -> Self {
        Current(p)
    }
}

impl<P: Pairable> std::ops::DerefMut for Current<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// NewType wrapper to ensure Proposed key-value is used for the Context
#[derive(Debug, Default, Clone)]
pub struct Proposed<P: Pairable>(pub P);

impl<P: Pairable> Deref for Proposed<P> {
    type Target = P;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<P: Pairable> From<P> for Proposed<P> {
    fn from(p: P) -> Self {
        Proposed(p)
    }
}

impl<P: Pairable> std::ops::DerefMut for Proposed<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<C: Pairable, P: Pairable> Context<C, P> {
    /// Create a new [Context] struct with the given [Current] and [Proposed] key-value stores,
    /// which are bound by both [Pairable].
    pub(crate) fn new(current: Either<C, P>, proposed: P) -> Self {
        Context {
            current,
            proposed,
            check_count: 0,
            rstack: Default::default(),
            pstack: Default::default(),
            domain: "/".to_string(),
        }
    }

    /// Check the signature of the given key str
    pub fn check_signature(&mut self, key: &str, msg: &str) -> bool {
        // lookup the keypair for this key
        let pubkey = {
            match &self.current.get(key) {
                Some(Value::Bin { hint: _, data }) => match Multikey::try_from(data.as_ref()) {
                    Ok(mk) => mk,
                    Err(e) => {
                        warn!("check_signature: error decoding multikey: {e}");
                        return self.check_fail(&e.to_string());
                    }
                },
                Some(_) => {
                    warn!("check_signature: unexpected value type associated with {key}");
                    return self
                        .check_fail(&format!("unexpected value type associated with {key}"));
                }
                None => {
                    warn!("check_signature: no multikey associated with {key}");
                    return self.check_fail(&format!("no multikey associated with {key}"));
                }
            }
        };

        // look up the message that was signed
        let message = {
            match self.proposed.get(msg) {
                Some(Value::Bin { hint: _, data }) => data,
                Some(Value::Str { hint: _, data }) => data.as_bytes().to_vec(),
                Some(_) => {
                    warn!("check_signature: unexpected value type associated with {msg}");
                    return self
                        .check_fail(&format!("unexpected value type associated with {msg}"));
                }
                None => {
                    warn!("check_signature: no message associated with {msg}");
                    return self.check_fail(&format!("no message associated with {msg}"));
                }
            }
        };

        // make sure we have at least one parameter on the stack
        if self.pstack.len() < 1 {
            return self.check_fail(&format!(
                "not enough parameters ({}) on the stack for check_signature ({key}, {msg})",
                self.pstack.len()
            ));
        }

        // peek at the top item and verify that it is a Multisig
        let sig = {
            match self.pstack.top() {
                Some(Value::Bin { hint: _, data }) => match Multisig::try_from(data.as_ref()) {
                    Ok(sig) => sig,
                    Err(e) => return self.check_fail(&e.to_string()),
                },
                _ => return self.check_fail("no multisig on stack"),
            }
        };

        // get the verify view
        let verify_view = match pubkey.verify_view() {
            Ok(v) => v,
            Err(e) => return self.check_fail(&e.to_string()),
        };

        // verify the signature
        match verify_view.verify(&sig, Some(message.as_ref())) {
            Ok(_) => {
                // the signature verification worked so pop the signature arg off
                // of the stack before continuing
                self.pstack.pop();
                self.succeed()
            }
            Err(e) => {
                warn!("check_signature({key}, {msg}) -> false");
                self.check_fail(&e.to_string())
            }
        }
    }

    /// Check the preimage of the given key
    pub fn check_preimage(&mut self, key: String) -> bool {
        // look up the hash and try to decode it
        let hash = {
            match self.current.get(&key) {
                Some(Value::Bin { hint: _, data }) => match Multihash::try_from(data.as_ref()) {
                    Ok(hash) => hash,
                    Err(e) => return self.check_fail(&e.to_string()),
                },
                Some(_) => {
                    return self
                        .check_fail(&format!("unexpected value type associated with {}", key))
                }
                None => return self.check_fail(&format!("kvp missing key: {key}")),
            }
        };

        // make sure we have at least one parameter on the stack
        if self.pstack.len() < 1 {
            warn!(
                "not enough parameters on the stack for check_preimage: {}",
                self.pstack.len()
            );
            return self.check_fail(&format!(
                "not enough parameters on the stack for check_preimage: {}",
                self.pstack.len()
            ));
        }

        // get the preimage data from the stack
        let preimage = {
            match self.pstack.top() {
                Some(Value::Bin { hint: _, data }) => {
                    match mh::Builder::new_from_bytes(hash.codec(), data) {
                        Ok(builder) => match builder.try_build() {
                            Ok(hash) => hash,
                            Err(e) => return self.check_fail(&e.to_string()),
                        },
                        Err(e) => return self.check_fail(&e.to_string()),
                    }
                }
                Some(Value::Str { hint: _, data }) => {
                    match mh::Builder::new_from_bytes(hash.codec(), data.as_bytes()) {
                        Ok(builder) => match builder.try_build() {
                            Ok(hash) => hash,
                            Err(e) => return self.check_fail(&e.to_string()),
                        },
                        Err(e) => return self.check_fail(&e.to_string()),
                    }
                }
                _ => return self.check_fail("no multihash data on stack"),
            }
        };

        // check that the hashes match
        if hash == preimage {
            // the hash check passed so pop the argument from the stack
            let _ = self.pstack.pop();
            self.succeed()
        } else {
            // the hashes don't match
            self.check_fail("preimage doesn't match")
        }
    }

    /// Verifies the top of the stack matches the value associated with the key
    pub fn check_eq(&mut self, key: &str) -> bool {
        // look up the value associated with the key
        let value = {
            match self.current.get(key) {
                Some(Value::Bin { hint: _, data }) => data,
                Some(Value::Str { hint: _, data }) => data.as_bytes().to_vec(),
                _ => {
                    warn!("check_eq: no value associated with {key}");
                    return self.check_fail(&format!("kvp missing key: {key}"));
                }
            }
        };

        // make sure we have at least one parameter on the stack
        if self.pstack.is_empty() {
            warn!(
                "not enough parameters on the stack for check_eq: {}",
                self.pstack.len()
            );
            return self.check_fail(&format!(
                "not enough parameters on the stack for check_eq: {}",
                self.pstack.len()
            ));
        }

        let stack_value = {
            match self.pstack.top() {
                Some(Value::Bin { hint: _, data }) => data,
                Some(Value::Str { hint: _, data }) => data.as_bytes().to_vec(),
                _ => {
                    warn!("check_eq: no value on the stack");
                    return self.check_fail("no value on the stack");
                }
            }
        };

        // check if equal
        if value == stack_value {
            // the values match so pop the argument from the stack
            let _ = self.pstack.pop();
            self.succeed()
        } else {
            // the values don't match
            self.check_fail("values don't match")
        }
    }

    /// Increment the check counter and to push a FAILURE marker on the return stack
    pub fn check_fail(&mut self, err: &str) -> bool {
        // update the context check_count
        self.check_count += 1;
        // fail
        self.fail(err)
    }

    /// Increment the check counter and to push a FAILURE marker on the return stack
    pub fn fail(&mut self, err: &str) -> bool {
        // push the FAILURE onto the return stack
        self.rstack.push(Value::Failure(err.to_string()));
        false
    }

    /// Push a SUCCESS marker onto the return stack
    pub fn succeed(&mut self) -> bool {
        // push the SUCCESS marker with the check count
        self.rstack.push(self.check_count.into());
        // return that we succeeded
        true
    }

    /// Push the value associated with the key onto the parameter stack
    pub fn push(&mut self, key: &str) -> bool {
        // try to look up the key-value pair by key and push the result onto the stack
        match self.current.get(key) {
            Some(v) => {
                self.pstack.push(v.clone());
                true
            }
            None => {
                warn!("push: no value associated with {key}");
                self.fail(&format!("kvp missing key: {key}"))
            }
        }
    }

    /// Calculate the full key given the context
    pub fn branch(&self, key: &str) -> String {
        let s = format!("{}{}", self.domain, key);
        debug!("branch({}) -> {}", key, s.as_str());
        s
    }
}
