use crate::bindings::comrade::api::pairs::Value;
use crate::bindings::comrade::api::pairs::{Binary, Str};
use crate::error::ApiError;
use crate::parser::{Expression, Function, Key, parse};
use multihash::{Multihash, mh};
use multikey::{Multikey, Views as _};
use multisig::Multisig;
use multiutil::prelude::*;

use crate::bindings::comrade::api::pairs::{self, Either};
use crate::bindings::comrade::api::utils::log;

#[derive(Default, Clone, Debug)]
struct Stk {
    pub stack: Vec<Value>,
}

impl Stk {
    /// push a value onto the stack
    fn push(&mut self, value: Value) {
        self.stack.push(value);
    }

    /// remove the last top value from the stack
    fn pop(&mut self) -> Option<Value> {
        self.stack.pop()
    }

    /// get a reference to the top value on the stack
    fn top(&self) -> Option<Value> {
        self.stack.last().cloned()
    }

    /// peek at the item at the given index
    fn peek(&self, idx: usize) -> Option<Value> {
        if idx >= self.stack.len() {
            return None;
        }
        Some(self.stack[self.stack.len() - 1 - idx].clone())
    }

    /// return the number of values on the stack
    fn len(&self) -> usize {
        self.stack.len()
    }

    /// return if the stack is empty
    fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }
}

impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Value::Success(n as u32)
    }
}

pub(crate) struct Context {
    /// The number of checks that have been performed
    pub(crate) check_count: usize,

    /// The Return stack
    pub(crate) rstack: Stk,

    /// The Parameters stack
    pub(crate) pstack: Stk,

    /// Optional domain segment of the /branch/leaf/ key-path. Defaults to "/".
    pub domain: String,
}

impl Context {
    /// Create a new [Context] struct with the given [Current] and [Proposed] key-value stores,
    /// which are bound by both [Pairable].
    pub fn new() -> Self {
        Context {
            check_count: 0,
            rstack: Default::default(),
            pstack: Default::default(),
            domain: "/".to_string(),
        }
    }

    /// Parse a script from a string and evaluate it, returning the result
    pub fn run(&mut self, script: &str) -> Result<bool, ApiError> {
        log(&format!("Running script: {script}"));
        let expressions = parse(script)?;

        // Execute each expression in sequence
        for expr in &expressions {
            if self.eval(expr) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Evaluate a single expression
    fn eval(&mut self, expr: &Expression) -> bool {
        match expr {
            Expression::Function(func) => self.eval_function(func),
            Expression::And(left, right) => self.eval(left) && self.eval(right),
            Expression::Or(left, right) => self.eval(left) || self.eval(right),
            Expression::Group(inner) => self.eval(inner),
        }
    }

    /// Evaluate a function call
    fn eval_function(&mut self, function: &Function) -> bool {
        match function {
            Function::CheckEq(key) => match key {
                Key::Branch(key) => self.check_eq(&self.branch(key)),
                Key::String(key) => self.check_eq(key),
            },
            Function::CheckSignature(key, msg) => match key {
                Key::Branch(key) => self.check_signature(&self.branch(key), msg),
                Key::String(key) => self.check_signature(key, msg),
            },
            Function::CheckPreimage(preimage) => match preimage {
                Key::Branch(key) => self.check_preimage(&self.branch(key)),
                Key::String(key) => self.check_preimage(key),
            },
            Function::Push(path) => match path {
                Key::Branch(key) => self.push(&self.branch(key)),
                Key::String(key) => self.push(key),
            },
        }
    }

    /// Check the signature of the given key str
    pub fn check_signature(&mut self, key: &str, msg: &str) -> bool {
        let current = pairs::get(Either::Current, key);
        // lookup the keypair for this key
        let pubkey = {
            match &current {
                Some(Value::Bin(Binary { hint: _, data })) => {
                    match Multikey::try_from(data.as_ref()) {
                        Ok(mk) => mk,
                        Err(e) => {
                            log("check_signature: error decoding multikey: {e}");
                            return self.check_fail(&e.to_string());
                        }
                    }
                }
                Some(_) => {
                    log("check_signature: unexpected value type associated with {key}");
                    return self
                        .check_fail(&format!("unexpected value type associated with {key}"));
                }
                None => {
                    log("check_signature: no multikey associated with {key}");
                    return self.check_fail(&format!("no multikey associated with {key}"));
                }
            }
        };

        // look up the message that was signed
        let message = {
            let proposed = pairs::get(Either::Proposed, msg);
            match proposed {
                Some(Value::Bin(Binary { hint: _, data })) => data,
                Some(Value::Str(Str { hint: _, data })) => data.as_bytes().to_vec(),
                Some(_) => {
                    log("check_signature: unexpected value type associated with {msg}");
                    return self
                        .check_fail(&format!("unexpected value type associated with {msg}"));
                }
                None => {
                    log("check_signature: no message associated with {msg}");
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
                Some(Value::Bin(Binary { hint: _, data })) => {
                    match Multisig::try_from(data.as_ref()) {
                        Ok(sig) => sig,
                        Err(e) => return self.check_fail(&e.to_string()),
                    }
                }
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
                log("check_signature({key}, {msg}) -> false");
                self.check_fail(&e.to_string())
            }
        }
    }

    /// Check the preimage of the given key
    pub fn check_preimage(&mut self, key: &str) -> bool {
        // look up the hash and try to decode it
        let hash = {
            let current = pairs::get(Either::Current, key);
            match current {
                Some(Value::Bin(Binary { hint: _, data })) => {
                    match Multihash::try_from(data.as_ref()) {
                        Ok(hash) => hash,
                        Err(e) => return self.check_fail(&e.to_string()),
                    }
                }
                Some(_) => {
                    return self
                        .check_fail(&format!("unexpected value type associated with {}", key));
                }
                None => return self.check_fail(&format!("kvp missing key: {key}")),
            }
        };

        // make sure we have at least one parameter on the stack
        if self.pstack.is_empty() {
            log(&format!(
                "not enough parameters on the stack for check_preimage: {}",
                self.pstack.len(),
            ));
            return self.check_fail(&format!(
                "not enough parameters on the stack for check_preimage: {}",
                self.pstack.len()
            ));
        }

        // get the preimage data from the stack
        let preimage = {
            match self.pstack.top() {
                Some(Value::Bin(Binary { data, hint: _ })) => {
                    match mh::Builder::new_from_bytes(hash.codec(), data) {
                        Ok(builder) => match builder.try_build() {
                            Ok(hash) => hash,
                            Err(e) => return self.check_fail(&e.to_string()),
                        },
                        Err(e) => return self.check_fail(&e.to_string()),
                    }
                }
                Some(Value::Str(Str { hint: _, data })) => {
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
            match pairs::get(Either::Current, key) {
                Some(Value::Bin(Binary { hint: _, data })) => data,
                Some(Value::Str(Str { hint: _, data })) => data.as_bytes().to_vec(),
                _ => {
                    log("check_eq: no value associated with {key}");
                    return self.check_fail(&format!("kvp missing key: {key}"));
                }
            }
        };

        // make sure we have at least one parameter on the stack
        if self.pstack.is_empty() {
            log(&format!(
                "not enough parameters on the stack for check_eq: {}",
                self.pstack.len(),
            ));
            return self.check_fail(&format!(
                "not enough parameters on the stack for check_eq: {}",
                self.pstack.len()
            ));
        }

        let stack_value = {
            match self.pstack.top() {
                Some(Value::Bin(Binary { hint: _, data })) => data,
                Some(Value::Str(Str { hint: _, data })) => data.as_bytes().to_vec(),
                _ => {
                    log("check_eq: no value on the stack");
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
        log(&format!("push(\"{key}\")"));
        // try to look up the key-value pair by key and push the result onto the stack
        match pairs::get(Either::Current, key) {
            Some(v) => {
                self.pstack.push(v.clone());
                true
            }
            None => {
                log(&format!("push: no value associated with {key}"));
                self.fail(&format!("kvp missing key: {key}"))
            }
        }
    }

    /// Calculate the full key given the context
    /// Concatenates the branch key-path with the provided key-path to create a key-path argument for other functions.
    /// When used in lock scripts, the branch key-path is the key-path the lock script is associated with.
    /// When used in unlock scripts, the branch key-path is always /. This function fails if used in a lock script associated with a leaf
    pub fn branch(&self, key: &str) -> String {
        let s = format!("{}{}", self.domain, key);
        log(&format!("branch({}) -> {}", key, s.as_str()));
        s
    }
}
