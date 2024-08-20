mod storage;

use multikey::{Multikey, Views as _};
use multisig::Multisig;
use rhai::{Engine, Scope};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
pub use storage::pairs::Pairs;
pub use storage::stack::Stack;
pub use storage::stack::Stk;
use storage::value::Value;
use tracing::info;

/// FAILURE
pub const FAILURE: bool = false;

/// The entry point for the Comrade API
pub struct Comrade {
    context: Context,
    engine: Engine,
    lock: Option<String>,
    unlock: Option<String>,
}

impl Default for Comrade {
    fn default() -> Self {
        let mut engine = Engine::new();
        let context = Context::new();

        let check_signature = {
            let context = Arc::new(Mutex::new(context.clone()));
            move |key: String| {
                let mut context = context.lock().unwrap();
                context.check_signature(key)
            }
        };

        // register push function
        let push = {
            let context = Arc::new(Mutex::new(context.clone()));
            move |key: String| {
                let mut context = context.lock().unwrap();
                context.push(&key)
            }
        };

        engine.register_fn("check_signature", check_signature);
        engine.register_fn("push", push);

        Comrade {
            context,
            engine,
            lock: None,
            unlock: None,
        }
    }
}

impl Comrade {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads an unlock script into Comrade
    pub fn load_unlock(&mut self, script: String) -> &mut Self {
        self.unlock = Some(script);
        self
    }

    /// Loads a lock script into Comrade
    pub fn load_lock(&mut self, script: String) -> &mut Self {
        self.lock = Some(script);
        self
    }

    /// Evaluate the Rhai script function with the given name
    pub fn run(&mut self, func: &str) -> Result<bool, String> {
        // get unlock script, if None return error
        let unlock = self.unlock.as_ref().ok_or("unlock script not loaded")?;

        let ast = self.engine.compile(unlock).map_err(|e| e.to_string())?;

        let mut scope = Scope::new();

        let result = self
            .engine
            .call_fn::<bool>(&mut scope, &ast, func, ())
            .map_err(|e| e.to_string())?;

        Ok(result)
    }
}

#[derive(Clone, Default)]
pub struct ContextPairs {
    pairs: HashMap<String, Value>,
}

impl Pairs for ContextPairs {
    fn get(&self, key: String) -> Option<Value> {
        self.pairs.get(&key).cloned()
    }

    fn put(&mut self, key: String, value: &Value) -> Option<Value> {
        self.pairs.insert(key, value.clone())
    }
}

#[derive(Clone, Default)]
struct Context {
    /// The key-value store for the Context keypairs
    pub pairs: ContextPairs,

    /// The number of times a check_* operation has been executed
    pub check_count: usize,

    /// The Return stack
    pub rstack: Stk,

    /// The Parameters stack
    pub pstack: Stk,
}

impl Context {
    pub fn new() -> Self {
        Context::default()
    }

    /// Check the signature of the given key str
    pub fn check_signature(&mut self, key: String) -> bool {
        // lookup the keypair for this key
        let pubkey = {
            match self.pairs.get(key.clone()) {
                Some(Value::Bin { hint: _, data }) => match Multikey::try_from(data.as_ref()) {
                    Ok(mk) => mk,
                    Err(e) => return self.check_fail(&e.to_string()),
                },
                Some(_) => {
                    return self.check_fail(&format!("unexpected value type associated with {key}"))
                }
                None => return self.check_fail(&format!("no multikey associated with {key}")),
            }
        };

        // make sure we have at least two parameters on the stack
        if self.pstack.len() < 2 {
            return self.check_fail(&format!(
                "not enough parameters on the stack for check_signature ({})",
                self.pstack.len()
            ));
        }

        // peek at the top item and verify that it is a Multisig
        let sig = {
            info!("sig: stack::top()");
            match self.pstack.top() {
                Some(Value::Bin { hint: _, data }) => match Multisig::try_from(data.as_ref()) {
                    Ok(sig) => sig,
                    Err(e) => return self.check_fail(&e.to_string()),
                },
                _ => return self.check_fail("no multisig on stack"),
            }
        };

        // peek at the next item down and get the message
        let msg = {
            info!("msg: stack::peek(1)");
            match self.pstack.peek(1) {
                Some(Value::Bin { hint: _, data }) => data,
                Some(Value::Str { hint: _, data }) => data.as_bytes().to_vec(),
                _ => return self.check_fail("no message on stack"),
            }
        };

        // get the verify view
        let verify_view = match pubkey.verify_view() {
            Ok(v) => v,
            Err(e) => return self.check_fail(&e.to_string()),
        };

        // verify the signature
        match verify_view.verify(&sig, Some(msg.as_ref())) {
            Ok(_) => {
                info!("verify: OK");
                // the signature verification worked so pop the two arguments off
                // of the stack before continuing
                self.pstack.pop();
                self.pstack.pop();
                self.succeed()
            }
            Err(e) => {
                info!("verify: Err({})", e.to_string());
                self.check_fail(&e.to_string())
            }
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
        match self.pairs.get(key.to_owned()) {
            Some(v) => {
                info!("push: {} -> {:?}", key, v);
                self.pstack.push(v.clone()); // pushes Value::Bin(Vec<u8>)
                true
            }
            None => self.fail(&format!("kvp missing key: {key}")),
        }
    }
}

#[cfg(test)]
mod tests {
    //use super::*;

    #[test]
    fn it_works() {}
}
