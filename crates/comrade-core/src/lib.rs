mod storage;

use multihash::{mh, Multihash};
use multikey::{Multikey, Views as _};
use multisig::Multisig;
use multiutil::CodecInfo;
use rhai::{Engine, Scope};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
pub use storage::pairs::Pairs;
pub use storage::stack::Stack;
pub use storage::stack::Stk;
pub use storage::value::Value;
use tracing::{debug, info, trace, warn};

/// FAILURE
pub const FAILURE: bool = false;

/// The entry point for the Comrade API
pub struct Comrade {
    pub(crate) context: Arc<Mutex<Context>>,
    engine: Engine,
    script: Option<String>,
}

impl Default for Comrade {
    fn default() -> Self {
        let mut engine = Engine::new();
        let context = Arc::new(Mutex::new(Context::new()));

        let check_signature = {
            let context = Arc::clone(&context);
            move |key: &str, msg: &str| {
                let mut context = context.lock().unwrap();
                context.check_signature(key, msg)
            }
        };

        // register push function
        let push = {
            let context = Arc::clone(&context);
            move |key: String| {
                let mut context = context.lock().unwrap();
                context.push(&key)
            }
        };

        let check_preimage = {
            let context = Arc::clone(&context);
            move |key: String| {
                let mut context = context.lock().unwrap();
                context.check_preimage(key)
            }
        };

        engine.register_fn("check_signature", check_signature);
        engine.register_fn("push", push);
        engine.register_fn("check_preimage", check_preimage);

        Comrade {
            context,
            engine,
            script: None,
        }
    }
}

pub struct Kvp {
    pub key: String,
    pub value: Value,
}

impl Comrade {
    pub fn new() -> Self {
        Self::default()
    }

    /// Put key-value pairs into the Comrade context
    pub fn put(&mut self, kvps: Vec<Kvp>) -> Result<(), String> {
        let mut context = self.context.lock().map_err(|e| e.to_string())?;

        // proposed gets set to the current by taking the value from memory
        context.proposed = std::mem::take(&mut context.current);

        kvps.into_iter().for_each(|kvp| {
            context.current.put(kvp.key, &kvp.value);
        });

        Ok(())
    }

    /// Returns the return Stack
    pub fn returns(&self) -> Stk {
        self.context.lock().unwrap().rstack.clone()
    }

    /// Loads a lock script into Comrade
    pub fn load(&mut self, script: String) -> &mut Self {
        self.script = Some(script);
        self
    }

    /// Evaluate the Rhai script function with the given name
    pub fn run(&mut self, func: &str) -> Result<bool, String> {
        // get unlock script, if None return error
        let script = self.script.as_ref().ok_or("no script loaded")?;

        let ast = self.engine.compile(script).map_err(|e| e.to_string())?;

        let mut scope = Scope::new();

        let result = self
            .engine
            .call_fn::<bool>(&mut scope, &ast, func, ())
            .map_err(|e| e.to_string())?;

        Ok(result)
    }
}

#[derive(Clone, Default, Debug)]
pub struct ContextPairs {
    pairs: HashMap<String, Value>,
}

impl Pairs for ContextPairs {
    fn get(&self, key: &str) -> Option<Value> {
        self.pairs.get(key).cloned()
    }

    fn put(&mut self, key: String, value: &Value) -> Option<Value> {
        self.pairs.insert(key, value.clone())
    }
}

#[derive(Clone, Default)]
struct Context {
    /// The current key-value store for the Context keypairs
    pub current: ContextPairs,

    /// The proposed key-value store for the Context keypairs
    pub proposed: ContextPairs,

    /// The number of times a check_* operation has been executed
    pub check_count: usize,

    /// The Return stack
    pub rstack: Stk,

    /// The Parameters stack
    pstack: Stk,
}

impl Context {
    pub fn new() -> Self {
        Context::default()
    }

    /// Check the signature of the given key str
    pub fn check_signature(&mut self, key: &str, msg: &str) -> bool {
        info!("check_signature: {} {}", key, msg);
        // lookup the keypair for this key
        let pubkey = {
            match self.current.get(key) {
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

        // look up the message that was signed
        info!("check_signature: loading from proposed {msg}");
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
                info!("check_signature({key}, {msg}) -> true");
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

    /// Check the preimage of the given key #[derive(Debug)]
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
                self.pstack.push(v.clone()); // pushes Value::Bin(Vec<u8>)
                true
            }
            None => {
                warn!("push: no value associated with {key}");
                self.fail(&format!("kvp missing key: {key}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error;
    use test_log::test;
    use tracing::{debug, info};

    #[test]
    fn test_lib_pubkey() -> Result<(), Box<dyn Error>> {
        let mut comrade = Comrade::new();

        // set engine on_print
        comrade.engine.on_print(|msg| {
            debug!("[RHAI]: {}", msg);
        });

        let entry_key = "/entry/";
        let entry_data = b"for great justice, move every zig!";

        let proof_key = "/entry/proof";
        let proof_data = hex::decode("3983a6c0060001004076fee92ca796162b5e37a84b4150da685d636491b43c1e2a1fab392a7337553502588a609075b56c46b5c033b260d8d314b584e396fc2221c55f54843679ee08").unwrap();

        let _ = comrade.put(Vec::from([
            Kvp {
                key: entry_key.to_owned(),
                value: entry_data.as_ref().into(),
            },
            Kvp {
                key: proof_key.to_owned(),
                value: proof_data.clone().into(),
            },
        ]));

        let for_great_justice = "for_great_justice";

        let unlock_script = format!(
            r#"
            fn {for_great_justice}() {{

                // print to console
                print("RUNNING for great justice");

                // push the serialized Entry as the message
                push("{entry_key}"); 

                // push the proof data
                push("{proof_key}");
            }}"#
        );

        // load and run `for_great_justice` function. Check stack for correctness.
        let res = comrade.load(unlock_script).run(for_great_justice)?;

        assert!(res);
        assert_eq!(comrade.context.lock().unwrap().pstack.len(), 2);
        assert_eq!(
            comrade.context.lock().unwrap().pstack.top().unwrap(),
            Value::Bin {
                hint: "".to_string(),
                data: proof_data
            }
        );
        assert_eq!(
            comrade.context.lock().unwrap().pstack.peek(1).unwrap(),
            Value::Bin {
                hint: "".to_string(),
                data: entry_data.to_vec()
            }
        );

        let pubkey = "/pubkey";
        let pub_key = hex::decode("3aed010874657374206b657901012084d515ef051e07d597f3c14ac09e5a9d5012c659c196d96db5c6b98ea552f603").unwrap();
        let _ = comrade.put(vec![Kvp {
            key: pubkey.to_owned(),
            value: pub_key.into(),
        }]);

        let move_every_zig = "move_every_zig";

        // lock is move_every_zig
        let lock_script = format!(
            r#"
            fn {move_every_zig}() {{

                // print to console
                print("MOVE, Zig!");

                // then check a possible threshold sig...
                check_signature("/tpubkey", "{entry_key}") ||

                // then check a possible pubkey sig...
                check_signature("{pubkey}", "{entry_key}") ||
                
                // then the pre-image proof...
                check_preimage("/hash")

            }}"#
        );

        let res = comrade.load(lock_script).run(move_every_zig)?;

        assert!(res);
        assert_eq!(comrade.context.lock().unwrap().rstack.len(), 2);
        assert_eq!(
            comrade.context.lock().unwrap().rstack.top().unwrap(),
            Value::Success(1)
        );

        Ok(())
    }

    #[test]
    fn test_preimage_hash() {
        let mut comrade = Comrade::new();

        // set engine on_print
        comrade.engine.on_print(|msg| {
            debug!("[RHAI]: {}", msg);
        });

        let entry_key = "/entry/";
        let entry_data = b"blah";

        let proof_key = "/entry/proof";
        let proof_data = b"for great justice, move every zig!";

        let _ = comrade.put(vec![
            Kvp {
                key: entry_key.to_owned(),
                value: entry_data.as_ref().into(),
            },
            Kvp {
                key: proof_key.to_owned(),
                value: proof_data.as_ref().into(),
            },
        ]);

        let for_great_justice = "for_great_justice";

        let unlock_script = format!(
            r#"
            fn {for_great_justice}() {{

                // print to console
                print("RUNNING preimage");

                // push the serialized Entry as the message
                push("{entry_key}"); 

                // push the proof data
                push("{proof_key}");
            }}"#
        );

        // load and run `preimage` function. Check stack for correctness.
        let res = comrade.load(unlock_script).run(for_great_justice).unwrap();

        assert!(res);
        assert_eq!(comrade.context.lock().unwrap().pstack.len(), 2);
        assert_eq!(
            comrade.context.lock().unwrap().pstack.top().unwrap(),
            Value::Bin {
                hint: "".to_string(),
                data: proof_data.to_vec()
            }
        );
        assert_eq!(
            comrade.context.lock().unwrap().pstack.peek(1).unwrap(),
            Value::Bin {
                hint: "".to_string(),
                data: entry_data.to_vec()
            }
        );

        let hash_key = "/hash";
        let hash_data =
            hex::decode("16206b761d3b2e7675e088e337a82207b55711d3957efdb877a3d261b0ca2c38e201")
                .unwrap();

        //let _ = comrade.put(hash_key.to_owned(), &hash_data.into());
        let _ = comrade.put(vec![Kvp {
            key: hash_key.to_owned(),
            value: hash_data.into(),
        }]);

        let move_every_zig = "move_every_zig";

        // lock is move_every_zig
        let lock_script = format!(
            r#"
            fn {move_every_zig}() {{

                // print to console
                print("HASH, Zig!");

                // then check a possible threshold sig...
                check_signature("/tpubkey", "{entry_key}") ||

                // then check a possible pubkey sig...
                check_signature("/pubkey", "{entry_key}") ||
                
                // then the pre-image proof...
                check_preimage("{hash_key}")

            }}"#
        );

        let res = comrade.load(lock_script).run(move_every_zig).unwrap();

        assert!(res);
        // NOTE: the check_preimage("/hash") call only pops the top preimage off of the stack so
        // the message is still on there giving the len of 2
        assert_eq!(comrade.context.lock().unwrap().rstack.len(), 3);
        // NOTE: the check count is 2 because the check_signature("/tpubkey") and
        // check_signature("/pubkey") failed before the check_preimage("/hash") succeeded
        assert_eq!(
            comrade.context.lock().unwrap().rstack.top().unwrap(),
            Value::Success(2)
        );
    }
}
