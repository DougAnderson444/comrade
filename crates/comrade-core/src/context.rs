use crate::storage::pairs::Pairs;
use crate::storage::stack::Stack as _;
use crate::storage::{stack::Stk, value::Value};
use multihash::{mh, Multihash};
use multikey::{Multikey, Views as _};
use multisig::Multisig;
use multiutil::CodecInfo;
use std::collections::HashMap;
use tracing::{info, warn};

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

#[derive(Clone, Debug)]
pub struct Context {
    /// The current key-value store for the Context keypairs
    pub current: ContextPairs,

    /// The proposed key-value store for the Context keypairs
    pub proposed: ContextPairs,

    /// The number of times a check_* operation has been executed
    pub check_count: usize,

    /// The Return stack
    pub rstack: Stk,

    /// The Parameters stack
    pub(crate) pstack: Stk,

    /// Optional domain segment of the /branch/leaf/ key-path. Defaults to "/".
    pub domain: String,
}

impl Default for Context {
    fn default() -> Self {
        Context {
            current: Default::default(),
            proposed: Default::default(),
            check_count: 0,
            rstack: Default::default(),
            pstack: Default::default(),
            domain: "/".to_string(),
        }
    }
}

impl Context {
    pub fn new() -> Self {
        Context::default()
    }

    /// Sets the current pairs to the given [ContextPairs] value
    pub fn with_current(&mut self, current: ContextPairs) -> &mut Self {
        self.current = current;
        self
    }

    /// Sets the proposed pairs to the given [ContextPairs] value
    pub fn with_proposed(&mut self, proposed: ContextPairs) -> &mut Self {
        self.proposed = proposed;
        self
    }

    /// Sets the domain to the given string Value
    pub fn with_domain(&mut self, domain: String) -> &mut Self {
        self.domain = domain;
        self
    }

    /// Builds the [Context] struct
    pub fn build(self) -> Self {
        self
    }

    /// Check the signature of the given key str
    pub fn check_signature(&mut self, key: &str, msg: &str) -> bool {
        info!("check_signature: {} {}", key, msg);
        // lookup the keypair for this key
        let pubkey = {
            match self.current.get(key) {
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

    /// Calculate the full key given the context
    pub fn branch(&self, key: &str) -> String {
        let s = format!("{}{}", self.domain, key);
        info!("branch({}) -> {}", key, s.as_str());
        s
    }
}

#[cfg(test)]
mod tests {
    use crate::{Comrade, Kvp};

    use super::*;

    use multicodec::Codec;
    use multikey::mk;
    use std::error::Error;
    use test_log::test;
    use tracing::debug;

    // Make a random pubkey and print out a pubkey in hex, and the multisignature of the given arg
    fn make_pubkey(msg: impl AsRef<[u8]>) -> (String, String) {
        let mut rng = rand::rngs::OsRng;
        let mk = mk::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let signmk = mk.sign_view().unwrap();
        let signature = signmk.sign(msg.as_ref(), false, None).unwrap();

        let s: Vec<u8> = signature.into();
        let sig = hex::encode(s);
        let conv = mk.conv_view().unwrap();
        let pk = conv.to_public_key().unwrap();
        let pubkey = hex::encode(Into::<Vec<u8>>::into(pk.clone()));
        (pubkey, sig)
    }

    #[test]
    fn test_lib_pubkey() -> Result<(), Box<dyn Error>> {
        let mut comrade = Comrade::default();

        // set engine on_print
        comrade.engine.lock().unwrap().on_print(|msg| {
            debug!("[RHAI]: {}", msg);
        });

        let entry_key = "/entry/";
        {
            // unlock
            let entry_data = b"for great justice, move every zig!";

            let proof_key = "/entry/proof";

            // make and print the pubkey and signature
            //let (pubkey, sig) = make_pubkey(entry_data);
            //debug!("pubkey: {}", pubkey);
            //debug!("signature: {}", sig);

            let proof_data = hex::decode("b92483a6c00600010040eda2eceac1ef60c4d54efc7b50d86b198ba12358749e5069dbe0a5ca6c3e7e78912a21c67a18a4a594f904e7df16f798d929d7a8cee57baca89b4ed0dfd1c801").unwrap();

            comrade.put(Vec::from([
                Kvp {
                    key: entry_key.to_owned(),
                    value: entry_data.as_ref().into(),
                },
                Kvp {
                    key: proof_key.to_owned(),
                    value: proof_data.clone().into(),
                },
            ]))?;

            let unlock_script = format!(
                r#"
                // print to console
                print("RUNNING for great justice");

                // push the serialized Entry as the message
                push("{entry_key}"); 

                // push the proof data
                push("{proof_key}");
            "#
            );

            // load and run `for_great_justice` function. Check stack for correctness.
            let res = comrade.load(unlock_script).run()?;

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
        } // end unlock block

        {
            // lock block
            let pubkey = "/pubkey";
            let pub_key = hex::decode("ba24ed010874657374206b657901012069c9e8cd599542b5ff7e4cdc4265847feb9785330557edd6a9edae741ed4c3b2").unwrap();
            comrade.put(vec![Kvp {
                key: pubkey.to_owned(),
                value: pub_key.into(),
            }])?;

            // lock is move_every_zig
            let lock_script = format!(
                r#"
                // print to console
                print("MOVE, Zig!");

                // then check a possible threshold sig...
                check_signature("/tpubkey", "{entry_key}") ||

                // then check a possible pubkey sig...
                check_signature("{pubkey}", "{entry_key}") ||
                
                // then the pre-image proof...
                check_preimage("/hash")

            "#
            );

            let res = comrade.load(lock_script).run()?;

            assert!(res);
            assert_eq!(comrade.context.lock().unwrap().rstack.len(), 2);
            assert_eq!(
                comrade.context.lock().unwrap().rstack.top().unwrap(),
                Value::Success(1)
            );
        } // end lock block

        Ok(())
    }

    #[test]
    fn test_preimage_hash() {
        let mut comrade = Comrade::default();

        // set engine on_print
        comrade.engine.lock().unwrap().on_print(|msg| {
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

        let unlock_script = format!(
            r#"
                // print to console
                print("RUNNING preimage");

                // push the serialized Entry as the message
                push("{entry_key}"); 

                // push the proof data
                push("{proof_key}");
            "#
        );

        // load and run `preimage` function. Check stack for correctness.
        let res = comrade.load(unlock_script).run().unwrap();

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

        // lock is move_every_zig
        let lock_script = format!(
            r#"
                // print to console
                print("RUN LOCK SCRIPT!");

                // then check a possible threshold sig...
                check_signature("/tpubkey", "{entry_key}") ||

                // then check a possible pubkey sig...
                check_signature("/pubkey", "{entry_key}") ||
                
                // then the pre-image proof...
                check_preimage("{hash_key}")
            "#
        );

        let res = comrade.load(lock_script).run().unwrap();

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
