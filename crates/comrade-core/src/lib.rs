mod context;
mod error;
mod storage;

use context::Context;

use context::ContextPairs;
use rhai::{Engine, Scope};
use std::sync::{Arc, Mutex};
pub use storage::pairs::Pairs;
pub use storage::stack::Stack;
pub use storage::stack::Stk;
pub use storage::value::Value;
use tracing::debug;

/// FAILURE
pub const FAILURE: bool = false;

/// Comrade Builder, which allows users to specify the key-path for the branch() function
pub struct ComradeBuilder {
    context: Arc<Mutex<Context>>,
    // Temp storage for current pairs until unlock script is run
    current: ContextPairs,
    unlock_script: String,
    unlock_entries: Vec<Kvp>,
}

impl ComradeBuilder {
    /// Create a new Comrade instance builder with the given unlock script and default context
    pub fn new(unlock: &str) -> Self {
        Self {
            context: Arc::new(Mutex::new(Context::default())),
            current: Default::default(),
            unlock_script: unlock.to_string(),
            unlock_entries: Default::default(),
        }
    }

    /// Sets the key-path value for use in branch() functions.
    ///
    /// # Example
    ///
    /// ```
    /// use comrade_core::ComradeBuilder;
    /// let comrade = ComradeBuilder::new("for_great_justice(){}").with_domain("/forks/child/").run();
    /// // full path is now "/forks/child/your-key-path"
    /// ```
    pub fn with_domain(&mut self, domain: &str) -> &mut Self {
        {
            let mut context = self.context.lock().unwrap();
            context.domain = domain.to_string();
        }
        self
    }

    /// Sets the current pairs to the given [ContextPairs] value
    pub fn with_current(&mut self, pairs: ContextPairs) -> &mut Self {
        self.current = pairs.clone();
        self
    }

    /// Sets the proposed pairs to the given [ContextPairs] value
    pub fn with_proposed(&mut self, pairs: ContextPairs) -> &mut Self {
        self.context.lock().unwrap().current = pairs.clone();
        self.context.lock().unwrap().proposed = pairs;
        self
    }
    /// Add an unlock entry to the list of unlock entries
    pub fn with_entry(&mut self, entry: Kvp) -> &mut Self {
        self.unlock_entries.push(entry);
        self
    }

    /// Builds the Comrade instance and runs the unlock script with the given context and entries.
    pub fn run(&mut self) -> Result<Comrade, Box<dyn std::error::Error>> {
        // take the context and move it out of self.context
        let ctx: Context = std::mem::take(&mut *self.context.lock().unwrap());
        let mut comrade = Comrade::new(ctx);

        // set engine on_print
        comrade.engine.lock().unwrap().on_print(|msg| {
            debug!("[RHAI]: {}", msg);
        });

        debug!("Comrade context: {:?}", comrade.context.lock().unwrap());

        // move the unlock script into the Comrade instance
        // and run the unlock script called "for_great_justice"
        comrade
            .load(std::mem::take(&mut self.unlock_script))
            .run("for_great_justice")?;

        // after unlock has run, set the proposed to self.proposed
        comrade.current(std::mem::take(&mut self.current));

        Ok(comrade)
    }
}

/// The entry point for the Comrade API
#[derive(Debug)]
pub struct Comrade {
    pub(crate) context: Arc<Mutex<Context>>,
    engine: Arc<Mutex<Engine>>,
    script: Option<String>,
}

impl Default for Comrade {
    /// Create a new Comrade instance with the default context
    fn default() -> Self {
        Self::new(Context::default())
    }
}

pub struct Kvp {
    pub key: String,
    pub value: Value,
}

impl Comrade {
    /// Create a new Comrade instance with the given context
    pub fn new(ctx: Context) -> Self {
        let engine = Engine::new();
        let context = Arc::new(Mutex::new(ctx));

        let mut comrade = Comrade {
            context: Arc::clone(&context),
            engine: Arc::new(Mutex::new(engine)),
            script: None,
        };

        comrade.register();

        comrade
    }

    /// Set the [Context] to the given [Context] value and re-register the functions to the new [Context]
    pub fn register(&mut self) {
        let check_signature = {
            let context = Arc::clone(&self.context);
            move |key: &str, msg: &str| {
                let mut context = context.lock().unwrap();
                context.check_signature(key, msg)
            }
        };

        // register push function
        let push = {
            let context = Arc::clone(&self.context);
            move |key: String| {
                let mut context = context.lock().unwrap();
                context.push(&key)
            }
        };

        let check_preimage = {
            let context = Arc::clone(&self.context);
            move |key: String| {
                let mut context = context.lock().unwrap();
                context.check_preimage(key)
            }
        };

        let branch = {
            let context = Arc::clone(&self.context);
            move |key: &str| {
                let context = context.lock().unwrap();
                context.branch(key)
            }
        };

        self.engine
            .lock()
            .unwrap()
            .register_fn("check_signature", check_signature);
        self.engine.lock().unwrap().register_fn("push", push);
        self.engine
            .lock()
            .unwrap()
            .register_fn("check_preimage", check_preimage);
        self.engine.lock().unwrap().register_fn("branch", branch);
    }

    /// Sets the Context to the given [Context] Value
    pub fn stack(&mut self, current: ContextPairs, proposed: ContextPairs) {
        self.context.lock().unwrap().current = current;
        self.context.lock().unwrap().proposed = proposed;
    }

    /// Sets current pairs to the given [ContextPairs] Value
    pub fn current(&mut self, current: ContextPairs) {
        self.context.lock().unwrap().current = current;
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

        let ast = self
            .engine
            .lock()
            .unwrap()
            .compile(script)
            .map_err(|e| e.to_string())?;

        let mut scope = Scope::new();

        let result = self
            .engine
            .lock()
            .unwrap()
            .call_fn::<bool>(&mut scope, &ast, func, ())
            .map_err(|e| e.to_string())?;

        Ok(result)
    }

    /// Try the given lock script. Clones the current context and runs the lock script on the clone.
    pub fn try_lock(&self, lock: String) -> Result<Option<Value>, String> {
        // We need to re-use expensive engine, but clone pstack and rstack for each lock try.
        // In order to do that, we would need to re-link the engine to the inner context in the clone.
        let cloned_inner_context = self.context.lock().unwrap().clone();
        let mut cloned = Comrade {
            context: Arc::new(Mutex::new(cloned_inner_context)),
            engine: self.engine.clone(),
            script: self.script.clone(),
        };

        cloned.register();

        // load lock script, run move_every_zig
        let pass = cloned.load(lock).run("move_every_zig")?;

        if !pass {
            return Ok(None);
        }

        // check the context rstack top, return the result
        let x = Ok(cloned.context.lock().unwrap().rstack.top());
        x
    }
}

/// From<Comrade> for Context
impl From<&Comrade> for Context {
    fn from(comrade: &Comrade) -> Self {
        comrade.context.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod test_public_api {
    use super::*;

    //use test_log::env_logger::{self, Env};
    use test_log::tracing_subscriber::{fmt, EnvFilter};
    use tracing::{debug, info};

    fn init_logger() {
        let subscriber = fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .finish();
        match tracing::subscriber::set_global_default(subscriber) {
            Ok(()) => info!("Global default set."),
            Err(_) => info!("Global default already set."),
        }
    }

    fn unlock_script(for_great_justice: &str, entry_key: &str, proof_key: &str) -> String {
        let unlock_script = format!(
            r#"
            fn {for_great_justice}() {{

                print("RUNNING unlock script: for great justice");

                // push the serialized Entry as the message
                push("{entry_key}"); 

                // push the proof data
                push("{proof_key}");
            }}"#
        );

        unlock_script
    }

    /// First lock is /ephemeral and {entry_key}
    fn first_lock_script(entry_key: &str) -> String {
        let first_lock = format!(
            r#"
            fn move_every_zig() {{

                // print to console
                print("RUNNING for great justice");

                // check the first key, which is ephemeral
                check_signature("/ephemeral", "{entry_key}") 
            }}"#
        );

        first_lock
    }

    /// Other lock script
    fn other_lock_script(entry_key: &str) -> String {
        format!(
            r#"
            fn move_every_zig() {{

                // print to console
                print("RUNNING move_every_zig");

                // then check a possible threshold sig...
                check_signature("/tpubkey", "{entry_key}") ||

                // then check a possible pubkey sig...
                check_signature("/pubkey", "{entry_key}") ||
                
                // then the pre-image proof...
                check_preimage("/hash")
            }}"#
        )
    }

    #[test]
    fn test_instance_builder() -> Result<(), Box<dyn std::error::Error>> {
        init_logger();
        let entry_key = "/entry/";

        // unlock
        let entry_data = b"for great justice, move every zig!";
        let proof_key = "/entry/proof";
        let proof_data = hex::decode("b92483a6c00600010040eda2eceac1ef60c4d54efc7b50d86b198ba12358749e5069dbe0a5ca6c3e7e78912a21c67a18a4a594f904e7df16f798d929d7a8cee57baca89b4ed0dfd1c801").unwrap();

        let mut kvp_unlock = ContextPairs::default();
        kvp_unlock.put(entry_key.to_owned(), &entry_data.to_vec().into());
        kvp_unlock.put(proof_key.to_owned(), &proof_data.into());

        let unlock = unlock_script("for_great_justice", entry_key, &format!("{entry_key}proof"));

        // lock
        let first_lock = first_lock_script(entry_key);
        let other_lock = other_lock_script(entry_key);

        let locks = [
            // first_lock,
            other_lock,
        ];

        let pubkey = "/pubkey";
        let pub_key = hex::decode("ba24ed010874657374206b657901012069c9e8cd599542b5ff7e4cdc4265847feb9785330557edd6a9edae741ed4c3b2").unwrap();
        let mut kvp_lock = ContextPairs::default();
        kvp_lock.put(pubkey.to_owned(), &pub_key.into());

        debug!("[1] Running ComradeBuilder");

        let maybe_unlocked = ComradeBuilder::new(&unlock)
            .with_current(kvp_lock)
            .with_proposed(kvp_unlock)
            .run()?;

        let mut count = 0;

        debug!("[2] Running lock scripts");

        for lock in locks {
            match maybe_unlocked.try_lock(lock)? {
                // break loop if lock script succeeds
                Some(Value::Success(ct)) => {
                    count = ct;
                    break;
                }
                // continue loop if lock script fails
                _ => continue,
            }
        }

        assert_eq!(count, 1);
        Ok(())
    }
}
