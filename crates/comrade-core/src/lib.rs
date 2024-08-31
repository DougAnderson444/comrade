#![doc = include_str!("../README.md")]

mod context;
mod error;
mod storage;

use context::Context;

use context::ContextPairs;
use parking_lot::Mutex;
use rhai::Engine;
use std::sync::Arc;
pub use storage::pairs::Pairs;
pub use storage::stack::Stack;
pub use storage::stack::Stk;
pub use storage::value::Value;
use tracing::debug;

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// Comrade goes starts at [Inital] Stage, then goes to [Unlocked] Stage.
pub struct Initial;

/// Comrade goes starts at [Inital] Stage, then goes to [Unlocked] Stage.
#[derive(Debug)]
pub struct Unlocked;

/// Comrade Builder, which allows users to specify the key-path for the branch() function
pub struct ComradeBuilder {
    context: Arc<Mutex<Context>>,
    // Temp storage for current pairs until unlock script is run
    current: ContextPairs,
    unlock_script: String,
    unlock_entries: Vec<Kvp>,
}

impl ComradeBuilder {
    /// Create a new [ComradeBuilder] builder with the given unlock script and default context
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
    /// let comrade = ComradeBuilder::new(r#"push("your-key-path"); push("your-proof");"#).with_domain("forks/child").try_unlock();
    /// // full path is now "/forks/child/your-key-path"
    /// ```
    pub fn with_domain(&mut self, domain: &str) -> &mut Self {
        {
            let mut context = self.context.lock();
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
        self.context.lock().current = pairs.clone();
        self.context.lock().proposed = pairs;
        self
    }
    /// Add an unlock entry to the list of unlock entries
    pub fn with_entry(&mut self, entry: Kvp) -> &mut Self {
        self.unlock_entries.push(entry);
        self
    }

    /// Builds the [Comrade<Unlocked>] instance and runs the unlock script with the given context and entries.
    pub fn try_unlock(&mut self) -> Result<Comrade<Unlocked>, Box<dyn std::error::Error>> {
        // take the context and move it out of self.context
        let ctx: Context = std::mem::take(&mut *self.context.lock());
        let mut comrade = Comrade::new(ctx);

        // set engine on_print
        comrade.engine.lock().on_print(|msg| {
            debug!("[RHAI]: {}", msg);
        });

        // move the unlock script into the Comrade instance
        // and run the unlock script called "for_great_justice"
        comrade
            .load(std::mem::take(&mut self.unlock_script))
            .run()?;

        // after unlock has run, set the proposed to self.proposed
        comrade.current(std::mem::take(&mut self.current));

        Ok(comrade.into())
    }
}

/// From Inital to Unlocked, PhantomData changes everything else stays the same
impl From<Comrade<Initial>> for Comrade<Unlocked> {
    fn from(comrade: Comrade<Initial>) -> Self {
        Comrade {
            context: comrade.context,
            engine: comrade.engine,
            script: comrade.script,
            stage: std::marker::PhantomData,
        }
    }
}

/// The entry point for the Comrade API
#[derive(Debug)]
pub struct Comrade<Stage> {
    context: Arc<Mutex<Context>>,
    engine: Arc<Mutex<Engine>>,
    script: Option<String>,
    stage: std::marker::PhantomData<Stage>,
}

impl Default for Comrade<Initial> {
    /// Create a new Comrade instance with the default context
    fn default() -> Self {
        Self::new(Context::default())
    }
}

pub struct Kvp {
    pub key: String,
    pub value: Value,
}

impl Comrade<Initial> {
    /// Create a new Comrade instance with the given context
    pub fn new(ctx: Context) -> Self {
        let engine = Engine::new();
        let context = Arc::new(Mutex::new(ctx));

        let mut comrade = Comrade {
            context: Arc::clone(&context),
            engine: Arc::new(Mutex::new(engine)),
            script: None,
            stage: std::marker::PhantomData,
        };

        comrade.register_unlock();

        comrade
    }

    /// Registers just the unlock functions (push, branch) to the [Context] Rhai [Engine]
    pub fn register_unlock(&mut self) {
        let push = {
            let context = Arc::clone(&self.context);
            move |key: String| {
                let mut context = context.lock();
                context.push(&key)
            }
        };

        let branch = {
            let context = Arc::clone(&self.context);
            move |key: &str| {
                let context = context.lock();
                context.branch(key)
            }
        };

        self.engine.lock().register_fn("push", push);
        self.engine.lock().register_fn("branch", branch);
    }
}

impl<Stage> Comrade<Stage> {
    /// Sets the Context to the given [Context] Value
    pub fn stack(&mut self, current: ContextPairs, proposed: ContextPairs) {
        self.context.lock().current = current;
        self.context.lock().proposed = proposed;
    }

    /// Sets current pairs to the given [ContextPairs] Value
    pub fn current(&mut self, current: ContextPairs) {
        self.context.lock().current = current;
    }

    /// Put key-value pairs into the Comrade context
    pub fn put(&mut self, kvps: Vec<Kvp>) -> Result<(), String> {
        let mut context = self.context.lock();

        // proposed gets set to the current by taking the value from memory
        context.proposed = std::mem::take(&mut context.current);

        kvps.into_iter().for_each(|kvp| {
            context.current.put(kvp.key, &kvp.value);
        });

        Ok(())
    }

    /// Loads a lock script into Comrade
    pub fn load(&mut self, script: String) -> &mut Self {
        self.script = Some(script);
        self
    }

    /// Evaluate the Rhai script function with the given name
    pub fn run(&mut self) -> Result<bool, String> {
        // get unlock script, if None return error
        let script = self.script.as_ref().ok_or("no script loaded")?;

        let result = self.engine.lock().eval(script).map_err(|e| e.to_string())?;

        Ok(result)
    }
}

impl Comrade<Unlocked> {
    /// Returns the return Stack
    pub fn returns(&self) -> Stk {
        self.context.lock().rstack.clone()
    }

    /// Registers just the lock functions (check_signature, check_preimage)
    pub fn register_lock(&mut self) {
        let check_signature = {
            let context = Arc::clone(&self.context);
            move |key: &str, msg: &str| {
                let mut context = context.lock();
                context.check_signature(key, msg)
            }
        };

        let check_preimage = {
            let context = Arc::clone(&self.context);
            move |key: String| {
                let mut context = context.lock();
                context.check_preimage(key)
            }
        };

        self.engine
            .lock()
            .register_fn("check_signature", check_signature);
        self.engine
            .lock()
            .register_fn("check_preimage", check_preimage);
    }

    /// Try the given lock script. Clones the current context and runs the lock script on the clone.
    pub fn try_lock(&self, lock: String) -> Result<Option<Value>, String> {
        // We want to re-use expensive Rhai Engine, but clone pstack and rstack for each lock try.
        // In order to do that, we would need to re-register the engine to the inner context of the clone.
        let cloned_inner_context = self.context.lock().clone();
        let mut cloned = Comrade::<Unlocked> {
            context: Arc::new(Mutex::new(cloned_inner_context)),
            engine: self.engine.clone(),
            script: self.script.clone(),
            stage: std::marker::PhantomData,
        };

        cloned.register_lock();

        // load lock script, run move_every_zig
        cloned.load(lock).run()?;

        // check the context rstack top, return the result
        let x = cloned.context.lock().rstack.top();
        Ok(x)
    }
}

/// From<Comrade> for Context
impl<Stage> From<&Comrade<Stage>> for Context {
    fn from(comrade: &Comrade<Stage>) -> Self {
        comrade.context.lock().clone()
    }
}

#[cfg(test)]
mod test_public_api {
    use super::*;

    //use test_log::env_logger::{self, Env};
    use test_log::tracing_subscriber::{fmt, EnvFilter};

    fn init_logger() {
        let subscriber = fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .finish();
        if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
            tracing::warn!("failed to set subscriber: {}", e);
        }
    }

    fn unlock_script(entry_key: &str, proof_key: &str) -> String {
        let unlock_script = format!(
            r#"
                print("RUNNING unlock script");

                // push the serialized Entry as the message
                push("{entry_key}"); 

                // push the proof data
                push("{proof_key}");
            "#
        );

        unlock_script
    }

    /// First lock is /ephemeral and {entry_key}
    fn first_lock_script(entry_key: &str) -> String {
        let first_lock = format!(
            r#"
                // print to console
                print("RUNNING first lock: for great justice");

                // check the first key, which is ephemeral
                check_signature("/ephemeral", "{entry_key}") 
            "#
        );

        first_lock
    }

    /// Other lock script
    fn other_lock_script(entry_key: &str) -> String {
        format!(
            r#"
                // print to console
                print("RUNNING lock script: move_every_zig");

                // then check a possible threshold sig...
                check_signature("/recoverykey", "{entry_key}") ||

                // then check a possible pubkey sig...
                check_signature("/pubkey", "{entry_key}") ||
                
                // then the pre-image proof...
                check_preimage("/hash")
            "#
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

        let unlock = unlock_script(entry_key, &format!("{entry_key}proof"));

        // lock
        let first_lock = first_lock_script(entry_key);
        let other_lock = other_lock_script(entry_key);

        let locks = [first_lock, other_lock];

        let pubkey = "/pubkey";
        let pub_key = hex::decode("ba24ed010874657374206b657901012069c9e8cd599542b5ff7e4cdc4265847feb9785330557edd6a9edae741ed4c3b2").unwrap();
        let mut kvp_lock = ContextPairs::default();
        kvp_lock.put(pubkey.to_owned(), &pub_key.into());

        let maybe_unlocked = ComradeBuilder::new(&unlock)
            .with_current(kvp_lock)
            .with_proposed(kvp_unlock)
            .try_unlock()?;

        let mut count = 0;

        for lock in locks {
            if let Some(Value::Success(ct)) = maybe_unlocked.try_lock(lock)? {
                count = ct;
                break;
            }
        }

        assert_eq!(count, 1);
        Ok(())
    }
}
