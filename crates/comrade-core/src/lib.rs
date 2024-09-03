#![doc = include_str!("../README.md")]

pub mod context;
mod error;
mod storage;

pub use context::ContextPairs;
pub use storage::pairs::Pairs;
pub use storage::stack::Stack;
pub use storage::stack::Stk;
pub use storage::value::Value;

use context::{Context, Current, Proposed};
use parking_lot::Mutex;
use rhai::Engine;
use std::fmt::Debug;
use std::ops::Deref;
use std::sync::Arc;

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// Comrade goes starts at [Initial] Stage, then goes to [Unlocked] Stage.
#[derive(Debug, Default)]
pub struct Initial;

/// Comrade goes starts at [Initial] Stage, then goes to [Unlocked] Stage.
#[derive(Debug)]
pub struct Unlocked;

/// Trait Pairable is: [Pairs], [Default], [Debug], and [Clone]
pub trait Pairable: Pairs + Default + Clone + Debug {}

impl<P: Pairs + Default + Clone> Pairable for P {}

/// Builder handles building the [Comrade] instance, which allows users to specify the key-path for the branch() function
pub struct ComradeBuilder<P: Pairable> {
    /// The context for the Comrade instance
    context: Arc<Mutex<Context<P>>>,
    /// Temp storage for [Current] [Pairable] until unlock script is run
    current: Current<P>,
    /// The unlock script to run
    unlock_script: String,
}

impl<P: Pairable + 'static> ComradeBuilder<P> {
    /// Creates a new [ComradeBuilder] builder with the given unlock Rhai expression script,
    /// [Current] [Pairable] and [Proposed] [Pairable].
    ///
    /// The user can then optionally specific a domain context for the branch() function path.
    pub fn new(unlock: &str, current: Current<P>, proposed: Proposed<P>) -> Self {
        Self {
            context: Arc::new(Mutex::new(Context::new(
                Current(proposed.deref().clone()),
                proposed,
            ))),
            current,
            unlock_script: unlock.to_string(),
        }
    }

    /// Optionally set the key-path domain for use in branch() functions.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// use comrade_core::ComradeBuilder;
    /// use comrade_core::{Comrade, ContextPairs, Unlocked};
    /// let comrade: Comrade<Unlocked, ContextPairs> = ComradeBuilder::new(
    ///     r#"push("your-key-path"); push("your-proof");"#,
    ///     Default::default(),
    ///     Default::default()
    /// )
    ///     .with_domain("forks/child")
    ///     .try_unlock()?;
    ///
    /// // full path is now "/forks/child/your-key-path"
    ///
    /// #
    /// #     Ok(())
    /// # }
    /// ```
    pub fn with_domain(&mut self, domain: &str) -> &mut Self {
        {
            let mut context = self.context.lock();
            context.domain = domain.to_string();
        }
        self
    }

    /// Builds the [Comrade<Unlocked>] instance and runs the unlock script with the given context and entries.
    pub fn try_unlock(&mut self) -> Result<Comrade<Unlocked, P>, Box<dyn std::error::Error>> {
        // take the context and move it out of self.context
        let ctx: Context<P> = self.context.lock().clone();
        let mut comrade = Comrade::new(ctx);

        // if test, set engine on_print
        #[cfg(test)]
        comrade.engine.lock().on_print(|msg| {
            tracing::debug!("[RHAI]: {}", msg);
        });

        // move the unlock script into the Comrade instance
        // and run the unlock script called "for_great_justice"
        comrade
            .load(std::mem::take(&mut self.unlock_script))
            .run()?;

        // During unlock, both the current and proposed are set to the proposed value.
        // after unlock has run, take the current to set the current value.
        // We can take the current value because the unlock script has already run, and only
        // runs once.
        // comrade.current((*self.current).clone());
        comrade.current(std::mem::take(&mut self.current));

        Ok(comrade.into())
    }
}

/// Switches the [std::marker::PhantomData] to [Unlocked] Stage
impl<P: Pairable> From<Comrade<Initial, P>> for Comrade<Unlocked, P> {
    fn from(comrade: Comrade<Initial, P>) -> Self {
        Comrade {
            context: comrade.context,
            engine: comrade.engine,
            script: comrade.script,
            stage: std::marker::PhantomData,
        }
    }
}

/// The Comrade API at either the [Initial] or [Unlocked] Stage. [Pairs] must be [Pairable].
#[derive(Debug, Default)]
pub struct Comrade<Stage, P: Pairable> {
    context: Arc<Mutex<Context<P>>>,
    engine: Arc<Mutex<Engine>>,
    script: Option<String>,
    stage: std::marker::PhantomData<Stage>,
}

impl<P: Pairable + 'static> Comrade<Initial, P> {
    /// Create a new Comrade instance with the given [Context].
    /// Can only be used to create a Comrade instance at the [Initial] Stage.
    pub fn new(ctx: Context<P>) -> Self {
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

    /// Registers just the unlock functions (push, branch) to the [Context] Rhai [Engine].
    /// Unock functions are only available at the [Initial] Stage.
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

impl<Stage, P: Pairable> Comrade<Stage, P> {
    /// Sets current pairs to the given [ContextPairs] Value
    pub fn current(&mut self, current: P) {
        self.context.lock().current = current.into();
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

/// Methods available at [Unlocked] Stage
impl<P: Pairable + 'static> Comrade<Unlocked, P> {
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
        let mut cloned = Comrade::<Unlocked, P> {
            context: Arc::new(Mutex::new(cloned_inner_context)),
            engine: self.engine.clone(),
            script: self.script.clone(),
            stage: std::marker::PhantomData,
        };

        cloned.register_lock();

        // load lock script, run move_every_zig
        cloned.load(lock).run()?;

        // check the context rstack top, return the result
        let res = cloned.context.lock().rstack.top();
        Ok(res)
    }
}

impl<Stage, P: Pairable> From<&Comrade<Stage, P>> for Context<P> {
    fn from(comrade: &Comrade<Stage, P>) -> Self {
        comrade.context.lock().clone()
    }
}

#[cfg(test)]
mod test_public_api {
    use super::*;

    use context::ContextPairs;
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
    fn test_api() -> Result<(), Box<dyn std::error::Error>> {
        init_logger();
        let entry_key = "/entry/";

        // unlock
        let entry_data = b"for great justice, move every zig!";
        let proof_key = "/entry/proof";
        let proof_data = hex::decode("b92483a6c00600010040eda2eceac1ef60c4d54efc7b50d86b198ba12358749e5069dbe0a5ca6c3e7e78912a21c67a18a4a594f904e7df16f798d929d7a8cee57baca89b4ed0dfd1c801").unwrap();

        let mut kvp_unlock = ContextPairs::default();
        kvp_unlock.put(entry_key, &entry_data.to_vec().into());
        kvp_unlock.put(proof_key, &proof_data.into());

        let unlock = unlock_script(entry_key, &format!("{entry_key}proof"));

        // lock
        let first_lock = first_lock_script(entry_key);
        let other_lock = other_lock_script(entry_key);

        let locks = [first_lock, other_lock];

        let pubkey = "/pubkey";
        let pub_key = hex::decode("ba24ed010874657374206b657901012069c9e8cd599542b5ff7e4cdc4265847feb9785330557edd6a9edae741ed4c3b2").unwrap();
        let mut kvp_lock = ContextPairs::default();
        kvp_lock.put(pubkey, &pub_key.into());

        let unlocked = ComradeBuilder::new(&unlock, Current(kvp_lock), Proposed(kvp_unlock))
            .with_domain("/")
            .try_unlock()?;

        let mut count = 0;

        for lock in locks {
            if let Some(Value::Success(ct)) = unlocked.try_lock(lock)? {
                count = ct;
                break;
            }
        }

        assert_eq!(count, 1);
        Ok(())
    }
}
