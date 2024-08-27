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

/// FAILURE
pub const FAILURE: bool = false;

/// Comrade Builder, which allows users to specify the key-path for the branch() function
#[derive(Default)]
pub struct InstanceBuilder {
    context: Arc<Mutex<Context>>,
}

impl InstanceBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the key-path value for use in branch() functions.
    ///
    /// # Example
    ///
    /// ```
    /// use comrade_core::InstanceBuilder;
    /// let comrade = InstanceBuilder::default().with_domain("/forks/child/").build();
    /// // full path is now "/forks/child/your-key-path"
    /// ```
    pub fn with_domain(&mut self, domain: &str) -> &mut Self {
        {
            let mut context = self.context.lock().unwrap();
            context.domain = domain.to_string();
        }
        self
    }

    /// Builds the Comrade instance
    pub fn build(&self) -> Instance {
        Instance {
            context: Arc::clone(&self.context),
            engine: Engine::new(),
            script: None,
        }
    }
}

/// The entry point for the Comrade API
pub struct Instance {
    pub(crate) context: Arc<Mutex<Context>>,
    engine: Engine,
    script: Option<String>,
}

impl Default for Instance {
    /// Create a new Comrade instance with the default context
    fn default() -> Self {
        Self::new(Context::default())
    }
}

pub struct Kvp {
    pub key: String,
    pub value: Value,
}

impl Instance {
    /// Create a new Comrade instance with the given context
    pub fn new(ctx: Context) -> Self {
        let mut engine = Engine::new();
        let context = Arc::new(Mutex::new(ctx));

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

        let branch = {
            let context = Arc::clone(&context);
            move |key: &str| {
                let context = context.lock().unwrap();
                context.branch(key)
            }
        };

        engine.register_fn("check_signature", check_signature);
        engine.register_fn("push", push);
        engine.register_fn("check_preimage", check_preimage);
        engine.register_fn("branch", branch);

        Instance {
            context,
            engine,
            script: None,
        }
    }

    /// Sets the Context to the given [Context] Value
    pub fn stack(&mut self, current: ContextPairs, proposed: ContextPairs) {
        self.context.lock().unwrap().current = current;
        self.context.lock().unwrap().proposed = proposed;
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
