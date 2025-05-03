use crate::bindings::comrade::api::pairs::{Binary, Str};
use comrade_core::Pairs;

use crate::{
    bindings::comrade::api::{
        pairs::{self, get, put},
        utils::log,
    },
    context::Context,
};

#[derive(Default, Clone, Debug)]
struct Current;

#[derive(Default, Clone, Debug)]
struct Proposed;

impl Pairs for Current {
    fn get(&self, key: &str) -> Option<comrade_core::Value> {
        get(pairs::Either::Current, key)
            .map(|v| v.clone())
            .map(|v| v.into())
            .or_else(|| {
                log(&format!("Key not found: {}", key));
                None
            })
    }

    fn put(&mut self, key: &str, value: &comrade_core::Value) -> Option<comrade_core::Value> {
        log(&format!("Putting key: {} value: {:?}", key, value));
        let val = put(pairs::Either::Current, key, &value.clone().into());
        Some(val.into())
    }
}

impl Pairs for Proposed {
    fn get(&self, key: &str) -> Option<comrade_core::Value> {
        get(pairs::Either::Proposed, key)
            .map(|v| v.clone())
            .map(|v| v.into())
            .or_else(|| {
                log(&format!("Key not found: {}", key));
                None
            })
    }

    fn put(&mut self, key: &str, value: &comrade_core::Value) -> Option<comrade_core::Value> {
        log(&format!("Putting key: {} value: {:?}", key, value));
        let val = put(pairs::Either::Proposed, key, &value.clone().into());
        Some(val.into())
    }
}

impl From<pairs::Value> for comrade_core::Value {
    fn from(value: crate::bindings::comrade::api::pairs::Value) -> Self {
        match value {
            pairs::Value::Str(Str { data, hint }) => comrade_core::Value::Str { hint, data },
            pairs::Value::Bin(Binary { data, hint }) => comrade_core::Value::Bin { hint, data },
            pairs::Value::Success(value) => comrade_core::Value::Success(value.try_into().unwrap()),
            pairs::Value::Failure(msg) => comrade_core::Value::Failure(msg),
        }
    }
}

// From<comrade_core::Value>`  for `pairs::Value`
impl From<comrade_core::Value> for pairs::Value {
    fn from(value: comrade_core::Value) -> Self {
        match value {
            comrade_core::Value::Str { hint, data } => pairs::Value::Str(Str { hint, data }),
            comrade_core::Value::Bin { hint, data } => pairs::Value::Bin(Binary { hint, data }),
            comrade_core::Value::Success(value) => pairs::Value::Success(value.try_into().unwrap()),
            comrade_core::Value::Failure(msg) => pairs::Value::Failure(msg),
        }
    }
}

pub(crate) struct Vm {
    script: Option<String>,
    context: Context,
}

impl Vm {
    pub fn new() -> Self {
        log("Creating new VM");
        Self {
            script: None,
            context: Context::new(Box::new(Current::default()), Box::new(Proposed::default())),
        }
    }

    pub fn run(&mut self, script: &str) -> Result<bool, String> {
        log(&format!("Running script: {}", script));

        let result = self.context.run(script).map_err(|e| {
            log(&format!("Error running script: {}", e));
            format!("Error running script: {}", e)
        })?;

        Ok(result)
    }

    /// Return stack value
    pub fn rstack(&self) -> Option<comrade_core::Value> {
        log(&format!(
            "Returning stack value: {:?}",
            self.context.rstack()
        ));
        self.context.rstack()
    }
}
