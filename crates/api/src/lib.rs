#[allow(warnings)]
mod bindings;

use bindings::comrade::api::pairs::Value;
use bindings::comrade::api::utils::log;
use bindings::comrade::api::vm;
use bindings::exports::comrade::api::api::{Guest, GuestApi};
// use bindings::exports::comrade::api::pairs::Value;

use std::cell::RefCell;

struct Api {
    unlock: RefCell<Option<String>>,
}

impl Guest for Api {
    type Api = Self;
}

impl GuestApi for Api {
    fn new() -> Self {
        log("Creating new Component");
        Self {
            unlock: RefCell::new(None),
        }
    }

    fn try_unlock(&self, unlock: String) -> Result<(), String> {
        log("Unlocking component");
        self.unlock.borrow_mut().replace(unlock.clone());
        vm::run(&unlock)?;
        Ok(())
    }

    fn try_lock(&self, lock: String) -> Result<Option<Value>, String> {
        log("Trying to lock component");
        // load the unlock script
        // run the unlock script
        // set context current
        todo!()
    }
}

bindings::export!(Api with_types_in bindings);
