#[allow(warnings)]
mod bindings;
mod context;
mod pest;
mod random;
mod vm;

use bindings::comrade::api::pairs::{self, Either, Value};
use bindings::comrade::api::utils::log;
use bindings::exports::comrade::api::api::{Guest, GuestApi};
use vm::Vm;

use std::cell::RefCell;

struct Api {
    vm: vm::Vm,
    unlock: RefCell<Option<String>>,
}

impl Guest for Api {
    type Api = Self;
}

impl GuestApi for Api {
    fn new() -> Self {
        log("Creating new Component");

        Self {
            vm: Vm::new(),
            unlock: RefCell::new(None),
        }
    }

    fn try_unlock(&self, unlock: String) -> Result<(), String> {
        log("Unlocking component");
        self.unlock.borrow_mut().replace(unlock.clone());
        self.vm.run(&unlock).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn try_lock(&self, _lock: String) -> Result<Option<Value>, String> {
        log("Trying to lock component");
        // load the unlock script
        // run the unlock script
        // set context current
        todo!()
    }
}

bindings::export!(Api with_types_in bindings);
