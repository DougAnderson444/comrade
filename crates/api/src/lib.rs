#[allow(warnings)]
mod bindings;
mod context;
mod error;
mod parser;
mod random;
mod vm;

use bindings::comrade::api::pairs::Value;
use bindings::comrade::api::utils::log;
use bindings::exports::comrade::api::api::{Guest, GuestApi};
use vm::Vm;

use std::cell::RefCell;

struct Api {
    vm: RefCell<vm::Vm>,
    unlock: RefCell<Option<String>>,
}

impl Guest for Api {
    type Api = Self;
}

impl GuestApi for Api {
    fn new() -> Self {
        log("Creating new Component");

        Self {
            vm: Vm::new().into(),
            unlock: RefCell::new(None),
        }
    }

    fn try_unlock(&self, unlock: String) -> Result<(), String> {
        log("try_unlock");
        self.unlock.borrow_mut().replace(unlock.clone());
        // self.vm.run(&unlock).map_err(|e| e.to_string())?;
        self.vm.borrow_mut().run(&unlock).map_err(|e| {
            log(&format!("Error running unlock script: {}", e));
            format!("Error running unlock script: {}", e)
        })?;
        Ok(())
    }

    fn try_lock(&self, lock: String) -> Result<Option<Value>, String> {
        log(&format!("try_lock script: {}", lock));
        self.vm.borrow_mut().run(&lock).map_err(|e| {
            log(&format!("Error running lock script: {}", e));
            format!("Error running lock script: {}", e)
        })?;
        // return rstack
        let rstack = self.vm.borrow_mut().rstack();
        Ok(rstack.map(|v| v.into()))
    }
}

bindings::export!(Api with_types_in bindings);
