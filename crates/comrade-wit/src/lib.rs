mod random;

wit_bindgen::generate!({
    path: "wit/world.wit"
});

export!(Comrade);

use std::cell::RefCell;

// The WIT deps, provided by the host system
use comrade::core::host::log;
use comrade::core::pairs::Value;
use exports::comrade::core::wacc::{Current, Proposed};

// The deps exported from this crate
use exports::comrade::core::wacc::{Guest, GuestConstructs};

struct Comrade {
    current: RefCell<Current>,
    proposed: RefCell<Proposed>,
    unlock: RefCell<Option<String>>,
}

impl Guest for Comrade {
    type Constructs = Self;
}

impl GuestConstructs for Comrade {
    fn new(current: Current, proposed: Proposed) -> Self {
        log("Creating new Component");
        Self {
            current: RefCell::new(current),
            proposed: RefCell::new(proposed),
            unlock: RefCell::new(None),
        }
    }

    fn try_unlock(&self, unlock: String) -> Result<(), String> {
        log("Unlocking component");
        self.unlock.borrow_mut().replace(unlock);
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
