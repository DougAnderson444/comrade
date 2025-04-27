mod random;

wit_bindgen::generate!({
    path: "wit/world.wit"
});

export!(Comrade);

use std::cell::RefCell;

// The WIT deps, provided by the host system
use comrade::core::host::log;
use comrade::core::pairs::Value;
// The deps exported from this crate
use exports::comrade::core::context::{self, GuestContext};
use exports::comrade::core::wacc::{self, GuestConstructs};

struct Comrade {
    unlock: RefCell<Option<String>>,
}

impl wacc::Guest for Comrade {
    type Constructs = Self;
}

impl GuestConstructs for Comrade {
    fn new() -> Self {
        log("Creating new Component");
        Self {
            unlock: RefCell::new(None),
        }
    }

    fn try_unlock(&self, unlock: String) -> Result<(), String> {
        log("Unlocking component");
        self.unlock.borrow_mut().replace(unlock);
        // run(unlock.clone())?;
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
impl context::Guest for Comrade {
    type Context = Self;
}

impl GuestContext for Comrade {
    // `new`, `check_signature`, `check_preimage`, `check_eq`, `check_fail`, `fail`, `succeed`, `push`, `branch`
    fn new() -> Self {
        todo!()
    }

    fn check_signature(&self, signature: String, msg: String) -> bool {
        log("Checking signature");
        // check the signature
        // set context current
        todo!()
    }

    fn check_preimage(&self, preimage: String) -> bool {
        log("Checking preimage");
        // check the preimage
        // set context current
        todo!()
    }

    fn check_eq(&self, eq: String) -> bool {
        log("Checking equality");
        // check the equality
        // set context current
        todo!()
    }

    fn check_fail(&self, fail: String) -> bool {
        log("Checking failure");
        // check the failure
        // set context current
        todo!()
    }

    fn fail(&self, fail: String) -> bool {
        log("Failing");
        // fail the component
        // set context current
        todo!()
    }

    fn succeed(&self) -> bool {
        log("Succeeding");
        // succeed the component
        // set context current
        todo!()
    }

    fn push(&self, push: String) -> bool {
        log("Pushing");
        // push the component
        // set context current
        todo!()
    }

    fn branch(&self, branch: String) -> bool {
        log("Branching");
        // branch the component
        // set context current
        todo!()
    }
}
