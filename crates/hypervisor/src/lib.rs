#[allow(warnings)]
mod bindings;

use bindings::exports::comrade::hypervisor::{check, stack};

struct Component;

impl check::Guest for Component {
    /// Checks the signature for the given key.
    fn signature(key: String) -> bool {
        todo!()
    }

    /// Checks the preimage for the given key.
    fn preimage(key: String) -> bool {
        todo!()
    }
}

impl stack::Guest for Component {
    /// Pushes the given value onto the stack.
    fn push(value: String) {
        todo!()
    }

    /// Pops the top value from the stack.
    fn pop() -> String {
        todo!()
    }
}

bindings::export!(Component with_types_in bindings);
