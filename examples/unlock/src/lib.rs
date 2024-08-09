#[allow(warnings)]
mod bindings;

use bindings::Guest;

use bindings::comrade::hypervisor::stack;

struct Component;

impl Guest for Component {
    /// Say hello!
    fn for_great_justice() {
        stack::push("Sign me with your key!");
    }
}

bindings::export!(Component with_types_in bindings);
