#[allow(warnings)]
mod bindings;

use bindings::{component::unlock::host::push, Guest};

struct Component;

impl Guest for Component {
    /// Say hello!  
    fn unlock() -> bool {
        // push "/entry/"
        push("/entry/");
        // push "/entry/proof"
        push("/entry/proof");

        true
    }
}

bindings::export!(Component with_types_in bindings);
