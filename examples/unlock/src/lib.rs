#[allow(warnings)]
mod bindings;

use bindings::Guest;

struct Component;

impl Guest for Component {
    /// Say hello!
    fn for_great_justice() {
        "push".to_string();
    }
}

bindings::export!(Component with_types_in bindings);
