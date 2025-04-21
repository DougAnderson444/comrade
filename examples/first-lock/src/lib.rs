#[allow(warnings)]
mod bindings;

use bindings::Guest;

struct Component;

impl Guest for Component {
    /// Say hello!
    fn lock(entry: String) -> bool {
        // check the first key, which is ephemeral
        check_signature("/ephemeral", "{entry_key}")
    }
}

bindings::export!(Component with_types_in bindings);
