#[allow(warnings)]
mod bindings;

use crate::bindings::exports::comrade::hypervisor::check::Guest;

struct Component;

impl Guest for Component {
    /// Checks the signature for the given key.
    fn signature(key: String) -> bool {
        todo!()
    }

    /// Checks the preimage for the given key.
    fn preimage(key: String) -> bool {
        todo!()
    }
}

bindings::export!(Component with_types_in bindings);
