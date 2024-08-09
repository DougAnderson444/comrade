#[allow(warnings)]
mod bindings;

use bindings::Guest;

use crate::bindings::comrade::hypervisor::check;

struct Component;

impl Guest for Component {
    /// Move zig!
    fn move_every_zig() -> bool {
        check::signature("/pubkey")
    }
}

bindings::export!(Component with_types_in bindings);
