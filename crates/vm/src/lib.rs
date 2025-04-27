#[allow(warnings)]
mod bindings;

use bindings::component::vm::utils::log;
use bindings::exports::component::vm::vm::Guest;

struct VirtualMachine;

impl Guest for VirtualMachine {
    /// Say hello!
    fn run(script: String) -> Result<bool, String> {
        log(&format!("Running script: {}", script));
        todo!()
    }
}

bindings::export!(VirtualMachine with_types_in bindings);
