wit_bindgen::generate!({
    path: "wit/world.wit"
});

export!(Component);

use std::cell::RefCell;

use comrade::core::host::{log, random_byte};
use comrade_core::{Context, Pairable};
use exports::comrade::core::foo::{Guest, GuestBar};

/// Custom function to use the import for random byte generation.
///
/// We do this is because "js" feature is incompatible with the component model
/// if you ever got the __wbindgen_placeholder__ error when trying to use the `js` feature
/// of getrandom,
fn imported_random(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    // iterate over the length of the destination buffer and fill it with random bytes
    (0..dest.len()).for_each(|i| {
        dest[i] = random_byte();
    });

    Ok(())
}

getrandom::register_custom_getrandom!(imported_random);

struct Component<C: Pairable, P: Pairable> {
    val: RefCell<Context<C, P>>,
}

impl<C: Pairable + 'static, P: Pairable + 'static> Guest for Component<C, P> {
    type Bar = Self;
}

impl<C: Pairable + 'static, P: Pairable + 'static> GuestBar for Component<C, P> {
    fn new(val: i32) -> Self {
        log(&format!("Creating new Component with value: {}", val));
        Component {
            val: RefCell::new(val),
        }
    }

    fn value(&self) -> i32 {
        *self.val.borrow()
    }
}
