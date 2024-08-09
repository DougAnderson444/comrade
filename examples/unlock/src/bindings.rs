// Generated by `wit-bindgen` 0.25.0. DO NOT EDIT!
// Options used:
#[doc(hidden)]
#[allow(non_snake_case)]
pub unsafe fn _export_for_great_justice_cabi<T: Guest>() {
    #[cfg(target_arch = "wasm32")]
    _rt::run_ctors_once();
    T::for_great_justice();
}
pub trait Guest {
    fn for_great_justice();
}
#[doc(hidden)]

macro_rules! __export_world_unlock_cabi{
  ($ty:ident with_types_in $($path_to_types:tt)*) => (const _: () = {

    #[export_name = "for-great-justice"]
    unsafe extern "C" fn export_for_great_justice() {
      $($path_to_types)*::_export_for_great_justice_cabi::<$ty>()
    }
  };);
}
#[doc(hidden)]
pub(crate) use __export_world_unlock_cabi;
#[allow(dead_code)]
pub mod comrade {
    #[allow(dead_code)]
    pub mod hypervisor {
        #[allow(dead_code, clippy::all)]
        pub mod check {
            #[used]
            #[doc(hidden)]
            #[cfg(target_arch = "wasm32")]
            static __FORCE_SECTION_REF: fn() =
                super::super::super::__link_custom_section_describing_imports;
            use super::super::super::_rt;
            #[allow(unused_unsafe, clippy::all)]
            /// Checks the signature
            pub fn signature(key: &str) -> bool {
                unsafe {
                    let vec0 = key;
                    let ptr0 = vec0.as_ptr().cast::<u8>();
                    let len0 = vec0.len();

                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "comrade:hypervisor/check@0.1.0")]
                    extern "C" {
                        #[link_name = "signature"]
                        fn wit_import(_: *mut u8, _: usize) -> i32;
                    }

                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8, _: usize) -> i32 {
                        unreachable!()
                    }
                    let ret = wit_import(ptr0.cast_mut(), len0);
                    _rt::bool_lift(ret as u8)
                }
            }
            #[allow(unused_unsafe, clippy::all)]
            /// Checks the hash preimage
            pub fn preimage(key: &str) -> bool {
                unsafe {
                    let vec0 = key;
                    let ptr0 = vec0.as_ptr().cast::<u8>();
                    let len0 = vec0.len();

                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "comrade:hypervisor/check@0.1.0")]
                    extern "C" {
                        #[link_name = "preimage"]
                        fn wit_import(_: *mut u8, _: usize) -> i32;
                    }

                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8, _: usize) -> i32 {
                        unreachable!()
                    }
                    let ret = wit_import(ptr0.cast_mut(), len0);
                    _rt::bool_lift(ret as u8)
                }
            }
        }
    }
}
mod _rt {
    pub unsafe fn bool_lift(val: u8) -> bool {
        if cfg!(debug_assertions) {
            match val {
                0 => false,
                1 => true,
                _ => panic!("invalid bool discriminant"),
            }
        } else {
            val != 0
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub fn run_ctors_once() {
        wit_bindgen_rt::run_ctors_once();
    }
}

/// Generates `#[no_mangle]` functions to export the specified type as the
/// root implementation of all generated traits.
///
/// For more information see the documentation of `wit_bindgen::generate!`.
///
/// ```rust
/// # macro_rules! export{ ($($t:tt)*) => (); }
/// # trait Guest {}
/// struct MyType;
///
/// impl Guest for MyType {
///     // ...
/// }
///
/// export!(MyType);
/// ```
#[allow(unused_macros)]
#[doc(hidden)]

macro_rules! __export_unlock_impl {
  ($ty:ident) => (self::export!($ty with_types_in self););
  ($ty:ident with_types_in $($path_to_types_root:tt)*) => (
  $($path_to_types_root)*::__export_world_unlock_cabi!($ty with_types_in $($path_to_types_root)*);
  )
}
#[doc(inline)]
pub(crate) use __export_unlock_impl as export;

#[cfg(target_arch = "wasm32")]
#[link_section = "component-type:wit-bindgen:0.25.0:unlock:encoded world"]
#[doc(hidden)]
pub static __WIT_BINDGEN_COMPONENT_TYPE: [u8; 261] = *b"\
\0asm\x0d\0\x01\0\0\x19\x16wit-component-encoding\x04\0\x07\x88\x01\x01A\x02\x01\
A\x04\x01B\x03\x01@\x01\x03keys\0\x7f\x04\0\x09signature\x01\0\x04\0\x08preimage\
\x01\0\x03\x01\x1ecomrade:hypervisor/check@0.1.0\x05\0\x01@\0\x01\0\x04\0\x11for\
-great-justice\x01\x01\x04\x01\x17component:unlock/unlock\x04\0\x0b\x0c\x01\0\x06\
unlock\x03\0\0\0G\x09producers\x01\x0cprocessed-by\x02\x0dwit-component\x070.208\
.1\x10wit-bindgen-rust\x060.25.0";

#[inline(never)]
#[doc(hidden)]
#[cfg(target_arch = "wasm32")]
pub fn __link_custom_section_describing_imports() {
    wit_bindgen_rt::maybe_link_cabi_realloc();
}
