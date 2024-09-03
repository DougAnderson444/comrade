# Comrade

Comrade is a cross-platform, sandboxed, WebAssembly friendly, Browser compatible VLAD (Verifiable Long-lived Addresses) virtual machine. It's the friend every VLAD wants.

## Usage

Natively, in Rust:

```rust
# use std::error::Error;
# use comrade_core::{Comrade, ComradeBuilder};
# use comrade_core::context::ContextPairs;
# use comrade_core::storage::pairs::Pairs;
# use comrade_core::storage::stack::Stack;
# use comrade_core::storage::stack::Stk;
# use comrade_core::storage::value::Value; 
# use comrade_core::context::{Proposed, Current};
# fn main() -> Result<(), Box<dyn Error>> {

let entry_key = "/entry/";

// unlock
let entry_data = b"for great justice, move every zig!";
let proof_key = "/entry/proof";
let proof_data = hex::decode("b92483a6c00600010040eda2eceac1ef60c4d54efc7b50d86b198ba12358749e5069dbe0a5ca6c3e7e78912a21c67a18a4a594f904e7df16f798d929d7a8cee57baca89b4ed0dfd1c801").unwrap();

let mut kvp_unlock = ContextPairs::default();
kvp_unlock.put(entry_key, &entry_data.to_vec().into());
kvp_unlock.put(proof_key, &proof_data.into());

let unlock = r#"
    // push the serialized Entry as the message
    push("/entry/"); 

    // push the proof data
    push("/entry/proof");
"#;

// lock
let first_lock = r#"
    // check the first key, which is ephemeral
    check_signature("/ephemeral", "/entry/")
"#;

let other_lock = r#"
    // then check a possible threshold sig...
    check_signature("/recoverykey", "/entry/") ||

    // then check a possible pubkey sig...
    check_signature("/pubkey", "/entry/") ||

    // then the pre-image proof...
    check_preimage("/hash")
"#;

let locks = [first_lock, other_lock];

let pubkey = "/pubkey";
let pub_key = hex::decode("ba24ed010874657374206b657901012069c9e8cd599542b5ff7e4cdc4265847feb9785330557edd6a9edae741ed4c3b2").unwrap();
let mut kvp_lock = ContextPairs::default();
kvp_lock.put(pubkey, &pub_key.into());

let unlocked = ComradeBuilder::new(&unlock, Current(kvp_lock), Proposed(kvp_unlock))
    .with_domain("/")
    .try_unlock()?;

let mut count = 0;

for lock in locks {
    if let Some(Value::Success(ct)) = unlocked.try_lock(lock.to_string())? {
        count = ct;
        break;
    }
}

assert_eq!(count, 1);

#
#     Ok(())
# }
```

In the Browser, you would pull Comrade in as a dependecy to `provenance_log` crate and use the Comrade vm to execute the script.

## Rationale

The main rationale behind Comarde to to iterate on the Script Format.

The initial design for the WebAssembly Cryptographic Constructs Virtual Machine has two heavy dependecies:
1. Wasmtime
2. Wasm Scripts

These dependecies place certain limitations on the user, namely:
- The user must write or compile to WebAssembly Text Format (WAT)
- Scripts cannot be written in the browser, nor can key-paths and values be dynamic
- It only will run whereever wasmtime runs, which excludes the browser, mobile, embedded, and other platforms

The goal here is to maintain the same security guarantees as the WebAssembly Cryptographic Constructs Virtual Machine, but to remove the limitations of the Wasmtime and WAT. We can do this by using Rhai Script.

Using WebAssembly to Script in WebAssembly is kind of like using C++ to extend Chrome instead of using JavaScript. Now before anyone gets upset, I am NOT advocating the we use JavaScript, it's just an analogy.

Using Rhai to Script in WebAssembly is like using Miniscript to Script in Bitcoin instead of Bitcoin Script. It's a higher level language that is more expressive and easier to use, yet offers sandboxing for running untrusted code.

With Comrade, the only functions available are the same that are available in WACC VM (push, check_signature, etc.). If any other function is called, the code will Error.

# Building

To build all crates that are WIT Components, run:

```sh
just build-wits
```

# Status: Experimental

Due to the ever changing nature of the pre-version 1.0 WASI, this project is experimental and may break at any time.
