# Comrade Core

Core logic that can be wrapped in any delivery means (extism, WIT, native, etc).

Takes lock and unlock script written as Rhai expressions and runs them through the virtal machine.

## Usage

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
