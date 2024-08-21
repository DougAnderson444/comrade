//use std::error::Error;

use test_log::test;
//use comrade_core::ContextPairs as Kvp;
//use comrade_core::Pairs as _;
use comrade_core::Stack as _;
//use comrade_core::Stk;
use comrade_core::Value;

use comrade_core::Comrade;
use std::error::Error;
use tracing::debug;

#[test]
fn test_lib_pubkey() -> Result<(), Box<dyn Error>> {
    debug!("LETS TEST THE PUBKEY CHECK");

    let mut comrade = Comrade::new();

    let entry_key = "/entry/";
    let proof_key = "/entry/proof";

    let data = hex::decode("3983a6c0060001004076fee92ca796162b5e37a84b4150da685d636491b43c1e2a1fab392a7337553502588a609075b56c46b5c033b260d8d314b584e396fc2221c55f54843679ee08").unwrap();

    let proof = b"for great justice, move every zig!";

    let _ = comrade.put(entry_key.to_owned(), &proof.as_ref().into());
    let _ = comrade.put(proof_key.to_owned(), &data.clone().into());

    let for_great_justice = "for_great_justice";

    let unlock_script = format!(
        r#"
            fn {for_great_justice}() {{

                // print to console
                print("RUNNING for great justice");

                // push the serialized Entry as the message
                push("{entry_key}"); 

                // push the proof data
                push("{proof_key}");
            }}"#
    );

    // load and run `for_great_justice` function. Check stack for correctness.
    let res = comrade.load(unlock_script).run(for_great_justice)?;

    assert!(res);

    let pubkey = "/pubkey";
    let pub_key = hex::decode("3aed010874657374206b657901012084d515ef051e07d597f3c14ac09e5a9d5012c659c196d96db5c6b98ea552f603").unwrap();
    let _ = comrade.put(pubkey.to_owned(), &pub_key.into());

    let move_every_zig = "move_every_zig";

    // lock is move_every_zig
    let lock_script = format!(
        r#"
            fn {move_every_zig}() {{

                // print to console
                print("MOVE, Zig!");

                // then check a possible threshold sig...
                check_signature("/tpubkey") ||

                // then check a possible pubkey sig...
                check_signature("{pubkey}") ||
                
                // then the pre-image proof...
                check_preimage("/hash")

            }}"#
    );

    let res = comrade.load(lock_script).run(move_every_zig)?;

    assert!(res);
    assert_eq!(
        //comrade.context.lock().unwrap().rstack.top().unwrap(),
        comrade.returns().top().unwrap(),
        Value::Success(1)
    );

    Ok(())
}
