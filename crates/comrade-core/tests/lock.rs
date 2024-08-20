use std::error::Error;

use test_log::test;
use tracing::{debug, info};

use comrade_core::ContextPairs as Kvp;
use comrade_core::Pairs as _;
use comrade_core::Stack as _;
use comrade_core::Stk;

#[test]
fn test_pubkey() -> Result<(), Box<dyn Error>> {
    debug!("LETS TEST THE PUBKEY CHECK");

    let mut kvp_unlock = Kvp::default();
    let entry_key = "/entry/";
    let proof_key = "/entry/proof";
    let _ = kvp_unlock.put(
        entry_key.to_owned(),
        &b"for great justice, move every zig!".as_ref().into(),
    );
    let _ = kvp_unlock.put(proof_key.to_owned(), &hex::decode("3983a6c0060001004076fee92ca796162b5e37a84b4150da685d636491b43c1e2a1fab392a7337553502588a609075b56c46b5c033b260d8d314b584e396fc2221c55f54843679ee08").unwrap().into());

    let unlock_script = format!(
        r#"
fn for_great_justice() {{
    // push the serialized Entry as the message
    push("{entry_key}"); 

    // push the proof data
    push("{proof_key}");
}}"#
    );

    debug!("script: {}", unlock_script);

    // run the unlock script to set up the stack
    let mut comrade = comrade_core::Comrade::new();

    // load and run `for_great_justice` function. Check stack for correctness.
    let res = comrade
        .load_unlock(unlock_script)
        .run("for_great_justice")?;

    Ok(())
}
