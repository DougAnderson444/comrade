use multicodec::Codec;
use multikey::mk;
use multikey::Views as _;

// Make a random pubkey and print out a pubkey in hex, and the multisignature of the given arg
fn make_pubkey(msg: impl AsRef<[u8]>) -> (String, String) {
    let mut rng = rand::rngs::OsRng;
    let mk = mk::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
        .unwrap()
        .with_comment("test key")
        .try_build()
        .unwrap();
    let signmk = mk.sign_view().unwrap();
    let signature = signmk.sign(msg.as_ref(), false, None).unwrap();

    let s: Vec<u8> = signature.into();
    let sig = hex::encode(s);
    let conv = mk.conv_view().unwrap();
    let pk = conv.to_public_key().unwrap();
    let pubkey = hex::encode(Into::<Vec<u8>>::into(pk.clone()));
    (pubkey, sig)
}
//#[test]
//fn test_lib_pubkey() -> Result<(), Box<dyn Error>> {
//    debug!("LETS TEST THE PUBKEY CHECK");
//
//    let mut comrade = Comrade::<Initial, ContextPairs>::default();
//
//    comrade.register_unlock();
//
//    let entry_key = "/entry/";
//    let entry_data = b"for great justice, move every zig!";
//
//    let proof_key = "/entry/proof";
//    let proof_data = hex::decode("b92483a6c00600010040eda2eceac1ef60c4d54efc7b50d86b198ba12358749e5069dbe0a5ca6c3e7e78912a21c67a18a4a594f904e7df16f798d929d7a8cee57baca89b4ed0dfd1c801").unwrap();
//
//    comrade.put(Vec::from([
//        Kvp {
//            key: entry_key.to_owned(),
//            value: entry_data.as_ref().into(),
//        },
//        Kvp {
//            key: proof_key.to_owned(),
//            value: proof_data.clone().into(),
//        },
//    ]))?;
//
//    let unlock_script = format!(
//        r#"
//            // print to console
//            print("UNLOCK, for great justice");
//
//            // push the serialized Entry as the message
//            push("{entry_key}");
//
//            // push the proof data
//            push("{proof_key}");
//        "#
//    );
//
//    // load and run unlock expression. Check stack for correctness.
//    let res = comrade.load(unlock_script).run()?;
//
//    assert!(res);
//
//    let pubkey = "/pubkey";
//    let pub_key = hex::decode("ba24ed010874657374206b657901012069c9e8cd599542b5ff7e4cdc4265847feb9785330557edd6a9edae741ed4c3b2").unwrap();
//    comrade.put(vec![Kvp {
//        key: pubkey.to_owned(),
//        value: pub_key.into(),
//    }])?;
//
//    // lock is move_every_zig
//    let lock_script = format!(
//        r#"
//            // print to console
//            print("LOCK, Zig!");
//
//            // then check a possible threshold sig...
//            check_signature("/recoverykey", "{entry_key}") ||
//
//            // then check a possible pubkey sig...
//            check_signature("{pubkey}", "{entry_key}") ||
//
//            // then the pre-image proof...
//            check_preimage("/hash")
//        "#
//    );
//
//    // convert to unlocked state
//    let mut comrade: Comrade<Unlocked, ContextPairs> = comrade.into();
//    comrade.register_lock();
//
//    let res = comrade.load(lock_script).run()?;
//
//    assert!(res);
//    //assert_eq!(comrade.returns().top().unwrap(), Value::Success(1));
//
//    Ok(())
//}
