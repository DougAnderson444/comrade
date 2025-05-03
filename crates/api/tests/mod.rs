//! This test use [wasm_component_layer] which gives us flexibility to define the host runtime,
//! but it is slower to run because the bytes have to be read into memory, as opposed
//! to being read from disk like when using wasmtime.
//!
//! Use this model when you need runtime agnostic code, or when you need to define your own
//! host runtime.  Otherwise on native targets, use the wasmtime runtime layer as it's faster.
//!
use std::{
    ops::Deref,
    path::{Path, PathBuf},
};

use comrade_core::{
    ContextPairs, Pairs,
    definitions::{either_enum, *},
};
use wasm_component_layer::*;

// Note: wasmi is way faster than wasmtime when using the layer
use wasmi_runtime_layer as runtime_layer;

/// Utility function to get the workspace dir
pub fn workspace_dir() -> PathBuf {
    let output = std::process::Command::new(env!("CARGO"))
        .arg("locate-project")
        .arg("--workspace")
        .arg("--message-format=plain")
        .output()
        .unwrap()
        .stdout;
    let cargo_path = Path::new(std::str::from_utf8(&output).unwrap().trim());
    cargo_path.parent().unwrap().to_path_buf()
}

#[derive(Clone, Default, Debug)]
struct Data {
    pub current: ContextPairs,
    pub proposed: ContextPairs,
}

#[test]
fn test_api_layer_instance() {
    //log with timstamp
    eprintln!("{} [TestLog] test_instantiate_instance", chrono::Utc::now());

    // get the target/wasm32-wasi/debug/CARGO_PKG_NAME.wasm file
    let pkg_name = std::env::var("CARGO_PKG_NAME").unwrap().replace('-', "_");
    let workspace = workspace_dir();
    let wasm_path = format!("target/wasm32-unknown-unknown/release/{}.wasm", pkg_name);
    eprintln!(
        "{} [TestLog] Looking for wasm file: {}",
        chrono::Utc::now(),
        wasm_path
    );
    let wasm_path = workspace.join(wasm_path);

    //let bytes: &[u8] =
    //    include_bytes!("../../../target/wasm32-unknown-unknown/release/wit_limbo.wasm");

    let bytes = std::fs::read(wasm_path).unwrap();

    let data = Data::default();

    // Create a new engine for instantiating a component.
    let engine = Engine::new(runtime_layer::Engine::default());

    // Create a store for managing WASM data and any custom user-defined state.
    let mut store = Store::new(&engine, data);

    eprintln!(
        "{} [TestLog] Created store, loading bytes.",
        chrono::Utc::now()
    );
    // Parse the component bytes and load its imports and exports.
    let component = Component::new(&engine, &bytes).unwrap();

    eprintln!("{} [TestLog] Loaded bytes", chrono::Utc::now());

    // Create a linker that will be used to resolve the component's imports, if any.
    let mut linker = Linker::default();

    let host_interface = linker
        .define_instance("comrade:api/utils".try_into().unwrap())
        .unwrap();

    host_interface
        .define_func(
            "log",
            Func::new(
                &mut store,
                FuncType::new([ValueType::String], []),
                move |_store, params, _results| {
                    if let Value::String(s) = &params[0] {
                        eprintln!("{}", s);
                    }
                    Ok(())
                },
            ),
        )
        .unwrap();

    // func "random-byte" is defined in the host interface
    host_interface
        .define_func(
            "random-byte",
            Func::new(
                &mut store,
                FuncType::new([], [ValueType::U8]),
                move |_store, _params, results| {
                    let random = rand::random::<u8>();
                    results[0] = Value::U8(random);
                    Ok(())
                },
            ),
        )
        .unwrap();

    let pairs_interface = linker
        .define_instance("comrade:api/pairs".try_into().unwrap())
        .unwrap();

    // get(choice: either, key: string) -> option<value>
    // gets either the current or proposed
    pairs_interface
        .define_func(
            "get",
            Func::new(
                &mut store,
                FuncType::new(
                    [ValueType::Enum(either_enum()), ValueType::String],
                    [ValueType::Option(OptionType::new(ValueType::Variant(
                        value_variant(),
                    )))],
                ),
                move |store, params, results| {
                    if let Value::Enum(choice) = &params[0] {
                        if let Value::String(key) = &params[1] {
                            let data = store.data();
                            let context_pair = match choice.discriminant() {
                                0 => {
                                    eprintln!("[TestLog] get current");
                                    &data.current
                                }
                                1 => {
                                    eprintln!("[TestLog] get proposed");
                                    &data.proposed
                                }
                                _ => panic!("Invalid choice"),
                            };
                            let value = context_pair.get(key.to_string().as_str());
                            eprintln!("\n[TestLog] get({:?}) = {:?}\n", key, value);
                            results[0] = match value {
                                Some(v) => {
                                    let value = into_comp_value(v.clone()).unwrap();
                                    Value::Option(OptionValue::new(
                                        OptionType::new(ValueType::Variant(value_variant())),
                                        Some(value),
                                    )?)
                                }
                                None => Value::Option(OptionValue::new(
                                    OptionType::new(ValueType::Variant(value_variant())),
                                    None,
                                )?),
                            };
                        } else {
                            panic!("Expected String, found {:?}", params[1]);
                        }
                    };
                    Ok(())
                },
            ),
        )
        .unwrap();

    // put is similar to get, except it mutates the current or proposed value witht he given value
    // and key
    // it returns success or failure
    pairs_interface
        .define_func(
            "put",
            Func::new(
                &mut store,
                FuncType::new(
                    [
                        ValueType::Enum(either_enum()),
                        ValueType::String,
                        ValueType::Variant(value_variant()),
                    ],
                    [ValueType::Variant(value_variant())],
                ),
                move |mut store, params, results| {
                    if let Value::Enum(choice) = &params[0] {
                        if let Value::String(key) = &params[1] {
                            let data = store.data_mut();
                            let cp = match choice.discriminant() {
                                0 => &mut data.current,
                                1 => &mut data.proposed,
                                _ => panic!("Invalid enum choice, must be current or proposed"),
                            };
                            let value = into_core_value(params[2].clone()).unwrap();
                            cp.put(key.to_string().as_str(), &value);
                            results[0] = success_variant(0);
                        } else {
                            results[0] =
                                failure_variant(format!("Expected String, found {:?}", params[1]));
                        }
                    };
                    Ok(())
                },
            ),
        )
        .unwrap();

    // Instantiate the component with the linker and store.
    let instance = linker.instantiate(&mut store, &component).unwrap();

    // Get the interface that the interface exports.
    let exports = instance.exports();

    /* Set up test data */
    let entry_key = "/entry/";

    // unlock
    let entry_data = b"for great justice, move every zig!";
    let proof_key = "/entry/proof";
    let proof_data = hex::decode("4819397f51b18bc6cffd1fff07afa33f7096c7a0c659590b077cc0ea5d6081d739512129becacb8e6997e6b7d18756299f515a822344ac2b6737979d5e5e6b03").unwrap();

    // /entry/ needs to be current for push("/entry/"), and proposed for check_signature("/pubkey", "/entry/")
    store
        .data_mut()
        .proposed
        .put(entry_key, &entry_data.to_vec().into());

    store
        .data_mut()
        .current
        .put(entry_key, &entry_data.to_vec().into());

    store
        .data_mut()
        .current
        .put(proof_key, &proof_data.clone().into());
    store.data_mut().proposed.put(proof_key, &proof_data.into());

    let unlock = format!(
        r#"
        // push the serialized Entry as the message
        push("{entry_key}");

        // push the proof data
        push("{entry_key}proof");
    "#
    );

    let first_lock = format!(
        r#"
                // check the first key, which is ephemeral
                check_signature("/ephemeral", "{entry_key}") 
            "#
    );

    let other_lock = format!(
        r#"
                // then check a possible threshold sig...
                check_signature("/recoverykey", "{entry_key}") ||

                // then check a possible pubkey sig...
                check_signature("/pubkey", "{entry_key}") ||
                
                // then the pre-image proof...
                check_preimage("/hash")
            "#
    );

    let locks = [first_lock, other_lock];

    let pubkey = "/pubkey";
    let pub_key = hex::decode("ba24ed010874657374206b657901012054d94d7b8a11d6581af4a14bc6451c7a23049018610f108c996968fe8fce9464").unwrap();

    // Set current
    store.data_mut().current.put(pubkey, &pub_key.into());

    let interface = exports
        .instance(&"comrade:api/api".try_into().unwrap())
        .unwrap();

    // Call the resource constructor
    let resource_constructor = interface.func("[constructor]api").unwrap();

    let arguments = &[];
    let mut results = vec![Value::Bool(false)];

    resource_constructor
        .call(&mut store, arguments, &mut results)
        .unwrap();

    let api_resource = match results[0] {
        Value::Own(ref resource) => resource.clone(),
        _ => panic!("Unexpected result type"),
    };

    let borrowed_api = api_resource.borrow(store.as_context_mut()).unwrap();

    let unlock_args = vec![
        Value::Borrow(borrowed_api.clone()),
        Value::String(unlock.into()),
    ];

    let try_unlock = interface.func("[method]api.try-unlock").unwrap();

    // Call the try_unlock method
    let mut results = vec![Value::Bool(false)];
    try_unlock
        .call(&mut store, &unlock_args, &mut results)
        .unwrap();

    // eprintln!("\n[TestLog] try_unlock = {:?}", results);

    // [Result(ResultValue { ty: ResultType { ok_err: (None, Some(String)) }, value: Ok(None) })]

    // Check the result
    if let Value::Result(result) = &results[0] {
        match **result {
            Ok(_) => {
                eprintln!("[TestLog] Unlock successful");
            }
            Err(ref e) => {
                panic!("Unlock failed with error: {:?}", e.as_ref().unwrap());
            }
        }
    } else {
        panic!("Unexpected result type");
    }

    let mut count = 0u32;

    for lock in locks {
        let lock_args = vec![
            Value::Borrow(borrowed_api.clone()),
            Value::String(lock.into()),
        ];

        let try_lock = interface.func("[method]api.try-lock").unwrap();

        // Call the try_lock method
        let mut results = vec![Value::Bool(false)];
        try_lock.call(&mut store, &lock_args, &mut results).unwrap();

        // eprintln!("\n[TestLog] try_lock = {:?}", results);

        // Check the result
        if let Value::Result(result) = &results[0] {
            let inner = result.deref();

            // eprintln!("\n[TestLog] Lock result: {:?}", inner);
            match inner {
                Ok(Some(Value::U32(ct))) => {
                    // eprintln!("\n[TestLog] Lock successful: {:?}", ct);
                    count = *ct;
                    break;
                }
                Err(e) => {
                    // eprintln!("\n[TestLog] Lock failed: {:?}", e.as_ref().unwrap());
                }
                _ => {
                    // eprintln!("\n[TestLog] Lock failed: {:?}", result);
                }
            }
        } else {
            panic!("Unexpected result type");
        }
    }

    assert_eq!(count, 1);
}

// Use Multikey to generate some test signatures
mod test {
    use multikey::EncodedMultikey;

    #[test]
    fn generate_test_signatures() {
        use multikey::Views as _;
        use multikey::{self, Multikey};
        use multisig::Views as _;
        use multiutil::prelude::*;

        let seed = hex::decode("f9ddcd5118319cc69e6985ef3f4ee3b6c591d46255e1ae5569c8662111b7d3c2")
            .unwrap();
        let mk = multikey::Builder::new_from_seed(Codec::Ed25519Priv, seed.as_slice())
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        let entry_data = b"for great justice, move every zig!";

        eprintln!("Entry data: {:?}", entry_data);

        let signmk = mk.sign_view().unwrap();

        let signature = signmk.sign(entry_data.as_slice(), false, None).unwrap();

        // print out hex signature
        let sig_data = signature.data_view().unwrap();
        let sig_bytes = sig_data.sig_bytes().unwrap();

        eprintln!("Signature bytes: {:?}", &sig_bytes);

        let ms = multisig::Builder::new(Codec::EddsaMsig)
            .with_signature_bytes(&sig_bytes)
            .try_build()
            .unwrap();

        let hex_sig = hex::encode(ms.data_view().unwrap().sig_bytes().unwrap());
        eprintln!("Signature: {}", hex_sig);

        // hex sig should be 4819397f51b18bc6cffd1fff07afa33f7096c7a0c659590b077cc0ea5d6081d739512129becacb8e6997e6b7d18756299f515a822344ac2b6737979d5e5e6b03
        assert_eq!(
            hex_sig,
            "4819397f51b18bc6cffd1fff07afa33f7096c7a0c659590b077cc0ea5d6081d739512129becacb8e6997e6b7d18756299f515a822344ac2b6737979d5e5e6b03"
        );

        let verify_mk = mk.verify_view().unwrap();
        assert!(verify_mk.verify(&ms, Some(entry_data.as_ref())).is_ok());

        // print pubkey
        let pubkey = mk.conv_view().unwrap();
        let pubkey_data = pubkey.to_public_key().unwrap();

        let pubkey_bytes: Vec<u8> = pubkey.to_public_key().unwrap().into();

        eprintln!("Pubkey bytes: {:?}", pubkey_bytes);
        let hex_pubkey = hex::encode(pubkey_bytes.clone());

        eprintln!("Pubkey: {}", hex_pubkey);

        // hex pubkey should be ba24ed010874657374206b657901012054d94d7b8a11d6581af4a14bc6451c7a23049018610f108c996968fe8fce9464
        assert_eq!(
            hex_pubkey,
            "ba24ed010874657374206b657901012054d94d7b8a11d6581af4a14bc6451c7a23049018610f108c996968fe8fce9464"
        );
    }
}
