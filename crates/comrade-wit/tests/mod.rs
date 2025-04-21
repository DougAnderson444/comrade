//! This test use [wasm_component_layer] which gives us flexibility to define the host runtime,
//! but it is slower to run because the bytes have to be read into memory, as opposed
//! to being read from disk like when using wasmtime.
//!
//! Use this model when you need runtime agnostic code, or when you need to define your own
//! host runtime.  Otherwise on native targets, use the wasmtime runtime layer as it's faster.
//!
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use comrade_core::Pairs;
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

pub fn list_data() -> ValueType {
    ValueType::List(ListType::new(ValueType::U8))
}

pub fn binary_rec_ty() -> RecordType {
    RecordType::new(
        None,
        vec![("value", list_data()), ("hint", ValueType::String)],
    )
    .unwrap()
}

pub fn str_rec_ty() -> RecordType {
    RecordType::new(
        None,
        vec![("value", ValueType::String), ("hint", ValueType::String)],
    )
    .unwrap()
}

/// Vlaue variant type is either, binary, str, success(u32), or failure(String)
fn value_variant() -> VariantType {
    VariantType::new(
        None,
        vec![
            VariantCase::new("bin", Some(ValueType::Record(binary_rec_ty()))),
            VariantCase::new("str", Some(ValueType::Record(str_rec_ty()))),
            VariantCase::new("success", Some(ValueType::U32)),
            VariantCase::new("failure", Some(ValueType::String)),
        ],
    )
    .unwrap()
}

fn bin_variant(data: Vec<u8>, hint: String) -> Value {
    Value::Variant(
        Variant::new(
            value_variant(),
            0,
            Some(Value::Record(
                Record::new(
                    binary_rec_ty(),
                    vec![
                        (
                            "value",
                            Value::List(
                                List::new(
                                    ListType::new(ValueType::U8),
                                    data.iter().map(|b| Value::U8(*b)).collect::<Vec<Value>>(),
                                )
                                .unwrap(),
                            ),
                        ),
                        ("hint", Value::String(hint.into())),
                    ],
                )
                .unwrap(),
            )),
        )
        .unwrap(),
    )
}

fn str_variant(data: String, hint: String) -> Value {
    Value::Variant(
        Variant::new(
            value_variant(),
            1,
            Some(Value::Record(
                Record::new(
                    str_rec_ty(),
                    vec![
                        ("value", Value::String(data.into())),
                        ("hint", Value::String(hint.into())),
                    ],
                )
                .unwrap(),
            )),
        )
        .unwrap(),
    )
}

fn failure_variant(msg: String) -> Value {
    Value::Variant(Variant::new(value_variant(), 3, Some(Value::String(msg.into()))).unwrap())
}

/// Success variant
fn success_variant(code: u32) -> Value {
    Value::Variant(Variant::new(value_variant(), 2, Some(Value::U32(code))).unwrap())
}

#[derive(Clone, Default, Debug)]
pub struct ContextPairs {
    pairs: HashMap<String, comrade_core::Value>,
}

impl Pairs for ContextPairs {
    fn get(&self, key: &str) -> Option<comrade_core::Value> {
        self.pairs.get(key).cloned()
    }

    fn put(&mut self, key: &str, value: &comrade_core::Value) -> Option<comrade_core::Value> {
        self.pairs.insert(key.to_string(), value.clone())
    }
}

/// From comrade_core::Value to wasm_component_layer::Value
fn into_comp_value(value: comrade_core::Value) -> Result<wasm_component_layer::Value, String> {
    match value {
        comrade_core::Value::Bin { hint, data } => Ok(wasm_component_layer::Value::Record(
            Record::new(
                binary_rec_ty(),
                vec![
                    (
                        "value",
                        Value::List(
                            List::new(
                                ListType::new(ValueType::U8),
                                data.iter().map(|b| Value::U8(*b)).collect::<Vec<Value>>(),
                            )
                            .unwrap(),
                        ),
                    ),
                    ("hint", Value::String(hint.into())),
                ],
            )
            .unwrap(),
        )),
        comrade_core::Value::Str { hint, data } => Ok(wasm_component_layer::Value::Record(
            Record::new(
                str_rec_ty(),
                vec![
                    ("value", Value::String(data.into())),
                    ("hint", Value::String(hint.into())),
                ],
            )
            .unwrap(),
        )),
        _ => Err(format!(
            "Cannot convert {:?} to wasm_component_layer::Value",
            value
        )),
    }
}

/// Convert from wasm_component_layer::Value to comrade_core::Value
fn into_core_value(value: wasm_component_layer::Value) -> Result<comrade_core::Value, String> {
    match value {
        wasm_component_layer::Value::Record(record) => {
            if let Some(Value::String(hint)) = record.field("hint") {
                if let Some(Value::List(list)) = record.field("value") {
                    let data: Vec<u8> = list
                        .iter()
                        .map(|v| match v {
                            Value::U8(b) => Ok(b),
                            _ => Err(format!("Expected U8, found {:?}", v)),
                        })
                        .collect::<Result<Vec<u8>, String>>()?;
                    return Ok(comrade_core::Value::Bin {
                        hint: hint.to_string(),
                        data,
                    });
                }
            }
            Err(format!("Invalid record: {:?}", record))
        }
        _ => Err(format!("Cannot convert {:?} to comrade_core::Value", value)),
    }
}

#[test]
fn test_wasm_component_layer_instance() {
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

    let data = ContextPairs::default();

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
        .define_instance("comrade:core/host".try_into().unwrap())
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
        .define_instance("comrade:core/pairs".try_into().unwrap())
        .unwrap();

    // Create a type to represent the host-defined resource to put/get values
    let pairs_resource_ty = ResourceType::new::<ContextPairs>(None);
    let pairs_resource_ty_clone = pairs_resource_ty.clone();

    pairs_interface
        .define_resource("kvpairs", pairs_resource_ty.clone())
        .unwrap();

    // Host provides the [constructor]kvpairs
    pairs_interface
        .define_func(
            "[constructor]kvpairs",
            Func::new(
                &mut store,
                FuncType::new([], [ValueType::Own(pairs_resource_ty.clone())]),
                move |store, _params, results| {
                    let resource = ResourceOwn::new(
                        store,
                        ContextPairs::default(),
                        pairs_resource_ty_clone.clone(),
                    )?;
                    results[0] = Value::Own(resource);
                    Ok(())
                },
            ),
        )
        .unwrap();

    // Host provides the [method]kvpairs.get
    pairs_interface
        .define_func(
            "[method]kvpairs.get",
            Func::new(
                &mut store,
                FuncType::new(
                    [
                        ValueType::Borrow(pairs_resource_ty.clone()),
                        ValueType::String,
                    ],
                    [ValueType::Variant(value_variant())],
                ),
                move |store, params, results| {
                    let Value::Borrow(res) = &params[0] else {
                        panic!("Expected Borrow, found {:?}", params[0]);
                    };

                    let key = params[1].clone();
                    let value = match key {
                        Value::String(ref s) => {
                            // Try to get and convert the value, return failure variant if any step fails
                            let ctx = &store.as_context();
                            let cp = res.rep::<ContextPairs, _, _>(ctx).unwrap();

                            cp.pairs
                                .get(&s.to_string())
                                .map(|v| {
                                    // could be bin or str? Or just str?
                                    if let comrade_core::Value::Str { hint, data } = v {
                                        str_variant(data.to_string(), hint.to_string())
                                    } else if let comrade_core::Value::Bin { hint, data } = v {
                                        bin_variant(data.to_vec(), hint.to_string())
                                    } else {
                                        failure_variant(format!(
                                            "Expected Bin or Str, found: {:?}",
                                            v
                                        ))
                                    }
                                })
                                .unwrap_or_else(|| {
                                    failure_variant(format!(
                                        "Failed to get value for key: {:?}",
                                        key
                                    ))
                                })
                        }
                        _ => failure_variant(format!(
                            "Invalid key type. Expected String, got: {:?}",
                            key
                        )),
                    };
                    results[0] = value;
                    Ok(())
                },
            ),
        )
        .unwrap();

    // Host provides the [method]kvpairs.put
    pairs_interface
        .define_func(
            "[method]kvpairs.put",
            Func::new(
                &mut store,
                FuncType::new(
                    [
                        ValueType::Borrow(pairs_resource_ty.clone()),
                        ValueType::String,
                        ValueType::Variant(value_variant()),
                    ],
                    [],
                ),
                move |mut store, params, results| {
                    let Value::Borrow(res) = &params[0] else {
                        panic!("Expected Borrow, found {:?}", params[0]);
                    };

                    let key = params[1].clone();
                    let value = params[2].clone();

                    results[0] = if let Value::String(ref s) = key {
                        // Try to get and convert the value, return failure variant if any step fails
                        let ctx = &mut store.as_context_mut();
                        let cp: &mut ContextPairs = res.rep_mut(ctx).unwrap();

                        // Convert the value to comrade_core::Value
                        let core_value = into_core_value(value)
                            .unwrap_or_else(|e| panic!("Failed to convert value: {:?}", e));

                        // Store the value in the pairs
                        cp.put(s, &core_value);

                        into_comp_value(core_value)
                            .unwrap_or_else(|e| panic!("Failed to convert value: {:?}", e))
                    } else {
                        failure_variant(format!(
                            "Invalid key type. Expected String, got: {:?}",
                            key
                        ))
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

    //// Get the interface that the interface exports.
    //let interface = exports
    //    .instance(&"component:wit-limbo/limbo".try_into().unwrap())
    //    .unwrap();
    //
    //// Call the resource constructor for 'bar' using a direct function call
    //let resource_constructor = interface.func("[constructor]database").unwrap();
    //
    //// We need to provide a mutable reference to store the results.
    //// This can be any Value type, as it will get overwritten by the result.
    //// It is a Value::Bool here but will be overwritten by a Value::Own(ResourceOwn)
    //// after we call the constructor.
    //let mut results = vec![Value::Bool(false)];
    //let arguments = &[Value::String(":memory:".to_string().into())];
    //
    //eprintln!(
    //    "{} [TestLog] Calling resource constructor",
    //    chrono::Utc::now()
    //);
    //
    //// Construct the resource with the argument `42`
    //resource_constructor
    //    .call(&mut store, arguments, &mut results)
    //    .unwrap();
    //
    //let database_resource = match results[0] {
    //    Value::Own(ref resource) => resource.clone(),
    //    _ => panic!("Unexpected result type"),
    //};
    //
    //let borrowed_db = database_resource.borrow(store.as_context_mut()).unwrap();
    //
    //// argument are: 1) The borrowed resource, and 2) the SQL statement
    //// Let's make the sqlite statement to be Create Table users
    //let sql = "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL);".to_string();
    //let exec_arguments = vec![
    //    Value::Borrow(borrowed_db.clone()),
    //    Value::String(sql.into()),
    //];
    //
    //eprintln!("{} [TestLog] Calling database.exec", chrono::Utc::now());
    //
    //// method database exec
    //let method_database_exec = interface.func("[method]database.exec").unwrap();
    //
    //method_database_exec
    //    .call(&mut store, &exec_arguments, &mut [])
    //    .unwrap();
    //
    //// Insert user into the database
    //let exec_arguments = vec![
    //    Value::Borrow(borrowed_db.clone()),
    //    Value::String("INSERT INTO users (name) VALUES ('Alice');".into()),
    //];
    //
    //eprintln!("{} [TestLog] Calling database.exec", chrono::Utc::now());
    //
    //// Call the method, mutate the results
    //method_database_exec
    //    .call(&mut store, &exec_arguments, &mut [])
    //    .unwrap();
    //
    //// Get the `value` method of the `bar` resource
    //let method_prepare = interface.func("[method]database.prepare").unwrap();
    //
    //let sql = "SELECT * FROM users;".to_string();
    //let prepare_arguments = vec![
    //    Value::Borrow(borrowed_db.clone()),
    //    Value::String(sql.into()),
    //];
    //let mut results = [Value::Bool(false)];
    //
    //eprintln!("{} [TestLog] Calling database.prepare", chrono::Utc::now());
    //
    //// Call the method, mutate the results
    //method_prepare
    //    .call(&mut store, &prepare_arguments, &mut results)
    //    .unwrap();
    //
    //let statement_resource = match results[0] {
    //    Value::Own(ref resource) => resource.clone(),
    //    _ => panic!("Unexpected result type"),
    //};
    //
    //// Now use the statement resource to call [method]statement.all to get all results
    //let borrowed_stmt = statement_resource.borrow(store.as_context_mut()).unwrap();
    //
    //let method_all = interface.func("[method]statement.all").unwrap();
    //
    //let mut results = [Value::Bool(false)];
    //
    //eprintln!("{} [TestLog] Calling statement.all", chrono::Utc::now());
    //
    //// Call the method, mutate the results
    //method_all
    //    .call(
    //        &mut store,
    //        &[Value::Borrow(borrowed_stmt.clone())],
    //        &mut results,
    //    )
    //    .unwrap();
    //
    //eprintln!(
    //    "{} [TestLog] Finished calling statement.all",
    //    chrono::Utc::now()
    //);
    //
    //let list = match results[0] {
    //    Value::List(ref list) => list.clone(),
    //    _ => panic!("Expected List, found Unexpected result type"),
    //};
    //
    //println!("[ResultLog]");
    //println!(" └ database.prepare() =");
    //// enumerate each row, then each column
    //for (i, row) in list.iter().enumerate() {
    //    println!("    └ Row {}", i);
    //    let row = match row {
    //        Value::List(ref list) => list,
    //        _ => panic!("Expected List, found Unexpected result type"),
    //    };
    //
    //    print!("       └ ");
    //    for (j, column) in row.iter().enumerate() {
    //        print!(" ");
    //        match column {
    //            Value::Variant(ref variant) => {
    //                let variant = variant.clone();
    //                let value = variant.value();
    //                match value {
    //                    Some(Value::S64(v)) => print!("       └ Column {}: {:?}, ", j, v),
    //                    Some(Value::String(v)) => print!("       └ Column {}: {:?}, ", j, v),
    //                    _ => print!(": {:?}", value),
    //                }
    //            }
    //            _ => panic!("Expected Variant, found Unexpected result type"),
    //        }
    //    }
    //    println!("\n\n");
    //}
    //
    //let record_value_ty = VariantType::new(
    //    None,
    //    vec![
    //        VariantCase::new("null", None),
    //        VariantCase::new("integer", Some(ValueType::S64)),
    //        VariantCase::new("float", Some(ValueType::F64)),
    //        VariantCase::new("text", Some(ValueType::String)),
    //        VariantCase::new("blob", Some(ValueType::List(ListType::new(ValueType::U8)))),
    //    ],
    //)
    //.unwrap();
    //
    //let list_type = ListType::new(ValueType::List(ListType::new(ValueType::Variant(
    //    record_value_ty.clone(),
    //))));
    //
    //let expected_list = List::new(
    //    list_type.clone(),
    //    vec![Value::List(
    //        List::new(
    //            ListType::new(ValueType::Variant(record_value_ty.clone())),
    //            vec![
    //                Value::Variant(
    //                    Variant::new(record_value_ty.clone(), 1, Some(Value::S64(1))).unwrap(),
    //                ),
    //                Value::Variant(
    //                    Variant::new(
    //                        record_value_ty.clone(),
    //                        3,
    //                        Some(Value::String("Alice".to_string().into())),
    //                    )
    //                    .unwrap(),
    //                ),
    //            ],
    //        )
    //        .unwrap(),
    //    )],
    //)
    //.unwrap();
    //
    //assert_eq!(list, expected_list);
}
