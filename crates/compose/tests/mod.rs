//! Compose and Test the composed wasm
use compose::compose;
use std::path::{Path, PathBuf};

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
fn test_wasm_component_layer_instance() {
    compose();
    //log with timstamp
    eprintln!("{} [TestLog] test_instantiate_instance", chrono::Utc::now());
}
