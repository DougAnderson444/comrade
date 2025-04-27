use wac_graph::{CompositionGraph, EncodeOptions, types::Package};

pub fn compose() -> Result<(), Box<dyn std::error::Error>> {
    let mut graph = CompositionGraph::new();

    // Register the package dependencies into the graph
    let package = Package::from_file(
        "hello",
        None,
        "../../target/wasm32-unknown-unknown/release/comrade_wit.wasm",
        graph.types_mut(),
    )?;

    let hello = graph.register_package(package)?;
    let package = Package::from_file(
        "greeter",
        None,
        "../../target/wasm32-unknown-unknown/release/vm.wasm",
        graph.types_mut(),
    )?;
    let greeter = graph.register_package(package)?;

    // Instantiate the hello instance which does not have any arguments
    let hello_instance = graph.instantiate(hello);

    // Instantiate the greeter instance which has a single argument "hello" which is exported by the hello instance
    let greeter_instance = graph.instantiate(greeter);
    let hello_export = graph.alias_instance_export(hello_instance, "hello")?;
    graph.set_instantiation_argument(greeter_instance, "hello", hello_export)?;

    // Alias the "greet" export from the greeter instance
    let greet_export = graph.alias_instance_export(greeter_instance, "greet")?;
    // Export the "greet" function from the composition
    graph.export(greet_export, "greet")?;

    // Encode the graph into a WASM binary
    let encoding = graph.encode(EncodeOptions::default())?;
    std::fs::write("composition.wasm", encoding)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn test_wasm_component_layer_instance() -> Result<(), Box<dyn std::error::Error>> {
        compose()?;
        //log with timstamp
        eprintln!("{} [TestLog] test_instantiate_instance", chrono::Utc::now());

        Ok(())
    }
}
