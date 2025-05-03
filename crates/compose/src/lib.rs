use wac_graph::{CompositionGraph, EncodeOptions, types::Package};

pub fn compose() -> Result<(), Box<dyn std::error::Error>> {
    let mut graph = CompositionGraph::new();

    // Register the API package
    let package = Package::from_file(
        "api",
        None,
        "../../target/wasm32-unknown-unknown/release/comrade_wit.wasm",
        graph.types_mut(),
    )
    .unwrap();
    let api = graph.register_package(package).unwrap();

    // Register the VM package
    let package = Package::from_file(
        "vm",
        None,
        "../../target/wasm32-unknown-unknown/release/vm.wasm",
        graph.types_mut(),
    )
    .unwrap();
    let vm = graph.register_package(package).unwrap();

    // Instantiate both components
    let api_instance = graph.instantiate(api);
    let vm_instance = graph.instantiate(vm);

    // Connect the "vm" export from the VM instance to the "vm" import of the API instance
    let vm_export = graph
        .alias_instance_export(vm_instance, "comrade:vm/vm")
        .unwrap();
    graph
        .set_instantiation_argument(api_instance, "comrade:api/vm", vm_export)
        .unwrap();

    // Alias the "api" export from the API instance
    let api_export = graph
        .alias_instance_export(api_instance, "comrade:api/vm")
        .unwrap();
    // Export the "api" function from the composition
    graph.export(api_export, "comrade:api/api").unwrap();

    // Encode the graph into a WASM binary
    let encoding = graph.encode(EncodeOptions::default()).unwrap();
    std::fs::write("composition.wasm", encoding).unwrap();

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
