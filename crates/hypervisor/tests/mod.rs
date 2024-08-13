//! Test module

mod bindgen {
    wasmtime::component::bindgen!();
}

use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

struct MyCtx {
    table: ResourceTable,
    ctx: WasiCtx,
}

impl WasiView for MyCtx {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.ctx
    }
}

#[cfg(test)]
mod test_hypervisor {
    use super::*;
    use crate::bindgen;
    use fusion::Fusion;
    use std::{
        error::Error,
        path::{Path, PathBuf},
    };

    /// Utility function to get the workspace dir
    fn workspace_dir() -> PathBuf {
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

    fn load(profile: &str) -> Result<(PathBuf, Config), Box<dyn Error>> {
        let pkg_name = std::env::var("CARGO_PKG_NAME")?.replace('-', "_");
        let workspace = workspace_dir();
        let wasm_path = format!("target/wasm32-wasi/{profile}/{pkg_name}.wasm");
        let wasm_path = workspace.join(wasm_path);

        let mut config = Config::new();
        config.cache_config_load_default()?;
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
        config.wasm_component_model(true);

        Ok((wasm_path, config))
    }
    #[test]
    fn test_composition() -> Result<(), Box<dyn Error>> {
        let (wasm, config) = load("debug")?;

        let engine = Engine::new(&config)?;
        let component = Component::from_file(&engine, &wasm)?;
        //let mut linker = Linker::new(&engine);

        Ok(())
    }
}
