//! # Fusion
//!
//! Take a lock and unlock script and feed them into the hypervisor.

use wac_graph::{types::Package, CompositionGraph, EncodeOptions, NodeId, PackageId};

/// Fusion is a composition struct that takes in lock and unlock scripts and
/// feeds them into the hypervisor.
pub struct Fusion {
    graph: CompositionGraph,
}

impl Default for Fusion {
    fn default() -> Self {
        Self::new()
    }
}

impl Fusion {
    /// Creates a new [Fusion] instance.
    pub fn new() -> Self {
        Self {
            graph: CompositionGraph::new(),
        }
    }

    /// Registers bytes in the Fusion graph.
    pub fn register(
        &mut self,
        name: &str,
        bytes: &[u8],
    ) -> Result<PackageId, Box<dyn std::error::Error>> {
        let version = None;
        let package = Package::from_bytes(name, version, bytes, self.graph.types_mut())?;
        Ok(self.graph.register_package(package)?)
    }

    /// Instantiates a package in the Fusion graph.
    pub fn instantiate(&mut self, package_id: PackageId) -> NodeId {
        self.graph.instantiate(package_id)
    }

    /// Sets the argument of the given instance in the graph
    pub fn set_argument(
        &mut self,
        importer_instance: NodeId,
        importee_instance: NodeId,
        alias: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let named_export = self.graph.alias_instance_export(importee_instance, alias)?;
        self.graph
            .set_instantiation_argument(importer_instance, alias, named_export)?;
        Ok(())
    }

    /// Exports an alias from the given instance in the wac_graph
    pub fn export_alias(
        &mut self,
        instance: NodeId,
        alias: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // alias the export from the instance
        let named_export = self.graph.alias_instance_export(instance, alias)?;
        // export the alias from the instance
        self.graph.export(named_export, alias)?;
        Ok(())
    }

    /// Encodes the Fused components into a binary format.
    pub fn encode(&self, options: EncodeOptions) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.graph.encode(options)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
