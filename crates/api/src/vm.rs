use crate::bindings::comrade::api::utils::log;

pub(crate) struct Vm {
    script: Option<String>,
}

impl Vm {
    pub fn new() -> Self {
        log("Creating new VM");
        Self { script: None }
    }

    pub fn run(&self, script: &String) -> Result<bool, String> {
        log("Running unlock script");

        Ok(true)
    }
}
