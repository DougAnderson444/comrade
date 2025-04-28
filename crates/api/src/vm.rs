use crate::{bindings::comrade::api::utils::log, context::Context};

pub(crate) struct Vm {
    script: Option<String>,
    context: Context,
}

impl Vm {
    pub fn new() -> Self {
        log("Creating new VM");
        Self {
            script: None,
            context: Context::new(),
        }
    }

    pub fn run(&mut self, script: &String) -> Result<bool, String> {
        log("Running unlock script");

        let result = self.context.run(script).map_err(|e| {
            log(&format!("Error running unlock script: {}", e));
            format!("Error running unlock script: {}", e)
        })?;

        Ok(result)
    }
}
