//! The smallest useful module, and the template for writing one.
//!
//! It declares a single read capability, `device.info`, and answers with the device's
//! name, platform and software version. Everything else (who may call it, journaling,
//! sessions) is the bus's job: a module only describes and does.

use async_trait::async_trait;
use passer_bus::{Capability, Ctx, Effect, Manifest, Module, ModuleError};
use serde_json::{Value, json};

pub const CAPABILITY: &str = "device.info";

/// Describes this device.
pub struct DeviceInfo {
    name: String,
}

impl DeviceInfo {
    /// `name` is the device name shown to the user (as recorded in the group).
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl Module for DeviceInfo {
    fn manifest(&self) -> Manifest {
        let mut cap = Capability::call(
            CAPABILITY,
            "Device info",
            "Returns the device's name, operating system, architecture and passer-core version.",
            Effect::Read,
            json!({ "type": "object", "additionalProperties": false }),
        );
        cap.output_schema = Some(json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "os": { "type": "string" },
                "arch": { "type": "string" },
                "version": { "type": "string" }
            },
            "required": ["name", "os", "arch", "version"]
        }));
        Manifest {
            module: "device-info".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            capabilities: vec![cap],
        }
    }

    async fn invoke(
        &self,
        _ctx: Ctx,
        capability: &str,
        _input: Value,
    ) -> Result<Value, ModuleError> {
        match capability {
            CAPABILITY => Ok(json!({
                "name": self.name,
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "version": env!("CARGO_PKG_VERSION"),
            })),
            other => Err(ModuleError::Unsupported(other.to_owned())),
        }
    }
}
