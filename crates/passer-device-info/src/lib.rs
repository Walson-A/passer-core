//! The smallest useful module, and the template for writing one.
//!
//! It declares a single read capability, `device.info`, and answers with the device's
//! name, kind, platform and software versions. Everything else (who may call it,
//! journaling, sessions) is the bus's job: a module only describes and does.

#![warn(missing_docs)]

use async_trait::async_trait;
use passer_bus::{Capability, Ctx, Effect, Manifest, Module, ModuleError};
use serde_json::{Map, Value, json};

/// The capability's name.
pub const CAPABILITY: &str = "device.info";

/// What sort of device this is, as the app knows it. The core cannot tell a laptop from
/// a desktop, or a phone from a tablet: the app says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DeviceKind {
    /// A phone.
    Phone,
    /// A tablet.
    Tablet,
    /// A laptop.
    Laptop,
    /// A desktop computer.
    Desktop,
    /// Not said, or a kind this version does not know.
    #[default]
    Unknown,
}

impl DeviceKind {
    /// The name sent in `device.info`: `phone`, `tablet`, `laptop`, `desktop`, `unknown`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Phone => "phone",
            Self::Tablet => "tablet",
            Self::Laptop => "laptop",
            Self::Desktop => "desktop",
            Self::Unknown => "unknown",
        }
    }

    /// Reads what another device said; anything unexpected is `Unknown`.
    pub fn parse(s: &str) -> Self {
        match s {
            "phone" => Self::Phone,
            "tablet" => Self::Tablet,
            "laptop" => Self::Laptop,
            "desktop" => Self::Desktop,
            _ => Self::Unknown,
        }
    }
}

/// What the app adds to the description: the core only knows the OS family.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Details {
    /// What sort of device this is.
    pub kind: DeviceKind,
    /// e.g. `17.4` on iOS, `10.0.26100` on Windows.
    pub os_version: Option<String>,
    /// The version of the app hosting passer-core.
    pub app_version: Option<String>,
}

/// Describes this device.
pub struct DeviceInfo {
    name: String,
    details: Details,
}

impl DeviceInfo {
    /// `name` is the device name shown to the user (as recorded in the group).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            details: Details::default(),
        }
    }

    /// Adds what the app knows about the device (kind, OS and app versions).
    pub fn with_details(mut self, details: Details) -> Self {
        self.details = details;
        self
    }

    /// The answer to `device.info`.
    pub fn describe(&self) -> Value {
        let mut out = Map::new();
        out.insert("name".into(), json!(self.name));
        out.insert("kind".into(), json!(self.details.kind.as_str()));
        out.insert("os".into(), json!(std::env::consts::OS));
        out.insert("arch".into(), json!(std::env::consts::ARCH));
        out.insert("version".into(), json!(env!("CARGO_PKG_VERSION")));
        if let Some(v) = &self.details.os_version {
            out.insert("os_version".into(), json!(v));
        }
        if let Some(v) = &self.details.app_version {
            out.insert("app_version".into(), json!(v));
        }
        Value::Object(out)
    }
}

#[async_trait]
impl Module for DeviceInfo {
    fn manifest(&self) -> Manifest {
        let mut cap = Capability::call(
            CAPABILITY,
            "Device info",
            "Returns the device's name, kind (phone, tablet, laptop, desktop), operating \
             system and version, architecture, and the versions of passer-core and of the app.",
            Effect::Read,
            json!({ "type": "object", "additionalProperties": false }),
        );
        cap.output_schema = Some(json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "kind": { "enum": ["phone", "tablet", "laptop", "desktop", "unknown"] },
                "os": { "type": "string" },
                "os_version": { "type": "string" },
                "arch": { "type": "string" },
                "version": { "type": "string", "description": "passer-core version" },
                "app_version": { "type": "string" }
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
            CAPABILITY => Ok(self.describe()),
            other => Err(ModuleError::Unsupported(other.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_kind_and_versions() {
        let info = DeviceInfo::new("WALSON-HP").with_details(Details {
            kind: DeviceKind::Laptop,
            os_version: Some("10.0.26100".into()),
            app_version: None,
        });
        let v = info.describe();
        assert_eq!(v["kind"], "laptop");
        assert_eq!(v["os_version"], "10.0.26100");
        assert!(v.get("app_version").is_none());
        assert_eq!(DeviceKind::parse("tablet"), DeviceKind::Tablet);
        assert_eq!(DeviceKind::parse("toaster"), DeviceKind::Unknown);
    }
}
