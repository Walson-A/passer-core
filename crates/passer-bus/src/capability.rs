//! What a module declares. The shape mirrors an MCP tool on purpose, so that the MCP
//! bridge is a near-mechanical translation.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How much an invocation can do. Drives the default policy and the MCP annotations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Reads non-sensitive data (device name, battery).
    Read,
    /// Changes something on the target (drops a file, sets the clipboard).
    Write,
    /// Reads or controls something private (clipboard content, screen, input).
    Sensitive,
}

/// Request-response, or a long-lived stream (file transfer, video).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Answers once.
    Call,
    /// Exchanges bytes both ways for as long as the lease lives.
    Stream,
}

/// Whether the target must show a visible indicator while the capability runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorRequirement {
    /// No indicator needed.
    #[default]
    None,
    /// Runs only on a device with an [`Indicator`](crate::Indicator) installed, shown for
    /// the whole lease.
    Required,
}

/// One thing a device can do for another.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Capability {
    /// Dotted name, e.g. `device.info`, `transfer.drop`, `screen.view`.
    pub name: String,
    /// Short human-readable name.
    pub title: String,
    /// What it does, for people and AI agents.
    pub description: String,
    /// JSON Schema, validated on the target before anything runs.
    pub input_schema: Value,
    /// JSON Schema of the output, if declared. The bus does not check it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// How much it can do. Drives the default policy and the lease cap.
    pub effect: Effect,
    /// Call or stream. A request only runs in the mode declared here.
    pub mode: Mode,
    /// Kind of target the capability acts on (e.g. `app` for the screen module).
    /// Policies can then differ per target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<String>,
    /// Whether a visible indicator must be shown while it runs.
    #[serde(default)]
    pub indicator: IndicatorRequirement,
}

impl Capability {
    /// A call capability with an object input schema and no target.
    pub fn call(
        name: &str,
        title: &str,
        description: &str,
        effect: Effect,
        input_schema: Value,
    ) -> Self {
        Self {
            name: name.to_owned(),
            title: title.to_owned(),
            description: description.to_owned(),
            input_schema,
            output_schema: None,
            effect,
            mode: Mode::Call,
            target_kind: None,
            indicator: IndicatorRequirement::None,
        }
    }
}

/// Everything a module offers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Name of the module.
    pub module: String,
    /// Version of the module.
    pub version: String,
    /// The capabilities it serves.
    pub capabilities: Vec<Capability>,
}

/// Checks a capability name: lowercase dotted segments, no wildcard.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 96
        && name.split('.').all(|seg| {
            !seg.is_empty()
                && seg
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        })
}
