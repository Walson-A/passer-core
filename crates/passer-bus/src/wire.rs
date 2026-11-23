//! What travels between devices for a call.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub input: Value,
    /// Set by a bridge (MCP) when it relays an AI agent. Lowers privileges by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

impl Request {
    pub fn new(capability: &str, input: Value) -> Self {
        Self {
            capability: capability.to_owned(),
            target: None,
            input,
            agent: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotMember,
    UnknownCapability,
    InvalidInput,
    Denied,
    ApprovalTimeout,
    NoIndicator,
    Interrupted,
    Unsupported,
    ModuleError,
    TooLarge,
    Protocol,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotMember => "not_member",
            ErrorCode::UnknownCapability => "unknown_capability",
            ErrorCode::InvalidInput => "invalid_input",
            ErrorCode::Denied => "denied",
            ErrorCode::ApprovalTimeout => "approval_timeout",
            ErrorCode::NoIndicator => "no_indicator",
            ErrorCode::Interrupted => "interrupted",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::ModuleError => "module_error",
            ErrorCode::TooLarge => "too_large",
            ErrorCode::Protocol => "protocol",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok { output: Value },
    Error { code: ErrorCode, message: String },
}

impl Response {
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Response::Error {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Response::Ok { .. } => None,
            Response::Error { code, .. } => Some(*code),
        }
    }
}
