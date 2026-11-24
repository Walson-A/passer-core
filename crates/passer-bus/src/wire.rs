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
    /// The caller opens a stream, not a call. A capability only runs in the mode it
    /// declares, so a call can never turn into a stream the caller did not expect.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stream: bool,
}

impl Request {
    pub fn new(capability: &str, input: Value) -> Self {
        Self {
            capability: capability.to_owned(),
            target: None,
            input,
            agent: None,
            stream: false,
        }
    }

    /// A request that opens a stream capability.
    pub fn stream(capability: &str, input: Value) -> Self {
        Self {
            stream: true,
            ..Self::new(capability, input)
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
    /// The first frame of an accepted stream: the target ran every check, the bytes can
    /// flow. The stream's own result comes as a last frame once it ends.
    pub fn stream_open() -> Self {
        Response::Ok {
            output: serde_json::json!({ "stream": "open" }),
        }
    }

    pub fn is_stream_open(&self) -> bool {
        matches!(self, Response::Ok { output } if output.get("stream").and_then(Value::as_str) == Some("open"))
    }

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
