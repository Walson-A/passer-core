//! What travels between devices for a call.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One invocation, as the caller sends it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// Name of the capability to invoke.
    pub capability: String,
    /// What the capability acts on, required exactly when it declares a `target_kind`.
    /// At most [`MAX_TARGET_LEN`](crate::MAX_TARGET_LEN) bytes, no control characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Checked against the capability's input schema. `null` when absent.
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
    /// A call request with no target and no agent.
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

/// Why a request failed. Sent on the wire in `snake_case`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The requester is not, or no longer, a member of the group.
    NotMember,
    /// No such capability on the target device.
    UnknownCapability,
    /// Bad target, agent name or input (schema mismatch, or refused by the module).
    InvalidInput,
    /// The policy denied it, or a human refused.
    Denied,
    /// Nobody answered the approval request within [`APPROVAL_TIMEOUT`](crate::APPROVAL_TIMEOUT).
    ApprovalTimeout,
    /// The capability needs a visible indicator and the device cannot show one.
    NoIndicator,
    /// The lease expired or was revoked while the capability ran.
    Interrupted,
    /// Not possible here, or opened in the wrong mode (call vs. stream).
    Unsupported,
    /// The module failed.
    ModuleError,
    /// A message exceeded a size limit.
    TooLarge,
    /// The request frame could not be read (malformed or too large).
    Protocol,
}

impl ErrorCode {
    /// The wire name, as written in responses and the journal.
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

/// The answer to a [`Request`]. On the wire, `status` is `ok` or `error`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// The request succeeded.
    Ok {
        /// What the capability returned, or the [`Response::stream_open`] marker.
        output: Value,
    },
    /// The request was refused or failed.
    Error {
        /// What kind of failure.
        code: ErrorCode,
        /// Human-readable detail.
        message: String,
    },
}

impl Response {
    /// The first frame of an accepted stream: the target ran every check, the bytes can
    /// flow. The stream's own result comes as a last frame once it ends.
    pub fn stream_open() -> Self {
        Response::Ok {
            output: serde_json::json!({ "stream": "open" }),
        }
    }

    /// Whether this is the frame [`Response::stream_open`] makes.
    pub fn is_stream_open(&self) -> bool {
        matches!(self, Response::Ok { output } if output.get("stream").and_then(Value::as_str) == Some("open"))
    }

    /// An error response.
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Response::Error {
            code,
            message: message.into(),
        }
    }

    /// The error code, `None` on success.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Response::Ok { .. } => None,
            Response::Error { code, .. } => Some(*code),
        }
    }
}
