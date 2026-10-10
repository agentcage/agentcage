//! The LLM client used by the Policy API decider and the traffic
//! watcher: anthropic, openai and openrouter wire formats, one forced tool
//! call, fail-closed argument parsing.
//!
//! Consumers depend on [`ToolCaller`] only, so the decider and the watcher
//! are tested against a scripted caller and the wire client is tested
//! against recorded request bodies (`tests/fixtures/egress/llm_wire.json`).

use crate::json::Json;

/// The forced tool, provider-neutral: `{name, description, parameters}`.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolSpec {
    /// Tool name; a reply calling any other tool is ignored.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// JSON Schema of the arguments.
    pub parameters: Json,
}

/// One forced-tool-call request.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolCall {
    /// The system prompt.
    pub system: String,
    /// The single user message.
    pub user_content: String,
    /// The tool the model must call.
    pub tool: ToolSpec,
    /// `max_tokens`, sent on every wire format.
    pub max_tokens: u32,
}

/// Why a call produced no arguments at all.
///
/// A reply that arrives but carries no usable tool call is *not* an error:
/// it parses to an empty object, and the consumer fails closed on that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LlmError {
    /// Operator-facing description. Never echoed to the caged agent.
    pub message: String,
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LlmError {}

/// Something that performs one forced tool call for a configured agent
/// (provider, model, key, base URL and timeout are the implementor's).
pub trait ToolCaller: Send + Sync + std::fmt::Debug {
    /// Make the call and return the tool's arguments as a JSON object —
    /// `{}` when the reply has no usable call of `call.tool.name`.
    ///
    /// # Errors
    ///
    /// Transport failure, timeout, non-2xx status or an unparseable body.
    fn call(&self, call: &ToolCall) -> Result<Json, LlmError>;
}
