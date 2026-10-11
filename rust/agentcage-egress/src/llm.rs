//! The LLM client used by the Policy API decider and the traffic
//! watcher: anthropic, openai and openrouter wire formats, one forced tool
//! call, fail-closed argument parsing.
//!
//! Consumers depend on [`ToolCaller`] only, so the decider and the watcher
//! are tested against a scripted caller and the wire client is tested
//! against recorded request bodies (`tests/fixtures/egress/llm_wire.json`).
//!
//! The wire client, [`LlmClient`], is called **directly from the egress**,
//! never through the proxy's own listeners: the model provider is the
//! operator's, not the cage's, so its traffic is neither inspected nor
//! subject to the cage's allowlist. It is blocking — HTTP through a small
//! [`HttpTransport`] — and callers on the async runtime run it on a
//! blocking worker, the way the replaced implementation ran its client in
//! a thread.
//!
//! Two wire formats:
//!
//! * `anthropic`: `POST {base}/v1/messages`, `x-api-key`,
//!   `anthropic-version: 2023-06-01`, `tool_choice {type: tool}`.
//! * everything else is chat-completions: `POST {base}/v1/chat/completions`
//!   (`openai`) or `{base}/chat/completions` (`openrouter`, whose base
//!   already carries `/api/v1`), Bearer auth, `tool_choice {type:
//!   function}`, `temperature: 0`, and an `X-Title` on OpenRouter.
//!
//! `max_tokens` rides every format: it is the cost and truncation guard,
//! and a guard on one wire format only is not one.

use std::sync::Arc;
use std::time::Duration;

use crate::json::{self, Json, object};

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

// ── Wire format ──────────────────────────────────────────────

/// The `User-Agent` both agents send.
pub const USER_AGENT: &str = "agentcage-policy-api";

/// The `anthropic-version` header value.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// A provider's default base URL, used when the agent block sets no
/// `base_url`. `None` for a provider without one: the caller fails closed
/// (`no llm base url`) rather than guessing.
///
/// OpenRouter's chat-completions endpoint is `/api/v1/chat/completions`,
/// so its base carries the `/api/v1` prefix and the call appends only
/// `/chat/completions`.
#[must_use]
pub fn default_base_url(provider: &str) -> Option<&'static str> {
    match provider {
        "anthropic" => Some("https://api.anthropic.com"),
        "openai" => Some("https://api.openai.com"),
        "openrouter" => Some("https://openrouter.ai/api/v1"),
        _ => None,
    }
}

/// One HTTP request, fully built: what goes on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireRequest {
    /// The absolute URL.
    pub url: String,
    /// Header name/value pairs, in the order they are sent.
    pub headers: Vec<(String, String)>,
    /// The JSON body, byte-for-byte what the replaced implementation sent
    /// (`json.dumps` defaults: `", "` / `": "`, ASCII-escaped).
    pub body: Vec<u8>,
}

/// Build the forced-tool-call request for `provider`.
///
/// `base_url` is used as given (the caller resolves the default and
/// strips a trailing `/`). Any provider other than `anthropic` speaks
/// chat-completions; only `openrouter` gets the bare `/chat/completions`
/// path and the `X-Title` header.
#[must_use]
pub fn build_request(
    provider: &str,
    model: &str,
    api_key: &str,
    base_url: &str,
    call: &ToolCall,
) -> WireRequest {
    let tool = &call.tool;
    let (url, headers, body) = if provider == "anthropic" {
        let headers = vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("x-api-key".to_owned(), api_key.to_owned()),
            ("anthropic-version".to_owned(), ANTHROPIC_VERSION.to_owned()),
            ("User-Agent".to_owned(), USER_AGENT.to_owned()),
        ];
        let body = object([
            ("model", Json::string(model)),
            ("max_tokens", Json::Int(i64::from(call.max_tokens))),
            ("system", Json::string(&call.system)),
            (
                "messages",
                Json::Array(vec![object([
                    ("role", Json::string("user")),
                    ("content", Json::string(&call.user_content)),
                ])]),
            ),
            (
                "tools",
                Json::Array(vec![object([
                    ("name", Json::string(&tool.name)),
                    ("description", Json::string(&tool.description)),
                    ("input_schema", tool.parameters.clone()),
                ])]),
            ),
            (
                "tool_choice",
                object([
                    ("type", Json::string("tool")),
                    ("name", Json::string(&tool.name)),
                ]),
            ),
        ]);
        (format!("{base_url}/v1/messages"), headers, body)
    } else {
        let url = if provider == "openrouter" {
            format!("{base_url}/chat/completions")
        } else {
            format!("{base_url}/v1/chat/completions")
        };
        let mut headers = vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Authorization".to_owned(), format!("Bearer {api_key}")),
            ("User-Agent".to_owned(), USER_AGENT.to_owned()),
        ];
        if provider == "openrouter" {
            // OpenRouter's attribution header; optional but cheap.
            headers.push(("X-Title".to_owned(), USER_AGENT.to_owned()));
        }
        let body = object([
            ("model", Json::string(model)),
            ("max_tokens", Json::Int(i64::from(call.max_tokens))),
            (
                "messages",
                Json::Array(vec![
                    object([
                        ("role", Json::string("system")),
                        ("content", Json::string(&call.system)),
                    ]),
                    object([
                        ("role", Json::string("user")),
                        ("content", Json::string(&call.user_content)),
                    ]),
                ]),
            ),
            (
                "tools",
                Json::Array(vec![object([
                    ("type", Json::string("function")),
                    (
                        "function",
                        object([
                            ("name", Json::string(&tool.name)),
                            ("description", Json::string(&tool.description)),
                            ("parameters", tool.parameters.clone()),
                        ]),
                    ),
                ])]),
            ),
            (
                "tool_choice",
                object([
                    ("type", Json::string("function")),
                    ("function", object([("name", Json::string(&tool.name))])),
                ]),
            ),
            ("temperature", Json::Int(0)),
        ]);
        (url, headers, body)
    };
    WireRequest {
        url,
        headers,
        body: json::to_string(&body).into_bytes(),
    }
}

/// Extract the forced tool call's arguments from a provider reply.
///
/// Fail-closed: `{}` on any parse failure — no tool call, unparseable
/// arguments, a call of a different tool, or a malformed reply. The name
/// check is not cosmetic: a provider (or a body echoed back from inside
/// the cage) that emits a call named something other than the forced tool
/// must not have that call's arguments honoured, or a stray `other` call
/// carrying a grant-shaped `decision` would be applied.
///
/// The replaced implementation raised (rather than returning `{}`) on a
/// few malformed shapes — a reply that is not an object, a `choices`
/// string, a truthy non-object tool call — and its callers then failed
/// closed on the exception. Here every one of them is `{}`, which every
/// caller already treats as "no usable answer". A truthy non-object
/// entry in `tool_calls` ends the scan rather than being skipped, as the
/// exception ended it.
#[must_use]
pub fn parse_tool_args(raw: &Json, provider: &str, tool_name: &str) -> Json {
    let args = if provider == "anthropic" {
        anthropic_args(raw, tool_name)
    } else {
        chat_completions_args(raw, tool_name)
    };
    match args {
        Some(found @ Json::Object(_)) => found,
        _ => Json::Object(Vec::new()),
    }
}

fn anthropic_args(raw: &Json, tool_name: &str) -> Option<Json> {
    let Json::Object(_) = raw else { return None };
    // `raw.get("content", []) or []`; only a list has blocks to look at.
    let Some(Json::Array(blocks)) = raw.get("content") else {
        return None;
    };
    for block in blocks {
        if !matches!(block, Json::Object(_)) {
            continue;
        }
        if block.get("type").and_then(Json::as_str) == Some("tool_use")
            && block.get("name").and_then(Json::as_str) == Some(tool_name)
        {
            // `block.get("input") or {}`.
            return Some(match block.get("input") {
                Some(input) if input.is_truthy() => input.clone(),
                _ => Json::Object(Vec::new()),
            });
        }
    }
    None
}

fn chat_completions_args(raw: &Json, tool_name: &str) -> Option<Json> {
    let Json::Object(_) = raw else { return None };
    // `(raw.get("choices") or [{}])[0]`.
    let choice = match raw.get("choices") {
        Some(choices) if choices.is_truthy() => match choices {
            Json::Array(items) => items.first()?,
            _ => return None,
        },
        _ => return None,
    };
    let Json::Object(_) = choice else { return None };
    let message = match choice.get("message") {
        Some(m) if m.is_truthy() => m,
        _ => return None,
    };
    let Json::Object(_) = message else {
        return None;
    };
    let calls = match message.get("tool_calls") {
        Some(Json::Array(calls)) => calls,
        Some(other) if other.is_truthy() => return None,
        _ => return None,
    };
    for entry in calls {
        // `(tc or {}).get("function") or {}`: a falsy entry is an empty
        // call; a truthy non-object one raised, ending the scan.
        if !entry.is_truthy() {
            continue;
        }
        let Json::Object(_) = entry else { return None };
        let function = match entry.get("function") {
            Some(f) if f.is_truthy() => f,
            _ => continue,
        };
        let Json::Object(_) = function else {
            return None;
        };
        if function.get("name").and_then(Json::as_str) != Some(tool_name) {
            continue;
        }
        // `json.loads(fn.get("arguments", "{}"))`: a string is parsed, a
        // missing key is `{}`, anything else raised TypeError.
        return match function.get("arguments") {
            None => Some(Json::Object(Vec::new())),
            Some(Json::Str(text)) => json::parse(text).ok(),
            Some(_) => None,
        };
    }
    None
}

// ── Transport ────────────────────────────────────────────────

/// A completed HTTP exchange: any status, with its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpReply {
    /// The status code.
    pub status: u16,
    /// The raw response body.
    pub body: Vec<u8>,
}

/// Something that can `POST` a [`WireRequest`]. Injected so the client is
/// tested offline.
pub trait HttpTransport: Send + Sync + std::fmt::Debug {
    /// Send `request` once (no retries) and return whatever status came
    /// back. Redirects are not followed: a `3xx` is returned as is.
    ///
    /// # Errors
    ///
    /// The exchange did not complete (DNS, connect, TLS, timeout, a
    /// broken connection); the string describes it for the operator.
    fn post(&self, request: &WireRequest, timeout: Duration) -> Result<HttpReply, String>;
}

/// The real transport: blocking `ureq` over rustls with the Mozilla roots
/// (`webpki-roots`), no proxy, no redirects, no retries.
///
/// The timeout bounds each phase of the exchange (resolve, connect, send,
/// await the response, read the body) separately, the closest match to
/// the replaced implementation's per-socket-operation timeout: a provider
/// that trickles a long reply is not cut off mid-body for being slow
/// overall, but one that goes silent is. The proxy environment variables
/// are deliberately ignored — the call leaves the egress directly.
#[derive(Debug, Default, Clone, Copy)]
pub struct UreqTransport;

impl HttpTransport for UreqTransport {
    fn post(&self, request: &WireRequest, timeout: Duration) -> Result<HttpReply, String> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .user_agent(ureq::config::AutoHeaderValue::None)
            .timeout_resolve(Some(timeout))
            .timeout_connect(Some(timeout))
            .timeout_send_request(Some(timeout))
            .timeout_send_body(Some(timeout))
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(Some(timeout))
            .build()
            .into();
        let mut builder = agent.post(&request.url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let mut response = builder.send(&request.body[..]).map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            // Generous for a tool-call reply; a provider that streams
            // more than this is not answering the question asked.
            .limit(16 * 1024 * 1024)
            .read_to_vec()
            .map_err(|e| e.to_string())?;
        Ok(HttpReply { status, body })
    }
}

// ── The client ───────────────────────────────────────────────

/// One configured LLM agent: provider, model, key, base URL, timeout.
///
/// Built from the agent block on every config (re)load, so a re-staged key
/// is picked up by building a new one.
#[derive(Clone)]
pub struct LlmClient {
    /// Lowercased provider name.
    pub provider: String,
    /// Model id.
    pub model: String,
    api_key: String,
    /// Resolved base URL, without a trailing `/`.
    pub base_url: String,
    /// Per-phase timeout (see [`UreqTransport`]).
    pub timeout: Duration,
    transport: Arc<dyn HttpTransport>,
}

impl std::fmt::Debug for LlmClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key is a credential: never in a Debug rendering.
        f.debug_struct("LlmClient")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl LlmClient {
    /// A client over `transport`. `base_url` is used as given.
    #[must_use]
    pub fn new(
        provider: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
        base_url: impl Into<String>,
        timeout: Duration,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            api_key: api_key.into(),
            base_url: base_url.into(),
            timeout,
            transport,
        }
    }

    /// `text` with the client's key replaced by `[redacted]`.
    fn without_key(&self, text: &str) -> String {
        if self.api_key.is_empty() {
            text.to_owned()
        } else {
            text.replace(&self.api_key, "[redacted]")
        }
    }
}

impl ToolCaller for LlmClient {
    fn call(&self, call: &ToolCall) -> Result<Json, LlmError> {
        let request = build_request(
            &self.provider,
            &self.model,
            &self.api_key,
            &self.base_url,
            call,
        );
        let reply = self
            .transport
            .post(&request, self.timeout)
            .map_err(|e| LlmError {
                message: self.without_key(&format!("llm error: {e}")),
            })?;
        if !(200..300).contains(&reply.status) {
            return Err(LlmError {
                message: status_error_message(reply.status, &reply.body, &self.api_key),
            });
        }
        let text = String::from_utf8_lossy(&reply.body);
        let raw = json::parse(&text).map_err(|e| LlmError {
            message: self.without_key(&format!("llm error: {e}")),
        })?;
        Ok(parse_tool_args(&raw, &self.provider, &call.tool.name))
    }
}

/// The operator-facing message for a non-2xx reply:
/// `llm http <status>: <repr of the first 200 body bytes>`, with the key
/// cut out of the body **before** truncating so no prefix of it survives.
///
/// This text is for the audit log only. The caged agent sees
/// [`agent_facing`] of it, which drops the provider's body: the body is
/// the provider's, can quote anything the request carried, and is no
/// business of the cage.
#[must_use]
pub fn status_error_message(status: u16, body: &[u8], api_key: &str) -> String {
    let body = if api_key.is_empty() {
        body.to_vec()
    } else {
        replace_bytes(body, api_key.as_bytes(), b"[redacted]")
    };
    let cut = &body[..body.len().min(200)];
    format!("llm http {status}: {}", python_bytes_repr(cut))
}

/// The part of an [`LlmError`] message the caged agent may see.
///
/// `llm http 401: b'…'` becomes `llm http 401`; any other message is
/// returned unchanged (transport and decode errors carry no provider
/// content).
#[must_use]
pub fn agent_facing(message: &str) -> &str {
    if let Some(rest) = message.strip_prefix("llm http ")
        && let Some(end) = rest.find(": ")
        && rest[..end].bytes().all(|b| b.is_ascii_digit())
    {
        return &message[.."llm http ".len() + end];
    }
    message
}

fn replace_bytes(haystack: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

/// CPython's `repr(bytes)`: `b'…'`, switching to double quotes when the
/// bytes hold a `'` and no `"`.
#[must_use]
pub fn python_bytes_repr(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::with_capacity(bytes.len() + 3);
    out.push('b');
    out.push(char::from(quote));
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if b == quote => {
                out.push('\\');
                out.push(char::from(b));
            }
            0x20..=0x7e => out.push(char::from(b)),
            _ => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out.push(char::from(quote));
    out
}

#[cfg(test)]
mod tests;
