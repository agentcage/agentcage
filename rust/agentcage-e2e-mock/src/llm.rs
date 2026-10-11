//! The stub LLM: plain HTTP, the Anthropic `/v1/messages` forced-tool-call
//! shape, for the domain decider (`decide`) and the traffic watcher
//! (`review`).
//!
//! Every call is appended to `llm.jsonl` as
//! `{"path": ..., "tool": ..., "x_api_key": ..., "domain": ...}`, so the
//! phase can show the egress injected the real key (9.13) and that the
//! never-grant floor answered without a call (9.17).

use std::io::{self, BufReader};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::http::{self, Head};
use crate::log::LogDir;
use crate::pyjson;

/// Default listen address (loopback in the egress's namespace).
pub const ADDR: &str = "127.0.0.1:18089";

/// The tool name forced by `tool_choice`, or `""`.
fn tool_name(request: &Value) -> &str {
    request
        .get("tool_choice")
        .and_then(|c| c.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// `domain_requested` from the decider's prompt, which is a JSON document
/// carried as the first message's string content; `""` otherwise.
fn requested_domain(request: &Value) -> String {
    request
        .pointer("/messages/0/content")
        .and_then(Value::as_str)
        .and_then(|c| serde_json::from_str::<Value>(c).ok())
        .and_then(|p| {
            p.get("domain_requested")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// The tool input the stub answers with.
#[derive(Serialize)]
#[serde(untagged)]
enum ToolInput {
    Decide {
        decision: &'static str,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl_seconds: Option<u32>,
    },
    Review {
        findings: [Finding; 1],
        allowlist_removals: Vec<Value>,
        baseline_recommendations: Vec<Value>,
    },
    /// Any other tool: `{}`.
    Empty {},
}

#[derive(Serialize)]
struct Finding {
    severity: &'static str,
    title: &'static str,
    detail: &'static str,
    recommendation: &'static str,
}

/// The decider grants any domain for 600 s unless its name contains
/// "deny"; the watcher reports one fixed low-severity finding.
fn tool_input(tool: &str, domain: &str) -> ToolInput {
    match tool {
        "decide" if domain.contains("deny") => ToolInput::Decide {
            decision: "deny",
            reason: format!("stub denies {domain}"),
            ttl_seconds: None,
        },
        "decide" => ToolInput::Decide {
            decision: "grant",
            reason: format!("stub grants {domain}"),
            ttl_seconds: Some(600),
        },
        "review" => ToolInput::Review {
            findings: [Finding {
                severity: "low",
                title: "e2e stub finding",
                detail: "the e2e stub LLM reviewed this window",
                recommendation: "none, this is a test",
            }],
            allowlist_removals: Vec::new(),
            baseline_recommendations: Vec::new(),
        },
        _ => ToolInput::Empty {},
    }
}

/// One `llm.jsonl` record.
#[derive(Serialize)]
struct Call<'a> {
    path: &'a str,
    tool: &'a str,
    x_api_key: &'a str,
    domain: &'a str,
}

/// A `/v1/messages` response whose only content block is the tool call.
#[derive(Serialize)]
struct Message<'a> {
    id: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    role: &'static str,
    model: Value,
    stop_reason: &'static str,
    content: [ToolUse<'a>; 1],
    usage: Usage,
}

#[derive(Serialize)]
struct ToolUse<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    id: &'static str,
    name: &'a str,
    input: ToolInput,
}

#[derive(Serialize)]
struct Usage {
    input_tokens: u32,
    output_tokens: u32,
}

/// The response body for one request body, plus the `llm.jsonl` line.
#[must_use]
pub fn answer(path: &str, api_key: &str, body: &[u8]) -> (String, String) {
    let request: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let tool = tool_name(&request);
    let domain = requested_domain(&request);
    let log_line = pyjson::dumps(&Call {
        path,
        tool,
        x_api_key: api_key,
        domain: &domain,
    });
    let response = pyjson::dumps(&Message {
        id: "msg_e2e",
        kind: "message",
        role: "assistant",
        model: request
            .get("model")
            .cloned()
            .unwrap_or_else(|| Value::from("")),
        stop_reason: "tool_use",
        content: [ToolUse {
            kind: "tool_use",
            id: "toolu_e2e",
            name: tool,
            input: tool_input(tool, &domain),
        }],
        usage: Usage {
            input_tokens: 1,
            output_tokens: 1,
        },
    });
    (response, log_line)
}

/// Serve one connection.
///
/// # Errors
/// On I/O errors; the caller drops the connection.
pub fn handle(stream: TcpStream, log: &Arc<LogDir>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let request = match http::read_head(&mut reader)? {
        Head::Request(r) => r,
        Head::Eof => return Ok(()),
        Head::Malformed => {
            return http::write_response(
                &mut writer,
                400,
                "Bad Request",
                "text/plain",
                b"bad request\n",
            );
        }
    };
    let body = http::read_body(&mut reader, &request)?;
    if request.method != "POST" {
        return http::write_response(
            &mut writer,
            501,
            "Not Implemented",
            "text/plain",
            b"POST only\n",
        );
    }
    let (response, log_line) = answer(
        &request.target,
        request.header("x-api-key").unwrap_or(""),
        &body,
    );
    log.append("llm.jsonl", &log_line);
    http::write_response(
        &mut writer,
        200,
        "OK",
        "application/json",
        response.as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::answer;
    use serde_json::{Value, json};

    fn decide(domain: &str) -> Vec<u8> {
        let prompt = json!({"domain_requested": domain, "reason": "r"}).to_string();
        json!({
            "model": "m",
            "tool_choice": {"type": "tool", "name": "decide"},
            "messages": [{"role": "user", "content": prompt}],
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn decider_grants_and_denies() {
        let (resp, log) = answer("/v1/messages", "k1", &decide("example.net"));
        assert_eq!(
            log,
            r#"{"path": "/v1/messages", "tool": "decide", "x_api_key": "k1", "domain": "example.net"}"#
        );
        let resp: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(resp["model"], "m");
        assert_eq!(resp["stop_reason"], "tool_use");
        assert_eq!(
            resp["content"][0]["input"],
            json!({"decision": "grant", "reason": "stub grants example.net", "ttl_seconds": 600})
        );
        let (resp, _) = answer("/v1/messages", "k1", &decide("deny.example.org"));
        let resp: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            resp["content"][0]["input"],
            json!({"decision": "deny", "reason": "stub denies deny.example.org"})
        );
    }

    #[test]
    fn watcher_and_garbage() {
        let body =
            json!({"tool_choice": {"name": "review"}, "messages": [{"content": "not json"}]});
        let (resp, log) = answer("/v1/messages", "", body.to_string().as_bytes());
        assert!(log.contains(r#""tool": "review""#) && log.contains(r#""domain": """#));
        let resp: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            resp["content"][0]["input"]["findings"][0]["title"],
            "e2e stub finding"
        );
        let (resp, _) = answer("/", "", b"{nope");
        let resp: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            (&resp["model"], &resp["content"][0]["input"]),
            (&json!(""), &json!({}))
        );
    }
}
