use super::*;
use std::sync::Mutex;

fn corpus() -> Json {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/egress/llm_wire.json"
    );
    let text = std::fs::read_to_string(path).expect("llm_wire.json is readable");
    json::parse(&text).expect("llm_wire.json parses")
}

fn cases() -> Vec<Json> {
    match corpus().get("cases") {
        Some(Json::Array(cases)) => cases.clone(),
        _ => panic!("llm_wire.json has no cases"),
    }
}

fn s<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("missing string {key}"))
}

fn tool_from(value: &Json) -> ToolSpec {
    ToolSpec {
        name: s(value, "name").to_owned(),
        description: s(value, "description").to_owned(),
        parameters: value.get("parameters").cloned().unwrap(),
    }
}

/// `NaN != NaN`; compare rendered JSON instead.
fn same(a: &Json, b: &Json) -> bool {
    json::to_string(a) == json::to_string(b)
}

fn run_request(input: &Json) -> (String, Vec<(String, String)>, String) {
    let Some(Json::Int(max_tokens)) = input.get("max_tokens") else {
        panic!("max_tokens")
    };
    let call = ToolCall {
        system: s(input, "system").to_owned(),
        user_content: s(input, "user_content").to_owned(),
        tool: tool_from(input.get("tool").unwrap()),
        max_tokens: u32::try_from(*max_tokens).unwrap(),
    };
    let req = build_request(
        s(input, "provider"),
        s(input, "model"),
        s(input, "api_key"),
        s(input, "base_url"),
        &call,
    );
    (req.url, req.headers, String::from_utf8(req.body).unwrap())
}

#[test]
fn every_recorded_case_is_reproduced() {
    let mut checked = 0;
    for case in cases() {
        let id = s(&case, "id").to_owned();
        let input = case.get("input").unwrap();
        let expected = case.get("expected").unwrap();
        match s(&case, "kind") {
            "request" => {
                let (url, headers, body) = run_request(input);
                assert_eq!(s(expected, "method"), "POST", "{id}");
                assert_eq!(url, s(expected, "url"), "{id}: url");
                assert_eq!(body, s(expected, "body"), "{id}: body bytes");
                let Some(Json::Array(want)) = expected.get("headers") else {
                    panic!("{id}: headers")
                };
                let want: Vec<(String, String)> = want
                    .iter()
                    .map(|pair| match pair {
                        Json::Array(kv) => (
                            kv[0].as_str().unwrap().to_ascii_lowercase(),
                            kv[1].as_str().unwrap().to_owned(),
                        ),
                        _ => panic!("{id}: header pair"),
                    })
                    .collect();
                let got: Vec<(String, String)> = headers
                    .into_iter()
                    .map(|(k, v)| (k.to_ascii_lowercase(), v))
                    .collect();
                assert_eq!(got, want, "{id}: headers");
            }
            "parse" => {
                let got = parse_tool_args(
                    input.get("raw").unwrap(),
                    s(input, "provider"),
                    s(input, "tool_name"),
                );
                // Where the Python raised, the port answers `{}`: both
                // are "no usable tool call" to every caller.
                let want = expected
                    .get("args")
                    .cloned()
                    .unwrap_or(Json::Object(Vec::new()));
                assert!(
                    same(&got, &want),
                    "{id}: got {}, want {}",
                    json::to_string(&got),
                    json::to_string(&want)
                );
            }
            other => panic!("{id}: unknown kind {other}"),
        }
        checked += 1;
    }
    assert!(checked >= 40, "only {checked} cases");
}

#[test]
fn a_wrong_expectation_is_caught() {
    // Mutation sanity check: the comparison bites on one byte.
    let case = cases()
        .into_iter()
        .find(|c| s(c, "kind") == "request")
        .unwrap();
    let (_, _, body) = run_request(case.get("input").unwrap());
    let mutated = s(case.get("expected").unwrap(), "body").replacen("\": ", "\":", 1);
    assert_ne!(body, mutated);
}

// ── the client over a scripted transport ──────────────────────

#[derive(Debug)]
struct Scripted {
    reply: Result<HttpReply, String>,
    seen: Mutex<Vec<(WireRequest, Duration)>>,
}

impl Scripted {
    fn new(reply: Result<HttpReply, String>) -> Arc<Self> {
        Arc::new(Self {
            reply,
            seen: Mutex::new(Vec::new()),
        })
    }
}

impl HttpTransport for Scripted {
    fn post(&self, request: &WireRequest, timeout: Duration) -> Result<HttpReply, String> {
        self.seen.lock().unwrap().push((request.clone(), timeout));
        self.reply.clone()
    }
}

const KEY: &str = "sk-or-FAKE-DECIDER-KEY-0123456789";

fn decide_call() -> ToolCall {
    ToolCall {
        system: "sys".into(),
        user_content: "{}".into(),
        tool: ToolSpec {
            name: "decide".into(),
            description: "d".into(),
            parameters: json::object([("type", Json::string("object"))]),
        },
        max_tokens: 1024,
    }
}

fn client(transport: Arc<Scripted>) -> LlmClient {
    LlmClient::new(
        "openrouter",
        "m",
        KEY,
        "https://openrouter.ai/api/v1",
        Duration::from_secs(15),
        transport,
    )
}

#[test]
fn a_good_reply_yields_the_tool_arguments() {
    let body = br#"{"choices": [{"message": {"tool_calls": [{"function": {"name": "decide", "arguments": "{\"decision\": \"grant\"}"}}]}}]}"#;
    let transport = Scripted::new(Ok(HttpReply {
        status: 200,
        body: body.to_vec(),
    }));
    let args = client(transport.clone()).call(&decide_call()).unwrap();
    assert_eq!(json::to_string(&args), r#"{"decision": "grant"}"#);
    let seen = transport.seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "exactly one attempt, no retries");
    assert_eq!(seen[0].1, Duration::from_secs(15));
    assert_eq!(
        seen[0].0.url,
        "https://openrouter.ai/api/v1/chat/completions"
    );
}

#[test]
fn a_reply_without_the_tool_is_an_empty_object_not_an_error() {
    let transport = Scripted::new(Ok(HttpReply {
        status: 200,
        body: br#"{"choices": [{"message": {"content": "prose"}}]}"#.to_vec(),
    }));
    let args = client(transport).call(&decide_call()).unwrap();
    assert_eq!(args, Json::Object(Vec::new()));
}

#[test]
fn a_provider_error_body_is_redacted_for_the_operator_and_cut_for_the_cage() {
    let body = format!(r#"{{"error": "invalid key {KEY}"}}"#);
    let transport = Scripted::new(Ok(HttpReply {
        status: 401,
        body: body.into_bytes(),
    }));
    let err = client(transport).call(&decide_call()).unwrap_err();
    assert_eq!(
        err.message,
        r#"llm http 401: b'{"error": "invalid key [redacted]"}'"#
    );
    assert!(!err.message.contains(KEY));
    assert_eq!(agent_facing(&err.message), "llm http 401");
}

#[test]
fn the_key_is_cut_before_the_body_is_truncated() {
    // A key straddling byte 200 must not leave a prefix behind.
    let mut body = vec![b'x'; 190];
    body.extend_from_slice(KEY.as_bytes());
    let message = status_error_message(500, &body, KEY);
    assert!(!message.contains("sk-or-FAKE"), "{message}");
    assert!(message.ends_with("[redacted]'"), "{message}");
}

#[test]
fn transport_and_decode_failures_are_errors_without_the_key() {
    let transport = Scripted::new(Err(format!("connect failed for {KEY}")));
    let err = client(transport).call(&decide_call()).unwrap_err();
    assert_eq!(err.message, "llm error: connect failed for [redacted]");
    assert_eq!(agent_facing(&err.message), err.message);

    let transport = Scripted::new(Ok(HttpReply {
        status: 200,
        body: b"<html>gateway</html>".to_vec(),
    }));
    let err = client(transport).call(&decide_call()).unwrap_err();
    assert!(err.message.starts_with("llm error: "), "{}", err.message);
}

#[test]
fn a_redirect_is_a_status_error() {
    let transport = Scripted::new(Ok(HttpReply {
        status: 307,
        body: Vec::new(),
    }));
    let err = client(transport).call(&decide_call()).unwrap_err();
    assert_eq!(err.message, "llm http 307: b''");
}

#[test]
fn the_key_never_appears_in_debug_output() {
    let c = client(Scripted::new(Err(String::new())));
    assert!(!format!("{c:?}").contains(KEY));
}

#[test]
fn bytes_repr_matches_cpython() {
    // Right-hand sides measured with CPython 3.12 `repr(bytes)`.
    assert_eq!(python_bytes_repr(b""), "b''");
    assert_eq!(python_bytes_repr(b"it's"), "b\"it's\"");
    assert_eq!(python_bytes_repr(b"a'b\"c"), "b'a\\'b\"c'");
    assert_eq!(
        python_bytes_repr(b"\t\n\r\\\x00\x7f\xff~"),
        "b'\\t\\n\\r\\\\\\x00\\x7f\\xff~'"
    );
}

#[test]
fn agent_facing_only_cuts_status_messages() {
    assert_eq!(agent_facing("llm http 503: b'busy'"), "llm http 503");
    assert_eq!(agent_facing("llm http oops: x"), "llm http oops: x");
    assert_eq!(agent_facing("llm error: timed out"), "llm error: timed out");
}

#[test]
fn default_bases_and_unknown_providers() {
    assert_eq!(
        default_base_url("anthropic"),
        Some("https://api.anthropic.com")
    );
    assert_eq!(
        default_base_url("openrouter"),
        Some("https://openrouter.ai/api/v1")
    );
    assert_eq!(default_base_url("gemini"), None);
}

// ── the real transport, against a loopback server ─────────────

/// Serve one canned response on a loopback port; return the port and a
/// handle yielding the raw request bytes.
fn one_shot_server(response: &'static [u8]) -> (u16, std::thread::JoinHandle<Vec<u8>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        // Read the head, then Content-Length bytes of body.
        loop {
            let n = sock.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&buf[..n]);
            if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map_or(0, |v| v.trim().parse().unwrap());
                if seen.len() >= end + 4 + len {
                    break;
                }
            }
        }
        sock.write_all(response).unwrap();
        seen
    });
    (port, handle)
}

#[test]
fn the_real_transport_returns_error_statuses_and_sends_the_headers() {
    let (port, server) = one_shot_server(
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbad api key",
    );
    let request = WireRequest {
        url: format!("http://127.0.0.1:{port}/v1/messages"),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("x-api-key".into(), "k".into()),
            ("User-Agent".into(), USER_AGENT.into()),
        ],
        body: b"{\"a\": 1}".to_vec(),
    };
    let reply = UreqTransport
        .post(&request, Duration::from_secs(5))
        .unwrap();
    assert_eq!(reply.status, 401);
    assert_eq!(reply.body, b"bad api key");
    let raw = String::from_utf8(server.join().unwrap()).unwrap();
    assert!(raw.starts_with("POST /v1/messages HTTP/1.1\r\n"), "{raw}");
    let lower = raw.to_ascii_lowercase();
    assert!(lower.contains("x-api-key: k\r\n"), "{raw}");
    assert!(
        lower.contains("user-agent: agentcage-policy-api\r\n"),
        "{raw}"
    );
    assert!(raw.ends_with("{\"a\": 1}"), "{raw}");
}

#[test]
fn the_real_transport_does_not_follow_redirects() {
    let (port, server) = one_shot_server(
        b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let request = WireRequest {
        url: format!("http://127.0.0.1:{port}/"),
        headers: Vec::new(),
        body: b"{}".to_vec(),
    };
    let reply = UreqTransport
        .post(&request, Duration::from_secs(5))
        .unwrap();
    assert_eq!(reply.status, 307);
    server.join().unwrap();
}

#[test]
fn the_real_transport_times_out_on_a_silent_server() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let request = WireRequest {
        url: format!("http://127.0.0.1:{port}/"),
        headers: Vec::new(),
        body: b"{}".to_vec(),
    };
    let started = std::time::Instant::now();
    let result = UreqTransport.post(&request, Duration::from_millis(300));
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(listener);
}
