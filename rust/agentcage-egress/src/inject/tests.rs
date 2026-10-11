//! Tests for the injector: the `injection.json` corpus recorded from the
//! Python egress, plus the reload and lifetime behaviour the corpus cannot
//! express as single operations.

use super::*;
use crate::json;

fn corpus() -> Json {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/egress/injection.json"
    );
    json::parse(&std::fs::read_to_string(path).expect("injection.json")).expect("valid JSON")
}

fn s<'a>(v: &'a Json, key: &str) -> &'a str {
    v.get(key).and_then(Json::as_str).unwrap_or_default()
}

fn arr<'a>(v: &'a Json, key: &str) -> &'a [Json] {
    match v.get(key) {
        Some(Json::Array(a)) => a,
        _ => &[],
    }
}

fn strs(v: &Json, key: &str) -> Vec<String> {
    arr(v, key)
        .iter()
        .filter_map(Json::as_str)
        .map(str::to_owned)
        .collect()
}

fn bytes_of(v: Option<&Json>) -> Vec<u8> {
    match v {
        Some(Json::Str(s)) => s.as_bytes().to_vec(),
        Some(v @ Json::Object(_)) => b64_decode_std(s(v, "b64")).expect("fixture base64"),
        _ => Vec::new(),
    }
}

fn headers_of(v: &Json) -> Headers {
    Headers(
        arr(v, "headers")
            .iter()
            .map(|p| {
                let Json::Array(kv) = p else {
                    panic!("header pair")
                };
                (
                    kv[0].as_str().unwrap().as_bytes().to_vec(),
                    kv[1].as_str().unwrap().as_bytes().to_vec(),
                )
            })
            .collect(),
    )
}

fn int(v: &Json, key: &str, default: i64) -> i64 {
    match v.get(key) {
        Some(Json::Int(n)) => *n,
        _ => default,
    }
}

fn request_of(v: &Json) -> Request {
    Request {
        method: s(v, "method").to_owned(),
        scheme: s(v, "scheme").to_owned(),
        host: s(v, "host").to_owned(),
        port: u16::try_from(int(v, "port", 443)).unwrap(),
        path: s(v, "path").to_owned(),
        http_version: "HTTP/1.1".into(),
        headers: headers_of(v),
        body: bytes_of(v.get("body")),
    }
}

fn response_of(v: &Json) -> Response {
    Response {
        status: u16::try_from(int(v, "status", 200)).unwrap(),
        headers: headers_of(v),
        body: bytes_of(v.get("body")),
        ..Response::default()
    }
}

/// A transform that returns a fixed value (or fails) and lists a fixed
/// set of active values (or none, for the last-two tracking).
#[derive(Debug)]
struct Fixed {
    value: String,
    fails: bool,
    active: Option<Vec<String>>,
}

impl Transform for Fixed {
    fn get_value(&self) -> Result<String, TransformError> {
        if self.fails {
            Err(TransformError("transform failed".into()))
        } else {
            Ok(self.value.clone())
        }
    }
    fn active_values(&self) -> Option<Vec<String>> {
        self.active.clone()
    }
}

fn rule_of(v: &Json) -> Rule {
    let mut rule = Rule::new(s(v, "name"), s(v, "placeholder"), s(v, "real_value"), &[]);
    rule.inject_to = strs(v, "inject_to");
    rule.inject_body = matches!(v.get("inject_body"), Some(Json::Bool(true)));
    rule.inject_headers = strs(v, "inject_headers");
    if let Some(t @ Json::Object(_)) = v.get("transform") {
        let active = match t.get("active") {
            Some(Json::Array(_)) => Some(strs(t, "active")),
            _ => None,
        };
        rule = rule.with_transform(
            s(t, "name"),
            Arc::new(Fixed {
                value: s(t, "value").to_owned(),
                fails: matches!(t.get("fails"), Some(Json::Bool(true))),
                active,
            }),
        );
    }
    rule
}

fn verdict_json(v: Option<Verdict>) -> Json {
    v.map_or(Json::Null, |v| {
        json::object([
            ("inspector", Json::string(v.inspector)),
            ("action", Json::string(v.action.as_str())),
            ("reason", Json::string(v.reason)),
            ("severity", Json::string(v.severity.as_str())),
        ])
    })
}

fn body_json(b: &[u8]) -> Json {
    match std::str::from_utf8(b) {
        Ok(s) => Json::string(s),
        Err(_) => json::object([("b64", Json::string(b64_encode_std(b)))]),
    }
}

fn headers_json(h: &Headers) -> Json {
    Json::Array(
        h.to_strings()
            .into_iter()
            .map(|(k, v)| Json::Array(vec![Json::string(k), Json::string(v)]))
            .collect(),
    )
}

fn request_json(r: &Request) -> Json {
    json::object([
        ("method", Json::string(r.method.clone())),
        ("scheme", Json::string(r.scheme.clone())),
        ("host", Json::string(r.host.clone())),
        ("port", Json::Int(i64::from(r.port))),
        ("path", Json::string(r.path.clone())),
        ("headers", headers_json(&r.headers)),
        ("body", body_json(&r.body)),
    ])
}

fn names_json(names: Vec<String>) -> Json {
    Json::Array(names.into_iter().map(Json::string).collect())
}

fn error_json() -> Json {
    json::object([("error", Json::string("ValueError"))])
}

/// Run one corpus case through the Rust injector, producing its `expect`
/// object.
fn run(case: &Json) -> Json {
    let rules = arr(case, "rules").iter().map(rule_of).collect();
    let redact_to = strs(case, "redact_to");
    let redact_to: Vec<&str> = redact_to.iter().map(String::as_str).collect();
    let inj = Injector::with_rules(rules, &redact_to);
    let content = || bytes_of(case.get("content"));
    match s(case, "op") {
        "policy" => match inj.check_injection_policy(&request_of(case.get("request").unwrap())) {
            Ok(v) => json::object([("verdict", verdict_json(v))]),
            Err(_) => error_json(),
        },
        op @ ("inject" | "redact_request") => {
            let mut req = request_of(case.get("request").unwrap());
            let result = if op == "inject" {
                inj.inject_request(&mut req)
            } else {
                inj.redact_request(&mut req)
            };
            match result {
                Ok(names) => json::object([
                    ("names", names_json(names)),
                    ("request", request_json(&req)),
                ]),
                Err(_) => error_json(),
            }
        }
        "redact_response" => {
            let mut resp = response_of(case.get("response").unwrap());
            match inj.redact_response(&mut resp) {
                Ok(names) => json::object([
                    ("names", names_json(names)),
                    (
                        "response",
                        json::object([
                            ("status", Json::Int(i64::from(resp.status))),
                            ("headers", headers_json(&resp.headers)),
                            ("body", body_json(&resp.body)),
                        ]),
                    ),
                ]),
                Err(_) => error_json(),
            }
        }
        "ws_policy" => json::object([(
            "verdict",
            verdict_json(inj.check_ws_injection_policy(&content(), s(case, "host"))),
        )]),
        "ws_inject" => {
            let (out, names) = inj.inject_ws_content(&content(), s(case, "host"));
            json::object([("content", body_json(&out)), ("names", names_json(names))])
        }
        "ws_redact" => {
            let (out, names) = inj.redact_ws_content(&content());
            json::object([("content", body_json(&out)), ("names", names_json(names))])
        }
        "redact_text" => {
            let (text, names) = inj.redact_text(s(case, "text"));
            json::object([("text", Json::string(text)), ("names", names_json(names))])
        }
        "redact_record" => {
            let mut record = case.get("record").cloned().unwrap();
            inj.redact_json(&mut record);
            json::object([("record", record)])
        }
        "basic" => {
            let got = rewrite_basic_auth(
                s(case, "value").as_bytes(),
                s(case, "find").as_bytes(),
                s(case, "replace").as_bytes(),
            );
            json::object([(
                "value",
                got.map_or(Json::Null, |v| Json::string(String::from_utf8(v).unwrap())),
            )])
        }
        other => panic!("unknown op {other}"),
    }
}

#[test]
fn corpus_cases_match_python() {
    let corpus = corpus();
    let mut failures = Vec::new();
    for case in arr(&corpus, "cases") {
        let want = case.get("expect").unwrap();
        let got = run(case);
        if &got != want {
            failures.push(format!(
                "{}:\n  got  {}\n  want {}",
                s(case, "name"),
                json::to_string(&got),
                json::to_string(want)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn a_wrong_expectation_fails() {
    // The comparison must bite: an altered expectation no longer matches.
    let corpus = corpus();
    let case = arr(&corpus, "cases")
        .iter()
        .find(|c| s(c, "name") == "inject/strict-header/Authorization")
        .unwrap();
    let mut want = case.get("expect").unwrap().clone();
    want.set("names", Json::Array(vec![]));
    assert_ne!(run(case), want);
}

#[test]
fn configure_matches_python() {
    let corpus = corpus();
    for case in arr(&corpus, "configure") {
        let staged = case.get("staged").cloned().unwrap_or(Json::Null);
        let env = case.get("env").cloned().unwrap_or(Json::Null);
        // The staged file wins (trailing newlines stripped, empty is a
        // tombstone), then the env: `secret_lookup::read_secret`.
        let lookup = |name: &str| -> String {
            if let Some(v) = staged.get(name).and_then(Json::as_str) {
                return v.trim_end_matches('\n').to_owned();
            }
            env.get(name)
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let section = agentcage_core::yaml::load(s(case, "config_yaml")).unwrap();
        let inj = Injector::new();
        inj.configure_with(Some(&section), &lookup, &crate::transforms::build);
        let got: Vec<Json> = inj
            .rules()
            .iter()
            .map(|r| {
                json::object([
                    ("name", Json::string(r.name.clone())),
                    ("placeholder", Json::string(r.placeholder.clone())),
                    ("real_value", Json::string(r.real_value.clone())),
                    ("inject_to", names_json(r.inject_to.clone())),
                    ("inject_body", Json::Bool(r.inject_body)),
                    ("inject_headers", names_json(r.inject_headers.clone())),
                    ("transform", Json::string(r.transform.clone())),
                ])
            })
            .collect();
        assert_eq!(
            Json::Array(got),
            case.get("rules").cloned().unwrap(),
            "{}",
            s(case, "name")
        );
        assert_eq!(
            inj.redact_to(),
            strs(case, "redact_to"),
            "{}",
            s(case, "name")
        );
    }
}

/// A transform handing out scripted tokens, each live until cleared.
#[derive(Debug)]
struct Scripted {
    tokens: Mutex<Vec<String>>,
    live: Mutex<Vec<String>>,
}

impl Transform for Scripted {
    fn get_value(&self) -> Result<String, TransformError> {
        let token = self.tokens.lock().unwrap().remove(0);
        self.live.lock().unwrap().push(token.clone());
        Ok(token)
    }
    fn active_values(&self) -> Option<Vec<String>> {
        Some(self.live.lock().unwrap().clone())
    }
}

fn bearer_request(host: &str, path: &str, auth: &str) -> Request {
    Request {
        host: host.into(),
        scheme: "https".into(),
        port: 443,
        path: path.into(),
        headers: Headers(vec![(b"Authorization".to_vec(), auth.as_bytes().to_vec())]),
        ..Request::default()
    }
}

#[test]
fn reload_keeps_an_unchanged_transform_and_retires_a_replaced_one() {
    let made: Arc<Mutex<Vec<Arc<Scripted>>>> = Arc::default();
    let factory = {
        let made = made.clone();
        move |_: &str, secret: &str, _: &Value| -> Result<Arc<dyn Transform>, TransformError> {
            let t = Arc::new(Scripted {
                tokens: Mutex::new(vec![format!("tok-{secret}-1"), format!("tok-{secret}-2")]),
                live: Mutex::new(Vec::new()),
            });
            made.lock().unwrap().push(t.clone());
            Ok(t)
        }
    };
    let cfg = agentcage_core::yaml::load(
        "- env: SA\n  placeholder: '{{SA}}'\n  inject_to: [example.com]\n  transform: scripted\n  transform_config: {scopes: [a]}\n",
    )
    .unwrap();
    let inj = Injector::new();
    let key_one = |_: &str| "key-one".to_owned();
    inj.configure_with(Some(&cfg), &key_one, &factory);
    let mut req = bearer_request("api.example.com", "/", "Bearer {{SA}}");
    assert_eq!(inj.inject_request(&mut req).unwrap(), ["SA"]);
    assert_eq!(
        req.headers.get("authorization").unwrap(),
        "Bearer tok-key-one-1"
    );

    // An unchanged rule keeps its transform, and its token stays secret.
    inj.configure_with(Some(&cfg), &key_one, &factory);
    assert_eq!(made.lock().unwrap().len(), 1);
    assert_eq!(inj.redact_str("x tok-key-one-1"), "x {{SA}}");

    // A re-staged secret builds a new transform; the old token is retired
    // but stays redacted and blocked while it is live.
    let key_two = |_: &str| "key-two".to_owned();
    inj.configure_with(Some(&cfg), &key_two, &factory);
    assert_eq!(made.lock().unwrap().len(), 2);
    assert_eq!(inj.redact_str("x tok-key-one-1"), "x {{SA}}");
    let blocked = inj
        .check_injection_policy(&bearer_request("evil.com", "/?t=tok-key-one-1", "none"))
        .unwrap()
        .unwrap();
    assert_eq!(
        blocked.reason,
        "literal secret value SA (a token its scripted transform minted) found in outbound request to evil.com"
    );

    // Once it expires, the retired rule is forgotten.
    made.lock().unwrap()[0].live.lock().unwrap().clear();
    assert_eq!(inj.redact_str("x tok-key-one-1"), "x tok-key-one-1");

    inj.configure_with(None, &key_two, &factory);
    assert!(inj.rules().is_empty());
}

#[test]
fn a_transform_without_active_values_has_its_last_two_values_redacted() {
    #[derive(Debug)]
    struct Seq(Mutex<Vec<&'static str>>);
    impl Transform for Seq {
        fn get_value(&self) -> Result<String, TransformError> {
            Ok(self.0.lock().unwrap().remove(0).to_owned())
        }
    }
    let rule = Rule::new("T", "{{T}}", "underlying", &["example.com"])
        .with_inject_body(true)
        .with_transform("t", Arc::new(Seq(Mutex::new(vec!["v1", "v1", "v2", "v3"]))));
    let inj = Injector::with_rules(vec![rule], &[]);
    for _ in 0..4 {
        let _ = inj.inject_ws_content(b"{{T}}", "example.com");
    }
    assert_eq!(inj.redact_text("v1 v2 v3").0, "v1 {{T}} {{T}}");
}

#[test]
fn the_injector_is_the_audit_redactor() {
    let inj = Injector::with_rules(vec![Rule::new("K", "{{K}}", "s3cret-value", &[])], &[]);
    let redactor: &dyn crate::audit::Redactor = &inj;
    let mut record = json::object([
        ("s3cret-value", Json::string("a s3cret-value b")),
        (
            "n",
            Json::Array(vec![Json::string("czNjcmV0LXZhbHVl"), Json::Int(1)]),
        ),
    ]);
    redactor.redact(&mut record);
    assert_eq!(
        json::to_string(&record),
        r#"{"s3cret-value": "a {{K}} b", "n": ["e3tLfX0=", 1]}"#
    );
}

#[test]
fn base64_strict_decoding() {
    assert_eq!(b64_decode_std("QUJD").unwrap(), b"ABC");
    assert_eq!(b64_decode_std("QR==").unwrap(), b"A");
    assert_eq!(b64_decode_std("").unwrap(), b"");
    for bad in [
        "QUJD=", "QUI", "QQ=", "=", "Q", "QU=D", "QUJ\n", " QUJD", "QQ==QQ==",
    ] {
        assert!(b64_decode_std(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn set_url_re_parses_and_rewrites_host() {
    let mut req = Request {
        scheme: "https".into(),
        host: "a.example".into(),
        port: 443,
        path: "/".into(),
        headers: Headers(vec![(b"Host".to_vec(), b"a.example".to_vec())]),
        ..Request::default()
    };
    set_url(&mut req, "http://B.example:8080/x;y?z#f").unwrap();
    assert_eq!(
        (
            req.scheme.as_str(),
            req.host.as_str(),
            req.port,
            req.path.as_str()
        ),
        ("http", "b.example", 8080, "/x;y?z#f")
    );
    assert_eq!(req.headers.get("host").unwrap(), "b.example:8080");
    // An IPv6 literal is bracketed in Host (the replaced implementation
    // wrote `::1:9`).
    set_url(&mut req, "https://[::1]:9/").unwrap();
    assert_eq!(req.headers.get("host").unwrap(), "[::1]:9");
    assert!(set_url(&mut req, "https://bad host/").is_err());
    assert!(set_url(&mut req, "https://h:99999/").is_err());
}
