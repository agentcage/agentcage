//! Tests for the injector: the `injection.json` corpus recorded from an
//! earlier release's egress, plus the reload and lifetime behaviour the
//! corpus cannot express as single operations.

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
fn corpus_cases_match_the_recording() {
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
fn configure_matches_the_recording() {
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

/// Every byte string a corpus case hands the injector.
fn corpus_inputs(case: &Json) -> Vec<Vec<u8>> {
    let mut out = vec![bytes_of(case.get("content"))];
    if let Some(Json::Str(text)) = case.get("text") {
        out.push(text.as_bytes().to_vec());
    }
    for key in ["request", "response"] {
        if let Some(msg) = case.get(key) {
            out.push(bytes_of(msg.get("body")));
            if let Some(Json::Str(url)) = msg.get("url") {
                out.push(url.as_bytes().to_vec());
            }
            for value in headers_of(msg.get("headers").unwrap_or(&Json::Null)).0 {
                out.push(value.1);
            }
        }
    }
    out
}

/// A small deterministic generator (xorshift), so the random bodies are
/// the same on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap()
    }
}

#[test]
fn the_redaction_prefilter_never_changes_a_result() {
    let corpus = corpus();
    let mut forms = Vec::new();
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    for case in arr(&corpus, "cases") {
        for rule in arr(case, "rules").iter().map(rule_of) {
            forms.push(SecretForms::new(
                &rule.real_value,
                &rule.placeholder,
                &rule.name,
            ));
        }
        inputs.extend(corpus_inputs(case));
    }
    assert!(forms.len() > 20 && inputs.len() > 100);
    // Random bodies stitched from pieces of the corpus inputs, random
    // bytes and the secrets' own values (so the forms do occur, cut and
    // joined in places the corpus never put them).
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let values: Vec<Vec<u8>> = forms.iter().map(|f| f.raw().to_vec()).collect();
    for _ in 0..400 {
        let mut body = Vec::new();
        for _ in 0..rng.below(8) {
            match rng.below(4) {
                0 => {
                    let src = &inputs[rng.below(inputs.len())];
                    if !src.is_empty() {
                        let a = rng.below(src.len());
                        let b = a + rng.below(src.len() - a + 1);
                        body.extend_from_slice(&src[a..b]);
                    }
                }
                1 => body.extend_from_slice(&values[rng.below(values.len())]),
                2 => {
                    let v = &values[rng.below(values.len())];
                    let blob = b64_encode_std(&[b"x:".as_slice(), v].concat());
                    body.extend_from_slice(blob.as_bytes());
                }
                _ => body.extend((0..rng.below(16)).map(|_| (rng.next() & 0xff) as u8)),
            }
        }
        inputs.push(body);
    }
    let mut hits = 0;
    for f in &forms {
        for input in &inputs {
            let want = f.redact_unfiltered(input);
            hits += usize::from(want.is_some());
            assert_eq!(f.redact(input), want, "{} over {input:?}", f.name());
            let occurs_unfiltered = contains(input, f.raw())
                || (f.has_derived() && f.redact_derived(std::borrow::Cow::Borrowed(input)).1);
            assert_eq!(f.occurs(input), occurs_unfiltered, "{}", f.name());
            if want.is_some() {
                assert!(f.may_occur(input));
            }
        }
    }
    // The comparison bites: plenty of inputs do hold a secret.
    assert!(hits > 100, "{hits}");
}

#[test]
fn a_predecoded_response_redacts_exactly_as_one_decoded_lazily() {
    let corpus = corpus();
    let mut checked = 0;
    for case in arr(&corpus, "cases") {
        if s(case, "op") != "redact_response" {
            continue;
        }
        let rules: Vec<Rule> = arr(case, "rules").iter().map(rule_of).collect();
        let inj = Injector::with_rules(rules, &[]);
        let mut lazy = response_of(case.get("response").unwrap());
        let mut eager = lazy.clone();
        let want = inj.redact_response(&mut lazy);
        let decoded = match crate::text::decoded_body(&eager.headers, &eager.body) {
            Ok(std::borrow::Cow::Owned(v)) => Some(v),
            Ok(std::borrow::Cow::Borrowed(_)) => None,
            // The pipeline fails such a response closed before redaction
            // (as it did when the context build decoded it).
            Err(_) => continue,
        };
        let had_decoded = decoded.clone();
        let (got, back) = inj.redact_response_decoded(&mut eager, decoded);
        assert_eq!(got.ok(), want.ok(), "{}", s(case, "name"));
        assert_eq!(eager.headers, lazy.headers, "{}", s(case, "name"));
        assert_eq!(eager.body, lazy.body, "{}", s(case, "name"));
        // Handed back only while it still differs from the body.
        if back.is_some() {
            assert_eq!(back, had_decoded);
        }
        checked += 1;
    }
    assert!(checked >= 2, "{checked}");

    // A gzip body without a secret is handed back decoded, untouched.
    let inj = Injector::with_rules(
        vec![rule_of(
            &arr(&corpus, "cases")
                .iter()
                .find(|c| !arr(c, "rules").is_empty())
                .map(|c| arr(c, "rules")[0].clone())
                .unwrap(),
        )],
        &[],
    );
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut enc, b"nothing secret here").unwrap();
    let mut resp = Response {
        status: 200,
        body: enc.finish().unwrap(),
        ..Response::default()
    };
    resp.headers.add("Content-Encoding", "gzip");
    let raw = resp.body.clone();
    let (names, back) =
        inj.redact_response_decoded(&mut resp, Some(b"nothing secret here".to_vec()));
    assert_eq!(names.unwrap(), Vec::<String>::new());
    assert_eq!(back.as_deref(), Some(&b"nothing secret here"[..]));
    assert_eq!(resp.body, raw);
}

// ── Streaming redaction ──────────────────────────────────

/// Redact `body` (no Content-Encoding) as the buffered path does: the
/// body and the names, headers included.
fn buffered_redaction(inj: &Injector, headers: &Headers, body: &[u8]) -> (Vec<u8>, Vec<String>) {
    let mut resp = Response {
        status: 200,
        headers: headers.clone(),
        body: body.to_vec(),
        ..Response::default()
    };
    let names = inj.redact_response(&mut resp).expect("identity body");
    (resp.body, names)
}

/// Stream `body` through a fresh redactor, cut at `cuts` (sorted
/// offsets), with `headers` redacted first as the streaming head is.
fn streamed_redaction(
    inj: &Injector,
    headers: &Headers,
    body: &[u8],
    cuts: &[usize],
) -> (Vec<u8>, Vec<String>) {
    let Some(mut red) = inj.stream_redactor() else {
        return (body.to_vec(), Vec::new());
    };
    let mut headers = headers.clone();
    let header_found = Injector::redact_headers_with(&mut headers, red.forms());
    let body = bytes::Bytes::copy_from_slice(body);
    let mut out = Vec::new();
    let mut at = 0;
    for &cut in cuts.iter().chain(std::iter::once(&body.len())) {
        if cut < at {
            continue;
        }
        red.push(body.slice(at..cut), &mut out).expect("bounded");
        at = cut;
    }
    red.finish(&mut out);
    (out.concat(), red.names(&header_found))
}

/// Every chunking worth checking for a body of `len` bytes: one cut at
/// every offset (all of them for short bodies), single bytes, and random
/// multi-cuts.
fn chunkings(len: usize, rng: &mut Rng) -> Vec<Vec<usize>> {
    let mut out = vec![Vec::new(), (1..len).collect()];
    let step = (len / 64).max(1);
    out.extend((1..len).step_by(step).map(|i| vec![i]));
    for _ in 0..8 {
        let mut cuts: Vec<usize> = (0..rng.below(6)).map(|_| rng.below(len + 1)).collect();
        cuts.sort_unstable();
        out.push(cuts);
    }
    out
}

fn assert_stream_equivalent(inj: &Injector, headers: &Headers, body: &[u8], rng: &mut Rng) -> bool {
    let want = buffered_redaction(inj, headers, body);
    for cuts in chunkings(body.len(), rng) {
        let got = streamed_redaction(inj, headers, body, &cuts);
        assert_eq!(
            got.0,
            want.0,
            "body differs for cuts {cuts:?} over {:?}",
            String::from_utf8_lossy(body)
        );
        assert_eq!(got.1, want.1, "names differ for cuts {cuts:?}");
    }
    want.0 != body
}

#[test]
fn streamed_redaction_matches_the_corpus_for_every_chunking() {
    let corpus = corpus();
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut checked = 0;
    for case in arr(&corpus, "cases") {
        if s(case, "op") != "redact_response" {
            continue;
        }
        let rules: Vec<Rule> = arr(case, "rules").iter().map(rule_of).collect();
        let inj = Injector::with_rules(rules, &[]);
        let resp = response_of(case.get("response").unwrap());
        let Ok(decoded) = crate::text::decoded_body(&resp.headers, &resp.body) else {
            continue;
        };
        let mut headers = resp.headers.clone();
        headers.remove("content-encoding");
        assert_stream_equivalent(&inj, &headers, &decoded, &mut rng);
        checked += 1;
    }
    assert!(checked >= 2, "{checked}");
}

/// The ways a server can spell `value` back.
fn spellings(value: &str, rng: &mut Rng) -> Vec<Vec<u8>> {
    use std::fmt::Write as _;
    let pct = |upper: bool| {
        value.bytes().fold(String::new(), |mut out, b| {
            if upper {
                let _ = write!(out, "%{b:02X}");
            } else {
                let _ = write!(out, "%{b:02x}");
            }
            out
        })
    };
    let json_u = value.encode_utf16().fold(String::new(), |mut out, u| {
        let _ = write!(out, "\\u{u:04x}");
        out
    });
    let mixed: String = value
        .chars()
        .map(|c| match c {
            ' ' => "+".to_owned(),
            '/' => "\\/".to_owned(),
            '"' => "\\\"".to_owned(),
            c if !c.is_ascii_alphanumeric() => format!("%{:02X}", u32::from(c) & 0xff),
            c => c.to_string(),
        })
        .collect();
    let mut out = vec![
        value.as_bytes().to_vec(),
        pct(true).into_bytes(),
        pct(false).into_bytes(),
        json_u.into_bytes(),
        mixed.into_bytes(),
    ];
    for prefix in ["", "u:", "ab", "xyz:"] {
        let raw = [prefix.as_bytes(), value.as_bytes(), b"!tail"].concat();
        let std = b64_encode_std(&raw);
        let mut url = std.clone().into_bytes();
        std_to_url(&mut url);
        out.push(std.into_bytes());
        out.push(url.clone());
        let unpadded: Vec<u8> = url.into_iter().filter(|&b| b != b'=').collect();
        out.push(unpadded);
    }
    // A cut-off spelling: a prefix that never completes.
    let cut = rng.below(value.len().max(1));
    out.push(value.as_bytes()[..cut].to_vec());
    out
}

#[test]
fn streamed_redaction_matches_buffered_on_random_bodies() {
    let values = [
        "sk-live-0123456789abcdef",
        "p@ss w/rd \"q\" \u{e9}",
        "abc/def+ghi==",
        "short",
        "%%%%%%%%%",
        "ffffffffffff",
        "tok_9f8e7d6c5b4a",
    ];
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let mut changed = 0;
    for round in 0..120 {
        // A few rules at a time, so passes of several secrets compose.
        let picked: Vec<&str> = (0..=rng.below(3))
            .map(|_| values[rng.below(values.len())])
            .collect();
        let rules: Vec<Rule> = picked
            .iter()
            .enumerate()
            .map(|(i, v)| {
                Rule::new(
                    &format!("SECRET_{i}"),
                    &format!("agentcage:secret:SECRET_{i}:{round:04x}"),
                    v,
                    &[],
                )
            })
            .collect();
        let inj = Injector::with_rules(rules, &[]);
        let fillers: [&[u8]; 8] = [
            b"data: {\"delta\": \"",
            b"\"}\n\n",
            b" ",
            b"AAAABBBBccccdddd0123",
            b"%2",
            b"\\u00",
            b"==",
            b"\xff\x00\x10",
        ];
        let mut body = Vec::new();
        for _ in 0..rng.below(10) {
            match rng.below(4) {
                0 => {
                    let v = picked[rng.below(picked.len())];
                    let forms = spellings(v, &mut rng);
                    body.extend_from_slice(&forms[rng.below(forms.len())]);
                }
                1 => body.extend_from_slice(fillers[rng.below(fillers.len())]),
                2 => body.extend((0..rng.below(24)).map(|_| (rng.next() & 0xff) as u8)),
                _ => body.extend((0..rng.below(40)).map(|_| b"ab0+/-_="[rng.below(8)])),
            }
        }
        let mut headers = Headers::new();
        if rng.below(3) == 0 {
            headers.add("X-Echo", picked[0]);
        }
        if assert_stream_equivalent(&inj, &headers, &body, &mut rng) {
            changed += 1;
        }
    }
    // The comparison bites: most bodies did carry a secret.
    assert!(changed > 40, "{changed}");
}

#[test]
fn streamed_redaction_holds_back_only_the_unfinished_tail() {
    let inj = Injector::with_rules(
        vec![Rule::new(
            "K",
            "agentcage:secret:K:1",
            "sk-live-0123456789",
            &[],
        )],
        &[],
    );
    let mut red = inj.stream_redactor().unwrap();
    let mut out = Vec::new();
    // An SSE event ends in "\n\n": nothing is held, and the chunk goes on
    // as it came (no copy).
    let event = bytes::Bytes::from_static(b"data: {\"delta\": \"hi\"}\n\n");
    red.push(event.clone(), &mut out).unwrap();
    assert_eq!(red.held(), 0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].as_ptr(), event.as_ptr(), "relayed without a copy");
    // A secret split across chunks is held until it can be judged.
    out.clear();
    red.push(bytes::Bytes::from_static(b"key: sk-live-01"), &mut out)
        .unwrap();
    assert_eq!(out.concat(), b"key: ");
    assert_eq!(red.held(), 10);
    red.push(bytes::Bytes::from_static(b"23456789\n"), &mut out)
        .unwrap();
    red.finish(&mut out);
    assert_eq!(out.concat(), b"key: agentcage:secret:K:1\n");
    assert_eq!(red.names(&[]), ["K"]);

    // A run with no separator past the bound aborts.
    let mut red = inj.stream_redactor().unwrap().with_max_hold(64);
    let mut out = Vec::new();
    let run = bytes::Bytes::from(vec![b'A'; 40]);
    red.push(run.clone(), &mut out).unwrap();
    assert_eq!(
        red.push(run, &mut out),
        Err(StreamRedactError::UnboundedRun)
    );
}

// ── Percent-encoded spellings of unreserved bytes (findings A1/A2) ──

/// The value with every byte spelled `%XX` (upper-case hex).
fn fully_percent_encoded(value: &str) -> String {
    use std::fmt::Write as _;
    value.bytes().fold(String::new(), |mut out, b| {
        let _ = write!(out, "%{b:02X}");
        out
    })
}

/// A secret whose bytes are all URL-unreserved (`A-Za-z0-9-._`), echoed
/// back fully percent-encoded, is redacted from the response body (A1).
#[test]
fn a_percent_encoded_unreserved_secret_is_redacted() {
    let secret = "sk-proj-AbC123-._";
    let encoded = fully_percent_encoded(secret);
    let inj = Injector::with_rules(vec![Rule::new("K", "{{K}}", secret, &[])], &[]);

    // Control: the literal echo is redacted (and proves the path bites).
    let mut literal = Response {
        status: 200,
        body: format!("token={secret}&x=1").into_bytes(),
        ..Response::default()
    };
    assert_eq!(inj.redact_response(&mut literal).unwrap(), ["K"]);
    assert_eq!(literal.body, b"token={{K}}&x=1");

    // The `%XX` echo must be redacted too (was left intact before the fix).
    let mut resp = Response {
        status: 200,
        body: format!("token={encoded}&x=1").into_bytes(),
        ..Response::default()
    };
    assert_eq!(inj.redact_response(&mut resp).unwrap(), ["K"]);
    let body = String::from_utf8(resp.body).unwrap();
    assert!(!body.contains(&encoded), "encoded secret survived: {body}");
    // The placeholder is written in the match's encoding.
    assert_eq!(body, "token=%7B%7BK%7D%7D&x=1");
}

/// The same encoded spelling sent to a host outside the rule's `inject_to`
/// is blocked, exactly as the literal spelling is (A2).
#[test]
fn a_percent_encoded_secret_to_a_foreign_host_is_blocked() {
    let secret = "sk-live-0123456789abcdef";
    let encoded = fully_percent_encoded(secret);
    let rule = Rule::new("K", "{{K}}", secret, &["openrouter.ai"]);
    let inj = Injector::with_rules(vec![rule], &[]);

    // Control: the literal spelling in the URL is blocked.
    let literal = inj
        .check_injection_policy(&bearer_request(
            "exfil.example.com",
            &format!("/?t={secret}"),
            "none",
        ))
        .unwrap()
        .expect("literal is blocked");
    assert_eq!(literal.action, Action::Block);

    // The encoded spelling is blocked in the URL and in the body.
    let url = inj
        .check_injection_policy(&bearer_request(
            "exfil.example.com",
            &format!("/?t={encoded}"),
            "none",
        ))
        .unwrap()
        .expect("encoded URL value is blocked");
    assert_eq!(url.action, Action::Block);

    let mut body_req = bearer_request("exfil.example.com", "/", "none");
    body_req.body = format!("key={encoded}").into_bytes();
    let body = inj
        .check_injection_policy(&body_req)
        .unwrap()
        .expect("encoded body value is blocked");
    assert_eq!(body.action, Action::Block);

    // Control: the allowlisted host still accepts both spellings.
    for value in [secret, encoded.as_str()] {
        let ok = inj
            .check_injection_policy(&bearer_request(
                "openrouter.ai",
                &format!("/?t={value}"),
                "none",
            ))
            .unwrap();
        assert!(ok.is_none(), "{value} to openrouter.ai: {ok:?}");
    }
}
