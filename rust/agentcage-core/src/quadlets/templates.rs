//! The minijinja environment, configured to match the Jinja2 one the
//! templates were written for.
//!
//! # Matching Jinja2's settings
//!
//! Earlier releases rendered these templates with a Jinja2 environment
//! set to `keep_trailing_newline=True, trim_blocks=True,
//! lstrip_blocks=True`, and the golden corpus pins its output.
//!
//! All three whitespace settings are load-bearing, because a systemd
//! unit file is line-oriented:
//!
//! * `trim_blocks` drops the newline after a block tag, so
//!   `{% for … %}\nVolume=…\n{% endfor %}\n` emits one line per item
//!   instead of one blank line per item.
//! * `lstrip_blocks` drops the leading whitespace before a block tag —
//!   the templates do not indent their tags today, but a future edit
//!   that did would silently gain leading spaces on every directive.
//! * `keep_trailing_newline` keeps the file's final newline. Jinja2
//!   *removes* it by default, which would make every generated unit end
//!   without one. `[Install]\nWantedBy=default.target` with no trailing
//!   newline is still parsed by systemd, but it is not what the corpus
//!   records, and POSIX text files end in a newline.
//!
//! Scaffold rendering uses the same environment plus the `placeholder`
//! global (see [`render_source`]): one environment, used by the quadlet
//! renderer here and by `agentcage init`'s config/scaffold renderer.
//!
//! # On `SandboxedEnvironment`
//!
//! Earlier releases deliberately used Jinja2's **sandbox**, not a plain
//! `Environment`. What that buys is specific: Jinja2 evaluates
//! expressions against live interpreter objects, so `{{ x.__class__ }}`,
//! `{{ x.__init__.__globals__ }}` or `{{ "".format(...) }}` in a
//! template are a path from template text to arbitrary objects in the
//! interpreter — the classic Jinja2 sandbox escape. `SandboxedEnvironment`
//! blocks it by intercepting attribute access (`is_safe_attribute`) and
//! calls (`is_safe_callable`). That matters because not every template
//! agentcage renders is first-party: `agentcage init` searches
//! `./.agentcage/scaffolds/` and `~/.config/agentcage/scaffolds/`, so a
//! scaffold a user checked out from someone else's repository is
//! rendered by the same environment.
//!
//! **In Rust there is no such path to close, so there is no sandbox to
//! reproduce.** A minijinja template can only see values that were put
//! into its context, and a [`minijinja::Value`] built from `Serialize`
//! data — which is all this module ever builds — is a plain tree of
//! strings, numbers, sequences and maps. There is no reflection back
//! into the host program: no `__class__`, no globals, no way to reach a
//! Rust function that was not explicitly registered as a filter or a
//! global. An unknown attribute is undefined, not an object. The
//! property `SandboxedEnvironment` provides is structural here rather
//! than enforced, and it would only stop being so if this crate began
//! handing templates custom `Object` implementations with
//! `call_method`, which it does not.
//!
//! Two residual risks the Jinja2 sandbox does not cover either, noted so
//! the absence is a decision rather than an oversight: a hostile
//! template can still loop for a very long time (minijinja's `fuel`
//! feature would bound that; Jinja2 has no equivalent, so enabling it
//! would be a *divergence*), and it can still read any context value it
//! is given. Neither changes with the sandbox.

use std::sync::OnceLock;

use minijinja::value::{Value, ValueKind, from_args};
use minijinja::{Environment, Error, ErrorKind};

/// The `.j2` sources, as embedded by `agentcage-assets`.
///
/// Registered under their paths relative to `templates/` —
/// `network.j2`, `lima/lima.yaml.j2`.
fn register_templates(environment: &mut Environment<'static>) -> Result<(), Error> {
    for (name, file) in agentcage_assets::tree("templates") {
        let Ok(source) = std::str::from_utf8(file.bytes) else {
            // A non-UTF-8 file under templates/ cannot be a Jinja
            // source, so it is simply not a template.
            continue;
        };
        environment.add_template(name, source)?;
    }
    Ok(())
}

/// The shared environment, built once.
///
/// Building it parses every template, which is why it is cached: a CLI
/// that renders a cage's five units should not parse the sources five
/// times.
fn shared() -> &'static Environment<'static> {
    static ENVIRONMENT: OnceLock<Environment<'static>> = OnceLock::new();
    ENVIRONMENT.get_or_init(|| environment().expect("embedded templates parse"))
}

/// Build the environment the quadlet renderer and scaffold rendering
/// share.
///
/// # Errors
///
/// [`minijinja::Error`] when an embedded template fails to parse, which
/// can only happen if a `.j2` file in the repository is malformed —
/// `templates_all_parse` pins that.
pub fn environment() -> Result<Environment<'static>, Error> {
    let mut environment = Environment::new();
    environment.set_keep_trailing_newline(true);
    environment.set_trim_blocks(true);
    environment.set_lstrip_blocks(true);
    // The one Jinja2 behaviour minijinja does not carry: `mapping.items()`
    // is a method in Jinja2, and minijinja exposes the same thing as the
    // `items` filter instead, so `{% for k, v in env.items() %}` —
    // which `cage.container.j2` uses twice — fails with `UnknownMethod`.
    // The templates stay valid Jinja2 (user scaffolds written against
    // earlier releases use the same syntax), so this is the shim minijinja
    // documents for exactly that case (`set_unknown_method_callback`),
    // and it is deliberately narrow — one method, on maps, with no
    // arguments — so an unrelated typo in a template is still an error
    // rather than quietly resolving to something.
    environment.set_unknown_method_callback(|state, value, method, args| {
        if value.kind() == ValueKind::Map && method == "items" {
            let () = from_args(args)?;
            state.apply_filter("items", std::slice::from_ref(value))
        } else {
            Err(Error::from(ErrorKind::UnknownMethod))
        }
    });
    environment.add_filter("systemd_exec", systemd_exec);
    // Jinja2's `indent` keeps a trailing newline as a blank line;
    // minijinja's drops it. See [`jinja_indent`].
    environment.add_filter("indent", jinja_indent);
    // Jinja2's `default` takes three arguments; minijinja's takes two.
    // `openclaw/cage.yaml.j2` uses the third — see [`jinja_default`].
    environment.add_filter("default", jinja_default);
    environment.add_filter("d", jinja_default);
    environment.add_global(
        "placeholder",
        Value::from_function(|_name: &str| -> Result<String, Error> {
            Err(Error::new(
                ErrorKind::InvalidOperation,
                "placeholder() has no generator; install one with \
                 `with_placeholder_global` before rendering a template \
                 that calls it",
            ))
        }),
    );
    register_templates(&mut environment)?;
    Ok(environment)
}

/// Render one of the embedded templates.
///
/// # Errors
///
/// [`minijinja::Error`] when the template is unknown or rendering it
/// fails.
pub(crate) fn render(name: &str, context: Value) -> Result<String, Error> {
    shared().get_template(name)?.render(context)
}

/// The environment the Lima config is rendered with, which is **not**
/// the one above: `keep_trailing_newline` only.
///
/// No `trim_blocks`, no `lstrip_blocks`. That is not an oversight to be
/// tidied away here: `lima.yaml.j2` wraps its `vz`
/// block and its `portForwards` block in `{% if %}` tags on their own
/// lines, and without `trim_blocks` each of those tags leaves its
/// newline behind. A QEMU cage's Lima YAML therefore has *two* blank
/// lines after `vmType: qemu` where a trimmed render has one. YAML does
/// not care and a human would not notice, but the fixture is a byte
/// comparison against what earlier releases rendered, and "close
/// enough" is not a category this renderer works in.
///
/// Built once and cached, like [`shared`].
fn lima() -> &'static Environment<'static> {
    static ENVIRONMENT: OnceLock<Environment<'static>> = OnceLock::new();
    ENVIRONMENT.get_or_init(|| {
        let mut environment = Environment::new();
        environment.set_keep_trailing_newline(true);
        environment.add_filter("indent", jinja_indent);
        register_templates(&mut environment).expect("embedded templates parse");
        environment
    })
}

/// Render one of the embedded templates with Jinja2's *default*
/// whitespace handling. See [`lima`].
///
/// # Errors
///
/// [`minijinja::Error`] when the template is unknown or rendering it
/// fails.
pub(crate) fn render_untrimmed(name: &str, context: Value) -> Result<String, Error> {
    lima().get_template(name)?.render(context)
}

/// Render a template that is not one of the embedded ones, with a live
/// `placeholder()`.
///
/// A scaffold's
/// `cage.yaml.j2` is read from wherever the scaffold was found — a
/// project checkout, `~/.config`, or the extracted asset tree — so it
/// cannot come from the embedded set, but it must be rendered by the
/// *same* environment, with the same whitespace settings, the same
/// filters and the same globals.
///
/// The environment is built fresh rather than shared: it carries a
/// caller-supplied `placeholder` global, and installing that on the
/// process-wide one would leak entropy policy between renders.
///
/// # Errors
///
/// [`Error`] when the source fails to parse or the render raises.
pub fn render_source<S: serde::Serialize>(
    name: &str,
    source: &str,
    context: &S,
    generator: impl Fn(&str) -> String + Send + Sync + 'static,
) -> Result<String, Error> {
    let mut environment = with_placeholder_global(environment()?, generator);
    environment.add_template_owned(name.to_owned(), source.to_owned())?;
    environment
        .get_template(name)?
        .render(Value::from_serialize(context))
}

/// [`render_source`] with Jinja2's *default* whitespace handling.
///
/// The environment `Containerfile.wrapper.j2` (apple-container) is
/// rendered with: `keep_trailing_newline` only.
///
/// No `trim_blocks` and no `lstrip_blocks`, which is load-bearing
/// rather than incidental: the template opens with a 35-line `{# … #}`
/// comment on its own lines, and without `trim_blocks` the newline
/// after `#}` survives. The rendered Containerfile therefore starts
/// with a blank line, and `container build` is handed those bytes.
///
/// No `placeholder` global and no filters beyond `indent` — the
/// template uses neither, and a narrower environment is easier to
/// reason about.
///
/// # Errors
///
/// [`Error`] when the source fails to parse or the render raises.
pub fn render_source_untrimmed<S: serde::Serialize>(
    name: &str,
    source: &str,
    context: &S,
) -> Result<String, Error> {
    let mut environment = Environment::new();
    environment.set_keep_trailing_newline(true);
    environment.add_filter("indent", jinja_indent);
    environment.add_template_owned(name.to_owned(), source.to_owned())?;
    environment
        .get_template(name)?
        .render(Value::from_serialize(context))
}

/// The `systemd_exec` filter — [`super::systemd_exec_join`].
///
/// Takes the command as a list of strings. A non-list, or a list
/// holding a non-string, is a template
/// bug rather than a user error, so it is an error rather than a
/// coercion — `Exec=` is the cage's entrypoint and a silently
/// stringified value there is a container that starts and does the
/// wrong thing.
fn systemd_exec(args: &Value) -> Result<String, Error> {
    let mut items: Vec<String> = Vec::new();
    for item in args.try_iter()? {
        let text = item.as_str().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidOperation,
                "systemd_exec expects a list of strings",
            )
        })?;
        items.push(text.to_owned());
    }
    Ok(super::systemd_exec_join(&items))
}

/// Jinja2's `indent(s, width=4, first=False, blank=False)`.
///
/// minijinja ships an `indent` filter, and it is not the same function.
/// Jinja2's opens with a comment-worthy quirk:
///
/// ```text
/// s += newline  # this quirk is necessary for splitlines method
/// ```
///
/// which turns a trailing newline into a final empty line that survives
/// the join — so `indent("a\nb\n", 6, first=True)` ends with a newline
/// and the next template line starts after a **blank** line. minijinja's
/// builtin strips it instead.
///
/// One filter, one blank line, and it is load-bearing: `lima.yaml.j2`
/// ends with
///
/// ```jinja
/// {{ provision_script | indent(6, first=true) }}
/// ```
///
/// so the difference is a missing blank line between the provisioning
/// script and `portForwards:` in every Lima config generated.
/// YAML does not care; the fixture comparison against the recorded
/// bytes does, and a renderer that is "equivalent" rather than equal is
/// one that stops being checkable.
///
/// Registered on both environments rather than only the Lima one: the
/// quadlet templates do not use `indent` today, and if one starts to,
/// it should get Jinja2's.
///
/// `blank` is accepted and honoured; `width` must be an integer, which
/// is all any template here passes (Jinja2 also accepts a string).
#[expect(
    clippy::needless_pass_by_value,
    reason = "minijinja's `Filter` impls are over owned argument types"
)]
fn jinja_indent(value: Value, rest: minijinja::value::Rest<Value>) -> Result<String, Error> {
    let text = value.to_string();
    let width = rest.first().map_or(Ok(4_usize), |v| {
        usize::try_from(v.as_i64().unwrap_or(4))
            .map_err(|_| Error::new(ErrorKind::InvalidOperation, "indent width must be positive"))
    })?;
    let first = rest.get(1).is_some_and(minijinja::value::Value::is_true);
    let blank = rest.get(2).is_some_and(minijinja::value::Value::is_true);
    let indention = " ".repeat(width);

    // `s += newline` then `splitlines()`: the appended newline is what
    // makes a string that already ended in one produce a final empty
    // element. Reproduced literally rather than reasoned about.
    let padded = format!("{text}\n");
    let mut lines: Vec<&str> = padded.split('\n').collect();
    // `str::split` leaves a trailing "" that `splitlines` does not.
    lines.pop();

    let mut out = if blank {
        lines.join(&format!("\n{indention}"))
    } else {
        let mut iter = lines.into_iter();
        let mut joined = iter.next().unwrap_or_default().to_owned();
        let rest: Vec<String> = iter
            .map(|line| {
                if line.is_empty() {
                    String::new()
                } else {
                    format!("{indention}{line}")
                }
            })
            .collect();
        if !rest.is_empty() {
            joined.push('\n');
            joined.push_str(&rest.join("\n"));
        }
        joined
    };
    if first {
        out.insert_str(0, &indention);
    }
    Ok(out)
}

/// Jinja2's `default(value, default_value='', boolean=False)`.
///
/// minijinja ships a two-argument `default` that substitutes only for an
/// *undefined* value. Jinja2's third argument switches the test to
/// falsiness, and `scaffolds/openclaw/cage.yaml.j2` opens with
///
/// ```jinja
/// {% set gateway_port = port | default(18789, true) %}
/// ```
///
/// which is the one construct in the scaffold corpus minijinja's builtin
/// cannot express. Without this filter the render fails outright on the
/// extra argument, and with only the two-argument semantics it would
/// succeed and emit `none` — `port` is passed as a none value, which
/// is defined-but-falsy, so `{% if port %}` and `default(..., true)`
/// have to agree that it is absent.
///
/// Registered for `d` as well, Jinja2's own alias for it.
#[expect(
    clippy::needless_pass_by_value,
    reason = "minijinja's `Function` impls are over owned argument types; \
              `Rest<Value>` by reference does not satisfy the bound"
)]
fn jinja_default(value: &Value, rest: minijinja::value::Rest<Value>) -> Value {
    let fallback = rest.first().cloned().unwrap_or_else(|| Value::from(""));
    let boolean = rest.get(1).is_some_and(Value::is_true);
    if value.is_undefined() || (boolean && !value.is_true()) {
        fallback
    } else {
        value.clone()
    }
}

/// Install a `placeholder(env_name)` global backed by `generator`.
///
/// `agentcage init` installs a placeholder generator here so a
/// rendered starter `cage.yaml` carries a concrete, unguessable token
/// rather than something the operator has to fill in later. The
/// generator is a parameter because it draws entropy — an I/O-shaped
/// concern this crate does not own — and because the golden corpus pins
/// it to a counter.
///
/// The quadlet templates never call it; `init-config.yaml.j2` and the
/// scaffolds do.
pub fn with_placeholder_global(
    mut environment: Environment<'static>,
    generator: impl Fn(&str) -> String + Send + Sync + 'static,
) -> Environment<'static> {
    environment.add_global(
        "placeholder",
        Value::from_function(move |name: &str| generator(name)),
    );
    environment
}

#[cfg(test)]
mod tests {
    use super::{environment, render};
    use minijinja::context;

    /// Every embedded `.j2` parses. This is what makes [`shared`]'s
    /// `expect` sound.
    #[test]
    fn templates_all_parse() {
        let environment = environment().expect("all templates parse");
        for name in [
            "network.j2",
            "volume.j2",
            "cage.container.j2",
            "egress.container.j2",
        ] {
            environment
                .get_template(name)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
    }

    /// `trim_blocks` + `keep_trailing_newline`, on the smallest
    /// template that shows both.
    #[test]
    fn whitespace_settings_match_jinja2() {
        let rendered =
            render("volume.j2", context! { volume_name => "agentcage-certs-x" }).expect("renders");
        assert_eq!(rendered, "[Volume]\nVolumeName=agentcage-certs-x\n");
    }

    /// A `{% for %}` body emits one line per item and no blank lines —
    /// the thing `trim_blocks` buys, and the thing a systemd unit
    /// notices.
    #[test]
    fn for_loops_do_not_leave_blank_lines() {
        let mut environment = environment().expect("environment");
        environment
            .add_template(
                "t.j2",
                "[X]\n{% for v in items %}\nV={{ v }}\n{% endfor %}\n",
            )
            .expect("parses");
        let rendered = environment
            .get_template("t.j2")
            .expect("template")
            .render(context! { items => vec!["a", "b"] })
            .expect("renders");
        assert_eq!(rendered, "[X]\nV=a\nV=b\n");
    }

    /// A `{# comment #}` block leaves nothing behind either — the
    /// quadlet templates carry several, and each one sits on its own
    /// line between two directives.
    #[test]
    fn comment_blocks_leave_no_trace() {
        let mut environment = environment().expect("environment");
        environment
            .add_template("t.j2", "A=1\n{# why A #}\nB=2\n")
            .expect("parses");
        let rendered = environment
            .get_template("t.j2")
            .expect("template")
            .render(context! {})
            .expect("renders");
        assert_eq!(rendered, "A=1\nB=2\n");
    }

    /// `loop.last`, which `egress.container.j2` uses to space
    /// `AGENTCAGE_INBOUND_PORTS`.
    #[test]
    fn loop_last_is_available() {
        let mut environment = environment().expect("environment");
        environment
            .add_template(
                "t.j2",
                "{% for v in items %}{{ v }}{% if not loop.last %} {% endif %}{% endfor %}",
            )
            .expect("parses");
        let rendered = environment
            .get_template("t.j2")
            .expect("template")
            .render(context! { items => vec!["3000", "3001"] })
            .expect("renders");
        assert_eq!(rendered, "3000 3001");
    }

    /// Map iteration order is the context's, not sorted. Without
    /// minijinja's `preserve_order` feature this test fails and every
    /// generated `Environment=` block is silently re-sorted.
    #[test]
    fn map_iteration_preserves_insertion_order() {
        let mut map = indexmap::IndexMap::new();
        map.insert("ZED".to_owned(), "1".to_owned());
        map.insert("ALPHA".to_owned(), "2".to_owned());
        let mut environment = environment().expect("environment");
        environment
            .add_template(
                "t.j2",
                "{% for k, v in env.items() %}{{ k }}={{ v }};{% endfor %}",
            )
            .expect("parses");
        let rendered = environment
            .get_template("t.j2")
            .expect("template")
            .render(context! { env => map })
            .expect("renders");
        assert_eq!(rendered, "ZED=1;ALPHA=2;");
    }

    /// The `systemd_exec` filter is reachable from a template.
    #[test]
    fn systemd_exec_filter_is_registered() {
        let mut environment = environment().expect("environment");
        environment
            .add_template("t.j2", "Exec={{ command | systemd_exec }}")
            .expect("parses");
        let rendered = environment
            .get_template("t.j2")
            .expect("template")
            .render(context! { command => vec!["bash", "-c", "echo hi"] })
            .expect("renders");
        assert_eq!(rendered, "Exec=bash -c \"echo hi\"");
    }

    /// Jinja2's three-argument `default`, which the openclaw scaffold
    /// opens with. `none | default(18789, true)` is `18789`, not
    /// `none` — and not a `TooManyArguments` error.
    #[test]
    fn default_has_jinja2s_three_argument_form() {
        let mut environment = environment().expect("environment");
        environment
            .add_template(
                "t.j2",
                "{{ port | default(18789, true) }}|{{ missing | default('x') }}|\
                 {{ port | default(18789) }}|{{ set_port | default(18789, true) }}|\
                 {{ empty | d('fallback', true) }}",
            )
            .expect("parses");
        let rendered = environment
            .get_template("t.j2")
            .expect("template")
            .render(context! {
                port => None::<i64>, set_port => 19999, empty => "",
            })
            .expect("renders");
        // `port` is defined-but-None: the boolean form substitutes, the
        // two-argument form keeps it (which is Jinja2's behaviour too,
        // and why the scaffold passes `true`) and renders it as `None`,
        // the spelling both use.
        assert_eq!(rendered, "18789|x|None|19999|fallback");
    }

    /// The `placeholder` global is reachable, and the default one
    /// refuses rather than inventing a token.
    #[test]
    fn placeholder_global_is_registered() {
        let mut environment =
            super::with_placeholder_global(environment().expect("environment"), |name| {
                format!("agentcage:secret:{name}:deadbeef")
            });
        environment
            .add_template("t.j2", "{{ placeholder('API_KEY') }}")
            .expect("parses");
        let rendered = environment
            .get_template("t.j2")
            .expect("template")
            .render(context! {})
            .expect("renders");
        assert_eq!(rendered, "agentcage:secret:API_KEY:deadbeef");

        let bare = environment_with_default_placeholder();
        assert!(bare.contains("has no generator"), "{bare}");
    }

    fn environment_with_default_placeholder() -> String {
        let mut environment = environment().expect("environment");
        environment
            .add_template("t.j2", "{{ placeholder('API_KEY') }}")
            .expect("parses");
        environment
            .get_template("t.j2")
            .expect("template")
            .render(context! {})
            .expect_err("the default refuses")
            .to_string()
    }

    /// There is no route from a template expression back into the host
    /// program — the property Jinja2's `SandboxedEnvironment` enforces
    /// and minijinja has by construction. Undefined, not an object.
    #[test]
    fn values_expose_no_host_internals() {
        let mut environment = environment().expect("environment");
        environment
            .add_template("t.j2", "[{{ s.__class__ }}][{{ s.upper }}]")
            .expect("parses");
        let rendered = environment
            .get_template("t.j2")
            .expect("template")
            .render(context! { s => "hello" })
            .expect("renders");
        assert_eq!(rendered, "[][]");
    }
}
