//! Outputs. Each implements [`Output`] and runs on its own thread behind its own bounded
//! queue (see [`crate::sink`]), so one slow or failing output never delays another.

pub mod jira;
pub mod jsonl;
pub mod syslog;
pub mod webhook;

use crate::schema::Alert;
use serde_json::{json, Value};
use std::time::Duration;

pub trait Output: Send {
    fn name(&self) -> &str;
    /// Deliver one alert. Errors are logged by the sink with the output name; they must
    /// not contain alert content (HTTP bodies are never echoed).
    fn send(&mut self, alert: &Alert) -> Result<(), String>;
}

/// Template context: the alert's JSON, plus `alert` (the whole thing) and `fmt.*` helpers.
pub fn template_ctx(alert: &Alert) -> Value {
    let mut v = alert.to_value();
    let d = &alert.clickfixed;
    let features = d
        .features
        .iter()
        .filter(|f| f.weight > 0.0)
        .map(|f| format!("{} (+{:.2}, layer {})", f.id, f.weight, f.layer))
        .collect::<Vec<_>>();
    let dampens = d
        .dampened_by
        .iter()
        .map(|x| format!("{}: {} -{:.2}", x.entry, x.feature, x.amount))
        .collect::<Vec<_>>();
    let origin = match (&alert.url, d.origin.kind) {
        (Some(u), _) => format!("{} ({})", u.full, d.origin.domain_class),
        (None, "application") => format!(
            "application: {}",
            d.origin.source_app.as_deref().unwrap_or("?")
        ),
        (None, k) => k.to_string(),
    };
    let process = alert
        .process
        .as_ref()
        .map(|p| {
            format!(
                "pid {} {}{}",
                p.pid,
                p.name.as_deref().unwrap_or("?"),
                p.parent
                    .as_ref()
                    .map(|x| format!(" (parent {})", x.name))
                    .unwrap_or_default()
            )
        })
        .unwrap_or_else(|| "-".into());
    let fmt = json!({
        "title": format!("ClickFix {}: {} on {}", d.verdict.as_str(), alert.rule.name, alert.host.name),
        "features": if features.is_empty() { "-".to_string() } else { features.join(", ") },
        "dampens": if dampens.is_empty() { "none".to_string() } else { dampens.join(", ") },
        "multipliers": if d.multipliers.is_empty() { "none".to_string() } else {
            d.multipliers.iter().map(|m| format!("{} x{}", m.name, m.factor)).collect::<Vec<_>>().join(", ")
        },
        "origin": origin,
        "process": process,
        "decoded": d.command.decoded.clone()
            .unwrap_or_else(|| "(no encoded layer; the raw command is never transmitted)".into()),
        "score": format!("{:.2}", d.score),
    });
    let obj = v.as_object_mut().expect("alert is an object");
    obj.insert("alert".into(), alert.to_value());
    obj.insert("fmt".into(), fmt);
    v
}

/// Shared blocking HTTP sender with timeouts and bounded retries.
pub struct Http {
    agent: ureq::Agent,
    retries: u32,
}

pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

impl Http {
    pub fn new(timeout: Duration, retries: u32) -> Self {
        let builder = ureq::Agent::config_builder();
        #[cfg(windows)]
        let builder = builder.tls_config(
            ureq::tls::TlsConfig::builder()
                .provider(ureq::tls::TlsProvider::NativeTls)
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        );
        let agent: ureq::Agent = builder
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .user_agent(concat!("clickfixed/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self { agent, retries }
    }

    /// `body` is a JSON value; `None` sends no body (GET).
    pub fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<HttpResponse, String> {
        let mut attempt = 0;
        loop {
            let r = self.once(method, url, headers, body);
            let retryable = match &r {
                Err(_) => true,
                Ok(resp) => resp.status == 429 || resp.status >= 500,
            };
            if !retryable || attempt >= self.retries {
                return r;
            }
            attempt += 1;
            std::thread::sleep(Duration::from_millis(250 * (1 << attempt.min(5))));
        }
    }

    fn once(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<HttpResponse, String> {
        let res = match (method, body) {
            ("GET", _) => {
                let mut rq = self.agent.get(url);
                for (k, v) in headers {
                    rq = rq.header(k, v);
                }
                rq.call()
            }
            (m, b) => {
                let payload = b.map(|v| v.to_string()).unwrap_or_default();
                let mut rq = match m {
                    "PUT" => self.agent.put(url),
                    _ => self.agent.post(url),
                };
                for (k, v) in headers {
                    rq = rq.header(k, v);
                }
                rq.header("Content-Type", "application/json").send(payload)
            }
        };
        match res {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                let body = resp
                    .body_mut()
                    .with_config()
                    .limit(1024 * 1024)
                    .read_to_string()
                    .unwrap_or_default();
                Ok(HttpResponse { status, body })
            }
            // Transport errors only (status errors are disabled). No URL in the message:
            // it may be a secret.
            Err(e) => Err(format!("transport error: {}", error_kind(&e))),
        }
    }
}

fn error_kind(e: &ureq::Error) -> &'static str {
    match e {
        ureq::Error::Timeout(_) => "timeout",
        ureq::Error::HostNotFound => "host not found",
        ureq::Error::ConnectionFailed => "connection failed",
        ureq::Error::Io(_) => "io",
        ureq::Error::Tls(_) => "tls",
        _ => "request failed",
    }
}

pub fn ensure_2xx(what: &str, r: HttpResponse) -> Result<HttpResponse, String> {
    if (200..300).contains(&r.status) {
        Ok(r)
    } else {
        Err(format!("{what}: HTTP {}", r.status))
    }
}
