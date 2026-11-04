//! Jira, deduplicated on the alert's dedupe key (host + command hash).
//!
//! The key is stored on the issue as a label. Before creating, we search for an open
//! issue (status category not Done) with that label. If one exists we comment on it, and
//! raise its priority when this alert maps to a higher severity band. Otherwise we create
//! one. A short local cache covers Jira's search-index lag right after a create.
//!
//! The payloads come from the template file (`create`, `comment`, optional `update`
//! sections), so the project, issue type and field mapping (including custom fields)
//! are configuration, not code.

use super::{ensure_2xx, template_ctx, Http, Output};
use crate::config::OnDuplicate;
use crate::schema::Alert;
use crate::severity::SeverityMap;
use crate::template::Template;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(15 * 60);

pub struct JiraTemplates {
    pub create: Template,
    pub comment: Template,
    pub update: Option<Template>,
}

impl JiraTemplates {
    pub fn from_template(t: &Template) -> Result<Self, String> {
        let create = t
            .section("create")
            .ok_or_else(|| format!("{}: missing \"create\" section", t.name))?;
        if !create.root().get("fields").is_some_and(Value::is_object) {
            return Err(format!(
                "{}: \"create\" must contain a \"fields\" object",
                t.name
            ));
        }
        let comment = t
            .section("comment")
            .ok_or_else(|| format!("{}: missing \"comment\" section", t.name))?;
        Ok(Self {
            create,
            comment,
            update: t.section("update"),
        })
    }
}

pub struct JiraSettings {
    pub base_url: String,
    pub search_path: String,
    pub project: String,
    pub issue_type: String,
    pub auth_header: String,
    pub label_prefix: String,
    pub on_duplicate: OnDuplicate,
}

pub struct Jira {
    s: JiraSettings,
    t: JiraTemplates,
    http: Http,
    severity: SeverityMap,
    /// dedupe label -> (issue key, created/seen at, highest rank sent)
    cache: HashMap<String, (String, Instant, usize)>,
}

struct Existing {
    key: String,
    rank: Option<usize>,
}

impl Jira {
    pub fn new(s: JiraSettings, t: JiraTemplates, http: Http, severity: SeverityMap) -> Self {
        Self {
            s,
            t,
            http,
            severity,
            cache: HashMap::new(),
        }
    }

    pub fn label_for(prefix: &str, dedupe_key: &str) -> String {
        format!("{prefix}{}", &dedupe_key[..32.min(dedupe_key.len())])
    }

    fn headers(&self) -> Vec<(String, String)> {
        vec![
            ("Authorization".into(), self.s.auth_header.clone()),
            ("Accept".into(), "application/json".into()),
        ]
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.s.base_url.trim_end_matches('/'), path)
    }

    fn ctx(&self, alert: &Alert, label: &str) -> Value {
        let mut c = template_ctx(alert);
        c.as_object_mut().unwrap().insert(
            "jira".into(),
            json!({"project": self.s.project, "issue_type": self.s.issue_type, "dedupe_label": label}),
        );
        c
    }

    fn search(&self, label: &str) -> Result<Option<Existing>, String> {
        let q = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let jql = format!(
            "project = \"{}\" AND labels = \"{}\" AND statusCategory != Done ORDER BY created DESC",
            q(&self.s.project),
            q(label)
        );
        let url = format!(
            "{}?jql={}&fields=priority&maxResults=1",
            self.url(&self.s.search_path),
            urlencode(&jql)
        );
        let r = ensure_2xx(
            "search",
            self.http.request("GET", &url, &self.headers(), None)?,
        )?;
        let v: Value = serde_json::from_str(&r.body)
            .map_err(|_| "search: unparseable response".to_string())?;
        Ok(v["issues"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|i| {
                Some(Existing {
                    key: i["key"].as_str()?.to_string(),
                    rank: i["fields"]["priority"]["name"]
                        .as_str()
                        .and_then(|p| self.severity.rank_of_jira_priority(p)),
                })
            }))
    }

    fn create(&self, ctx: &Value, label: &str) -> Result<String, String> {
        let mut body = self.t.create.render(ctx);
        // The dedupe label is always attached, whatever the template says.
        let fields = body["fields"].as_object_mut().expect("validated");
        let labels = fields.entry("labels").or_insert_with(|| json!([]));
        if !labels.is_array() {
            *labels = json!([]);
        }
        let arr = labels.as_array_mut().unwrap();
        if !arr.iter().any(|l| l == label) {
            arr.push(json!(label));
        }
        let r = ensure_2xx(
            "create issue",
            self.http.request(
                "POST",
                &self.url("/rest/api/2/issue"),
                &self.headers(),
                Some(&body),
            )?,
        )?;
        let v: Value = serde_json::from_str(&r.body).unwrap_or(Value::Null);
        v["key"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| "create issue: no key in response".into())
    }

    fn comment(&self, key: &str, ctx: &Value) -> Result<(), String> {
        let body = self.t.comment.render(ctx);
        let path = format!("/rest/api/2/issue/{}/comment", urlencode(key));
        ensure_2xx(
            "comment",
            self.http
                .request("POST", &self.url(&path), &self.headers(), Some(&body))?,
        )
        .map(|_| ())
    }

    fn update(&self, key: &str, ctx: &Value) -> Result<(), String> {
        let Some(t) = &self.t.update else {
            return Ok(());
        };
        let body = t.render(ctx);
        let path = format!("/rest/api/2/issue/{}", urlencode(key));
        ensure_2xx(
            "update issue",
            self.http
                .request("PUT", &self.url(&path), &self.headers(), Some(&body))?,
        )
        .map(|_| ())
    }
}

impl Output for Jira {
    fn name(&self) -> &str {
        "jira"
    }

    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        let label = Self::label_for(&self.s.label_prefix, alert.dedupe_key());
        let ctx = self.ctx(alert, &label);
        let rank = alert.severity_rank();

        let existing = match self.search(&label)? {
            Some(e) => Some(e),
            None => self.cache.get(&label).and_then(|(k, at, r)| {
                (at.elapsed() < CACHE_TTL).then(|| Existing {
                    key: k.clone(),
                    rank: Some(*r),
                })
            }),
        };

        match existing {
            Some(e) => {
                if self.s.on_duplicate == OnDuplicate::Skip {
                    return Ok(());
                }
                self.comment(&e.key, &ctx)?;
                // Only escalate. A priority a human set (or one we can't map) is left alone
                // unless this alert is strictly more severe than what the issue shows.
                let escalate = match e.rank {
                    Some(r) => rank > r,
                    None => false,
                };
                if escalate {
                    self.update(&e.key, &ctx)?;
                }
                let best = e.rank.unwrap_or(0).max(rank);
                self.cache.insert(label, (e.key, Instant::now(), best));
                tracing::info!(output = "jira", "commented on existing issue");
            }
            None => {
                let key = self.create(&ctx, &label)?;
                tracing::info!(output = "jira", issue = %key, "created issue");
                self.cache.insert(label, (key, Instant::now(), rank));
            }
        }
        self.cache.retain(|_, (_, at, _)| at.elapsed() < CACHE_TTL);
        Ok(())
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
