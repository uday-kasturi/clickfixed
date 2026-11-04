//! Generic HTTP POST sender driven by a template file (Slack, Teams, PagerDuty, a SOAR...).

use super::{ensure_2xx, template_ctx, Http, Output};
use crate::schema::Alert;
use crate::template::Template;

pub struct Webhook {
    name: String,
    url: String,
    headers: Vec<(String, String)>,
    template: Template,
    http: Http,
}

impl Webhook {
    pub fn new(
        name: String,
        url: String,
        headers: Vec<(String, String)>,
        template: Template,
        http: Http,
    ) -> Self {
        Self {
            name: format!("webhook:{name}"),
            url,
            headers,
            template,
            http,
        }
    }
}

impl Output for Webhook {
    fn name(&self) -> &str {
        &self.name
    }
    fn send(&mut self, alert: &Alert) -> Result<(), String> {
        let body = self.template.render(&template_ctx(alert));
        let r = self
            .http
            .request("POST", &self.url, &self.headers, Some(&body))?;
        ensure_2xx("POST", r).map(|_| ())
    }
}
