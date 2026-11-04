//! Severity mapping: the single source of truth for every output's severity form.
//!
//! The engine owns the verdict (its warn/block thresholds, including role adjustment).
//! This mapping owns how a verdict + score is *rendered*: Wazuh level, syslog severity,
//! CEF severity, ECS `event.severity`, Slack colour and Jira priority. Outputs read the
//! band stamped on the alert; none of them computes a threshold of its own.

use cfx_engine::Level;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictName {
    Benign,
    Suspicious,
    Malicious,
}

impl VerdictName {
    pub fn from_level(l: Level) -> Self {
        match l {
            Level::Clean => Self::Benign,
            Level::Warn => Self::Suspicious,
            Level::Block => Self::Malicious,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Benign => "benign",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
        }
    }
}

/// One severity band. Bands are listed lowest to highest; a band's rank is its index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Band {
    pub name: String,
    /// Which engine verdict this band applies to.
    pub verdict: VerdictName,
    /// Escalate within a verdict: the highest band whose `min_score` <= score wins.
    #[serde(default)]
    pub min_score: f64,
    /// Wazuh rule level, 0-15.
    pub wazuh_level: u8,
    /// Syslog severity, 0 (emergency) - 7 (debug).
    pub syslog: u8,
    /// CEF severity, 0-10.
    pub cef: u8,
    /// ECS `event.severity`, 0-100.
    pub ecs: u8,
    pub slack_color: String,
    pub jira_priority: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SeverityMap {
    bands: Vec<Band>,
}

pub const DEFAULT_BANDS: &str = r##"
[[severity]]
name = "medium"
verdict = "suspicious"
min_score = 0.0
wazuh_level = 7
syslog = 4
cef = 5
ecs = 47
slack_color = "#e8a317"
jira_priority = "Medium"

[[severity]]
name = "high"
verdict = "malicious"
min_score = 0.0
wazuh_level = 12
syslog = 2
cef = 8
ecs = 73
slack_color = "#d40e0d"
jira_priority = "High"

[[severity]]
name = "critical"
verdict = "malicious"
min_score = 3.0
wazuh_level = 14
syslog = 1
cef = 10
ecs = 99
slack_color = "#6b0000"
jira_priority = "Highest"
"##;

pub fn default_bands() -> Vec<Band> {
    #[derive(Deserialize)]
    struct F {
        severity: Vec<Band>,
    }
    toml::from_str::<F>(DEFAULT_BANDS)
        .expect("default severity bands parse")
        .severity
}

impl Default for SeverityMap {
    fn default() -> Self {
        Self::new(default_bands()).expect("default severity bands are valid")
    }
}

impl SeverityMap {
    /// Validates ordering and ranges. Every non-benign verdict must have a base band
    /// (`min_score = 0`) so no suspicious or malicious verdict is ever left unmapped.
    pub fn new(bands: Vec<Band>) -> Result<Self, String> {
        if bands.is_empty() {
            return Err("alerts.severity: at least one band is required".into());
        }
        if bands.len() > 20 {
            return Err("alerts.severity: at most 20 bands".into());
        }
        let mut names = std::collections::HashSet::new();
        for (i, b) in bands.iter().enumerate() {
            let at = format!("alerts.severity[{i}] ({})", b.name);
            if b.name.is_empty()
                || !b
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(format!("{at}: name must be [A-Za-z0-9_-]+"));
            }
            if !names.insert(b.name.clone()) {
                return Err(format!("{at}: duplicate name"));
            }
            if b.wazuh_level > 15 || b.syslog > 7 || b.cef > 10 || b.ecs > 100 {
                return Err(format!(
                    "{at}: out of range (wazuh 0-15, syslog 0-7, cef 0-10, ecs 0-100)"
                ));
            }
            if !(b.min_score.is_finite() && b.min_score >= 0.0) {
                return Err(format!("{at}: min_score must be >= 0"));
            }
            if !b.slack_color.starts_with('#') || b.jira_priority.is_empty() {
                return Err(format!(
                    "{at}: slack_color must be #rrggbb and jira_priority non-empty"
                ));
            }
            if i > 0 {
                let p = &bands[i - 1];
                let ordered =
                    p.verdict < b.verdict || (p.verdict == b.verdict && p.min_score < b.min_score);
                if !ordered {
                    return Err(format!(
                        "{at}: bands must be listed lowest to highest (by verdict, then min_score)"
                    ));
                }
                if b.wazuh_level < p.wazuh_level
                    || b.cef < p.cef
                    || b.ecs < p.ecs
                    || b.syslog > p.syslog
                {
                    return Err(format!(
                        "{at}: a higher band cannot have a lower severity than the band before it"
                    ));
                }
            }
        }
        for v in [VerdictName::Suspicious, VerdictName::Malicious] {
            if !bands.iter().any(|b| b.verdict == v && b.min_score == 0.0) {
                return Err(format!(
                    "alerts.severity: no base band (min_score = 0) for verdict \"{}\"",
                    v.as_str()
                ));
            }
        }
        Ok(Self { bands })
    }

    pub fn bands(&self) -> &[Band] {
        &self.bands
    }

    /// The band for a verdict and score, with its rank. `None` means "do not alert"
    /// (benign with no benign band configured).
    pub fn classify(&self, verdict: VerdictName, score: f64) -> Option<(usize, &Band)> {
        self.bands
            .iter()
            .enumerate()
            .rev()
            .find(|(_, b)| b.verdict == verdict && b.min_score <= score)
    }

    pub fn rank_of(&self, name: &str) -> Option<usize> {
        self.bands.iter().position(|b| b.name == name)
    }

    /// Highest rank whose Jira priority is `priority` (to read back an issue's severity).
    pub fn rank_of_jira_priority(&self, priority: &str) -> Option<usize> {
        self.bands
            .iter()
            .rposition(|b| b.jira_priority.eq_ignore_ascii_case(priority))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mapping() {
        let m = SeverityMap::default();
        assert_eq!(m.classify(VerdictName::Benign, 0.9), None);
        assert_eq!(
            m.classify(VerdictName::Suspicious, 1.2).unwrap().1.name,
            "medium"
        );
        assert_eq!(
            m.classify(VerdictName::Malicious, 2.1).unwrap().1.name,
            "high"
        );
        assert_eq!(
            m.classify(VerdictName::Malicious, 3.4).unwrap().1.name,
            "critical"
        );
        assert_eq!(m.rank_of_jira_priority("high"), Some(1));
    }

    #[test]
    fn rejects_unmapped_verdict_and_disorder() {
        let mut b = default_bands();
        b.remove(0);
        assert!(SeverityMap::new(b).unwrap_err().contains("suspicious"));
        let mut b = default_bands();
        b.swap(1, 2);
        assert!(SeverityMap::new(b).is_err());
        let mut b = default_bands();
        b[2].wazuh_level = 3;
        assert!(SeverityMap::new(b).is_err());
    }
}
