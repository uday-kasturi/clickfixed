//! Engine input types. Collectors build these; the engine never touches the OS.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// One thing the engine is asked to judge: clipboard content or a command line.
#[derive(Debug, Clone)]
pub struct Observation {
    /// Clipboard content or command line. Treated as hostile.
    pub text: String,
    /// Where the text came from. The highest-value feature, and the one EDR cannot see.
    pub origin: Origin,
    /// Where the text is going.
    pub target: Target,
    /// Tunes thresholds. Never whitelists.
    pub role: UserRole,
    pub timestamp: SystemTime,
}

impl Observation {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            origin: Origin::Unknown,
            target: Target::Unknown,
            role: UserRole::Unknown,
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }
    pub fn origin(mut self, origin: Origin) -> Self {
        self.origin = origin;
        self
    }
    pub fn target(mut self, target: Target) -> Self {
        self.target = target;
        self
    }
    pub fn role(mut self, role: UserRole) -> Self {
        self.role = role;
        self
    }
    pub fn at(mut self, ts: SystemTime) -> Self {
        self.timestamp = ts;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Origin {
    Browser {
        url: Option<String>,
        domain_class: DomainClass,
    },
    Application {
        name: String,
    },
    Unknown,
}

impl Origin {
    /// The origin class used by allowlist context entries.
    /// Only a browser origin can be `vendor_docs` or `internal`; everything else is `unknown`.
    pub fn class(&self) -> DomainClass {
        match self {
            Origin::Browser { domain_class, .. } => *domain_class,
            _ => DomainClass::Unknown,
        }
    }
    pub fn app_name(&self) -> Option<&str> {
        match self {
            Origin::Application { name } => Some(name),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainClass {
    VendorDocs,
    Internal,
    Unknown,
}

impl DomainClass {
    pub fn as_str(self) -> &'static str {
        match self {
            DomainClass::VendorDocs => "vendor_docs",
            DomainClass::Internal => "internal",
            DomainClass::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    /// Win+R. Highest signal: almost no benign workflow pastes here.
    RunDialog,
    Terminal {
        shell: String,
    },
    /// Win+X. The known RunMRU evasion.
    QuickAccessMenu,
    Unknown,
}

impl Target {
    pub fn as_str(&self) -> &'static str {
        match self {
            Target::RunDialog => "run_dialog",
            Target::Terminal { .. } => "terminal",
            Target::QuickAccessMenu => "quick_access_menu",
            Target::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Standard,
    Engineering,
    Admin,
    Unknown,
}

impl UserRole {
    pub fn as_str(self) -> &'static str {
        match self {
            UserRole::Standard => "standard",
            UserRole::Engineering => "engineering",
            UserRole::Admin => "admin",
            UserRole::Unknown => "unknown",
        }
    }
}

/// Default-deny origin classifier. A host is `vendor_docs` or `internal` only if it is
/// explicitly listed (exact host or a subdomain of a listed host). Everything else is
/// `unknown`, so fresh attacker infrastructure gets no benefit and there is no
/// bad-domain list to maintain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainClassifier {
    #[serde(default)]
    pub vendor_docs: Vec<String>,
    #[serde(default)]
    pub internal: Vec<String>,
}

impl DomainClassifier {
    pub fn classify_url(&self, url: &str) -> DomainClass {
        match host_of(url) {
            Some(h) => self.classify_host(&h),
            None => DomainClass::Unknown,
        }
    }

    pub fn classify_host(&self, host: &str) -> DomainClass {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let hit = |list: &[String]| {
            list.iter().any(|d| {
                let d = d.trim_start_matches("*.").to_ascii_lowercase();
                host == d || host.ends_with(&format!(".{d}"))
            })
        };
        // Internal wins over vendor if both match; neither is checked unless listed.
        if hit(&self.internal) {
            DomainClass::Internal
        } else if hit(&self.vendor_docs) {
            DomainClass::VendorDocs
        } else {
            DomainClass::Unknown
        }
    }
}

/// Extract the host from a URL without pulling in a URL crate.
/// Userinfo (`user@host`) is stripped so `https://docs.rs@evil.example` classifies as evil.example.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let hostport = authority.rsplit('@').next()?;
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        stripped.split(']').next()?
    } else {
        hostport.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_is_default_deny() {
        let c = DomainClassifier {
            vendor_docs: vec!["rustup.rs".into(), "brew.sh".into()],
            internal: vec!["corp.example".into()],
        };
        assert_eq!(
            c.classify_url("https://rustup.rs/"),
            DomainClass::VendorDocs
        );
        assert_eq!(
            c.classify_url("https://www.brew.sh/x"),
            DomainClass::VendorDocs
        );
        assert_eq!(
            c.classify_url("https://wiki.corp.example/a"),
            DomainClass::Internal
        );
        assert_eq!(
            c.classify_url("https://rustup.rs.evil.example/"),
            DomainClass::Unknown
        );
        assert_eq!(
            c.classify_url("https://evilrustup.rs/"),
            DomainClass::Unknown
        );
        assert_eq!(
            c.classify_url("https://rustup.rs@evil.example/"),
            DomainClass::Unknown
        );
        assert_eq!(c.classify_url("not a url"), DomainClass::Unknown);
    }
}
