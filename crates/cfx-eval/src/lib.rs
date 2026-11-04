//! cfx-eval: corpus in, metrics out.

use cfx_engine::{
    DomainClass, Engine, EngineConfig, Level, Observation, Origin, Target, UserRole, Verdict,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MaliciousRow {
    pub id: String,
    pub campaign: String,
    pub actor: String,
    pub platform: String,
    pub target: String,
    pub origin: String,
    pub text: String,
    pub fidelity: String,
    pub source: String,
    pub notes: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenignRow {
    pub id: String,
    pub category: String,
    pub platform: String,
    pub text: String,
    pub origin: String,
    pub target: String,
    pub role: String,
    pub bypass_risk: String,
    pub source_row: String,
    pub notes: String,
}

/// A row in either corpus reduced to what the engine needs.
#[derive(Debug, Clone)]
pub struct Case {
    pub id: String,
    pub label: String,
    pub obs: Observation,
}

pub fn parse_origin(s: &str) -> Origin {
    match s.trim() {
        "browser_vendor_docs" => Origin::Browser {
            url: None,
            domain_class: DomainClass::VendorDocs,
        },
        "browser_internal" => Origin::Browser {
            url: None,
            domain_class: DomainClass::Internal,
        },
        "browser_unknown" => Origin::Browser {
            url: None,
            domain_class: DomainClass::Unknown,
        },
        s if s.starts_with("application:") => Origin::Application {
            name: s["application:".len()..].to_string(),
        },
        _ => Origin::Unknown,
    }
}

pub fn parse_target(s: &str) -> Target {
    match s.trim() {
        "run_dialog" => Target::RunDialog,
        "quick_access_menu" => Target::QuickAccessMenu,
        s if s.starts_with("terminal") => Target::Terminal {
            shell: s
                .split_once(':')
                .map(|(_, sh)| sh.to_string())
                .unwrap_or_default(),
        },
        _ => Target::Unknown,
    }
}

pub fn parse_role(s: &str) -> UserRole {
    match s.trim() {
        "standard" => UserRole::Standard,
        "engineering" => UserRole::Engineering,
        "admin" => UserRole::Admin,
        _ => UserRole::Unknown,
    }
}

pub fn load_malicious(path: &Path) -> Result<Vec<MaliciousRow>, Box<dyn std::error::Error>> {
    let mut rdr = csv::Reader::from_path(path)?;
    Ok(rdr
        .deserialize()
        .collect::<Result<Vec<MaliciousRow>, _>>()?)
}

pub fn load_benign(path: &Path) -> Result<Vec<BenignRow>, Box<dyn std::error::Error>> {
    let mut rdr = csv::Reader::from_path(path)?;
    Ok(rdr.deserialize().collect::<Result<Vec<BenignRow>, _>>()?)
}

impl From<&MaliciousRow> for Case {
    fn from(r: &MaliciousRow) -> Self {
        Case {
            id: r.id.clone(),
            label: r.campaign.clone(),
            // The victim's role is unknown to the attacker; evaluate as a standard user.
            obs: Observation::new(r.text.clone())
                .origin(parse_origin(&r.origin))
                .target(parse_target(&r.target))
                .role(UserRole::Standard),
        }
    }
}

impl From<&BenignRow> for Case {
    fn from(r: &BenignRow) -> Self {
        Case {
            id: r.id.clone(),
            label: r.category.clone(),
            obs: Observation::new(r.text.clone())
                .origin(parse_origin(&r.origin))
                .target(parse_target(&r.target))
                .role(parse_role(&r.role)),
        }
    }
}

/// Named engine configurations for ablation.
pub fn configs() -> Vec<(&'static str, EngineConfig)> {
    let full = EngineConfig::default();
    vec![
        ("full", full),
        (
            "no_allowlist",
            EngineConfig {
                allowlist_enabled: false,
                ..full
            },
        ),
        (
            "no_deobfuscation",
            EngineConfig {
                deobfuscate: false,
                ..full
            },
        ),
        (
            "no_context (typed / Signal 2)",
            EngineConfig {
                use_context: false,
                ..full
            },
        ),
    ]
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub id: String,
    pub label: String,
    pub level: Level,
    pub score: f64,
    pub features: Vec<String>,
    pub dampened_by: Vec<String>,
}

impl CaseResult {
    fn new(c: &Case, v: &Verdict) -> Self {
        CaseResult {
            id: c.id.clone(),
            label: c.label.clone(),
            level: v.level,
            score: (v.score * 100.0).round() / 100.0,
            features: v
                .features
                .iter()
                .filter(|f| f.weight > 0.0)
                .map(|f| f.feature.clone())
                .collect(),
            dampened_by: v.dampens.iter().map(|d| d.entry.clone()).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Rates {
    pub config: String,
    pub malicious: usize,
    pub detected: usize,
    pub blocked: usize,
    pub benign: usize,
    pub false_pos: usize,
    pub false_block: usize,
    pub misses: Vec<CaseResult>,
    pub fps: Vec<CaseResult>,
}

impl Rates {
    pub fn detection_rate(&self) -> f64 {
        self.detected as f64 / self.malicious.max(1) as f64
    }
    pub fn fp_rate(&self) -> f64 {
        self.false_pos as f64 / self.benign.max(1) as f64
    }
}

pub fn evaluate(engine: &Engine, name: &str, mal: &[Case], ben: &[Case]) -> Rates {
    let mut r = Rates {
        config: name.to_string(),
        malicious: mal.len(),
        detected: 0,
        blocked: 0,
        benign: ben.len(),
        false_pos: 0,
        false_block: 0,
        misses: vec![],
        fps: vec![],
    };
    for c in mal {
        let v = engine.fast_path(&c.obs);
        match v.level {
            Level::Block => {
                r.detected += 1;
                r.blocked += 1
            }
            Level::Warn => r.detected += 1,
            Level::Clean => r.misses.push(CaseResult::new(c, &v)),
        }
    }
    for c in ben {
        let v = engine.fast_path(&c.obs);
        if v.level >= Level::Warn {
            r.false_pos += 1;
            if v.level == Level::Block {
                r.false_block += 1;
            }
            r.fps.push(CaseResult::new(c, &v));
        }
    }
    r
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FeatureStat {
    pub malicious_hits: usize,
    pub benign_hits: usize,
    pub malicious_weight: f64,
    pub benign_weight: f64,
    pub benign_dampened: usize,
}

/// Per-feature contribution on both corpora (full config). A feature that fires often on
/// benign and rarely on malicious is a rule to rework.
pub fn feature_breakdown(
    engine: &Engine,
    mal: &[Case],
    ben: &[Case],
) -> BTreeMap<String, FeatureStat> {
    let mut out: BTreeMap<String, FeatureStat> = engine
        .rules()
        .feature_ids()
        .into_iter()
        .map(|f| (f, FeatureStat::default()))
        .collect();
    for (cases, is_mal) in [(mal, true), (ben, false)] {
        for c in cases {
            let v = engine.fast_path(&c.obs);
            for f in &v.features {
                let s = out.entry(f.feature.clone()).or_default();
                if is_mal {
                    s.malicious_hits += 1;
                    s.malicious_weight += f.weight;
                } else {
                    s.benign_hits += 1;
                    s.benign_weight += f.weight;
                    if f.weight < f.raw {
                        s.benign_dampened += 1;
                    }
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct Latency {
    pub samples: usize,
    pub p50_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
    pub over_budget: usize,
}

/// Fast-path latency over every case, `iters` times each, after one warm-up pass.
pub fn latency(engine: &Engine, cases: &[Case], iters: usize) -> Latency {
    for c in cases {
        let _ = engine.fast_path(&c.obs);
    }
    let mut samples: Vec<Duration> = Vec::with_capacity(cases.len() * iters);
    for _ in 0..iters {
        for c in cases {
            let t = Instant::now();
            let v = engine.fast_path(&c.obs);
            samples.push(t.elapsed());
            std::hint::black_box(v);
        }
    }
    samples.sort();
    let pct = |p: f64| {
        let i = ((samples.len() as f64 - 1.0) * p).round() as usize;
        samples[i].as_secs_f64() * 1e6
    };
    Latency {
        samples: samples.len(),
        p50_us: pct(0.50),
        p95_us: pct(0.95),
        p99_us: pct(0.99),
        max_us: samples.last().map(|d| d.as_secs_f64() * 1e6).unwrap_or(0.0),
        over_budget: samples
            .iter()
            .filter(|d| **d > Duration::from_millis(5))
            .count(),
    }
}

/// Allowlist regression guard: for every malicious row, the allowlist must never move the
/// verdict below what it is without the allowlist. Returns offending rows.
///
/// Checked in the row's own context AND in an "attacker-best-case" context: target is a
/// terminal and the victim is an engineer, the two context facts an attacker can
/// influence (by choosing the lure and the audience). Origin stays unknown because the
/// attacker does not control which site the victim actually visited.
pub fn allowlist_regression(mal: &[Case]) -> Vec<(String, &'static str, Level, Level)> {
    let with = Engine::default();
    let without = Engine::default().with_config(EngineConfig {
        allowlist_enabled: false,
        ..EngineConfig::default()
    });
    let mut bad = vec![];
    for c in mal {
        let shell = if c.obs.text.to_ascii_lowercase().contains("powershell") {
            "powershell"
        } else {
            "bash"
        };
        let best_case = c
            .obs
            .clone()
            .target(Target::Terminal {
                shell: shell.into(),
            })
            .role(UserRole::Engineering);
        for (ctx, obs) in [("as_recorded", &c.obs), ("attacker_best_case", &best_case)] {
            let a = with.fast_path(obs).level;
            let b = without.fast_path(obs).level;
            if a < b {
                bad.push((c.id.clone(), ctx, a, b));
            }
        }
    }
    bad
}
