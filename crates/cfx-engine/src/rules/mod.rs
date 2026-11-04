//! Rule definitions (TOML) and their compiled form.
//!
//! A regex rule fires when **any** of its `when` groups matches, where a group matches
//! only if **all** of its patterns match. If any `unless` pattern matches, the rule does
//! not fire. Patterns are case-insensitive.

use crate::util::build_regex;
use crate::EngineError;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DEFAULT_RULES: &str = include_str!("default.toml");
pub const DEFAULT_ALLOWLIST: &str = include_str!("allowlist.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureClass {
    /// High precision. Weighted heavily.
    Structural,
    /// Medium precision. Below the warn threshold alone without context.
    Behavioral,
}

#[derive(Debug, Deserialize)]
pub struct RuleFile {
    pub version: u32,
    pub thresholds: Thresholds,
    pub multipliers: Multipliers,
    pub computed: Computed,
    #[serde(rename = "rule")]
    pub rules: Vec<RuleDef>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Thresholds {
    pub warn: f64,
    pub block: f64,
    /// Added to both thresholds. Negative = stricter. Roles tune, they never whitelist.
    #[serde(default)]
    pub role_adjust: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Multipliers {
    pub run_dialog: f64,
    pub quick_access_menu: f64,
    pub browser_unknown_origin: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Computed {
    pub trailing_decoy_prose: WeightOnly,
    pub interpreter_entropy: EntropyCfg,
    pub obfuscation_layers: LayersCfg,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WeightOnly {
    pub weight: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EntropyCfg {
    pub weight: f64,
    pub min_token_len: usize,
    pub min_bits: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LayersCfg {
    pub weight_per_layer: f64,
    pub max_layers: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleDef {
    pub id: String,
    pub class: FeatureClass,
    pub weight: f64,
    pub description: String,
    pub when: Vec<Vec<String>>,
    #[serde(default)]
    pub unless: Vec<String>,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub id: String,
    pub class: FeatureClass,
    pub weight: f64,
    pub description: String,
    when: Vec<Vec<Regex>>,
    unless: Vec<Regex>,
}

impl CompiledRule {
    /// Returns the span of the first pattern of the matching group, for evidence.
    pub fn matches(&self, text: &str) -> Option<(usize, usize)> {
        if self.unless.iter().any(|r| r.is_match(text)) {
            return None;
        }
        'group: for group in &self.when {
            let mut first = None;
            for r in group {
                match r.find(text) {
                    Some(m) => {
                        first.get_or_insert((m.start(), m.end()));
                    }
                    None => continue 'group,
                }
            }
            if first.is_some() {
                return first;
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct RuleSet {
    pub thresholds: Thresholds,
    pub multipliers: Multipliers,
    pub computed: Computed,
    pub rules: Vec<CompiledRule>,
}

/// Names of features computed in code rather than by regex.
pub const COMPUTED_FEATURES: &[(&str, FeatureClass)] = &[
    ("trailing_decoy_prose", FeatureClass::Structural),
    ("interpreter_entropy", FeatureClass::Behavioral),
    ("obfuscation_layers", FeatureClass::Behavioral),
];

impl RuleSet {
    pub fn from_toml(src: &str) -> Result<Self, EngineError> {
        let file: RuleFile = toml::from_str(src).map_err(|e| EngineError::Rules(e.to_string()))?;
        if file.version != 1 {
            return Err(EngineError::Rules(format!(
                "unsupported rule version {}",
                file.version
            )));
        }
        if file.thresholds.warn <= 0.0 || file.thresholds.block < file.thresholds.warn {
            return Err(EngineError::Rules("need 0 < warn <= block".into()));
        }
        let mut seen = std::collections::HashSet::new();
        let mut rules = Vec::new();
        for def in file.rules {
            if !seen.insert(def.id.clone()) || COMPUTED_FEATURES.iter().any(|(n, _)| *n == def.id) {
                return Err(EngineError::Rules(format!(
                    "duplicate feature id {}",
                    def.id
                )));
            }
            if def.when.is_empty() || def.when.iter().any(|g| g.is_empty()) {
                return Err(EngineError::Rules(format!(
                    "{}: empty `when` group",
                    def.id
                )));
            }
            let compile = |p: &String| {
                build_regex(p)
                    .map_err(|e| EngineError::Rules(format!("{}: bad regex {p:?}: {e}", def.id)))
            };
            let when = def
                .when
                .iter()
                .map(|g| g.iter().map(compile).collect::<Result<Vec<_>, _>>())
                .collect::<Result<Vec<_>, _>>()?;
            let unless = def
                .unless
                .iter()
                .map(compile)
                .collect::<Result<Vec<_>, _>>()?;
            rules.push(CompiledRule {
                id: def.id,
                class: def.class,
                weight: def.weight,
                description: def.description,
                when,
                unless,
            });
        }
        Ok(Self {
            thresholds: file.thresholds,
            multipliers: file.multipliers,
            computed: file.computed,
            rules,
        })
    }

    pub fn feature_ids(&self) -> Vec<String> {
        self.rules
            .iter()
            .map(|r| r.id.clone())
            .chain(COMPUTED_FEATURES.iter().map(|(n, _)| n.to_string()))
            .collect()
    }

    pub fn class_of(&self, id: &str) -> Option<FeatureClass> {
        self.rules
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.class)
            .or_else(|| {
                COMPUTED_FEATURES
                    .iter()
                    .find(|(n, _)| *n == id)
                    .map(|(_, c)| *c)
            })
    }
}
