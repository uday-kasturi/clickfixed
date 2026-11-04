//! Scoring: per-feature max across layers, allowlist dampening, context multipliers,
//! role-tuned thresholds.

use crate::allowlist::Allowlist;
use crate::deobfus::DecodeTrace;
use crate::features::Hit;
use crate::rules::{FeatureClass, RuleSet};
use crate::types::{DomainClass, Observation, Origin, Target};
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Clean,
    Warn,
    Block,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Clean => "clean",
            Level::Warn => "warn",
            Level::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FeatureScore {
    pub feature: String,
    pub class: FeatureClass,
    /// Weight before dampening.
    pub raw: f64,
    /// Weight after dampening (what was summed).
    pub weight: f64,
    pub layer: usize,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Dampen {
    pub entry: String,
    pub feature: String,
    pub before: f64,
    pub after: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Multiplier {
    pub name: &'static str,
    pub factor: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub level: Level,
    pub score: f64,
    /// Sum of feature weights after dampening, before multipliers.
    pub base: f64,
    pub warn_threshold: f64,
    pub block_threshold: f64,
    pub features: Vec<FeatureScore>,
    pub dampens: Vec<Dampen>,
    pub multipliers: Vec<Multiplier>,
    /// Decoder names per resolved layer.
    pub decode_layers: Vec<Vec<&'static str>>,
    /// True when the fast path stopped decoding early (layer/time/expansion limit):
    /// Signal 3 should look at this one.
    pub needs_deep_analysis: bool,
    pub sha256: String,
    pub elapsed: Duration,
}

impl Verdict {
    pub fn fired(&self, feature: &str) -> bool {
        self.features
            .iter()
            .any(|f| f.feature == feature && f.weight > 0.0)
    }
}

pub(crate) struct ScoreInput<'a> {
    pub rules: &'a RuleSet,
    pub allowlist: Option<&'a Allowlist>,
    pub use_context: bool,
    pub obs: &'a Observation,
    pub hits: Vec<Hit>,
    pub trace: &'a DecodeTrace,
    pub interpreter_anywhere: bool,
}

#[allow(clippy::type_complexity)]
pub(crate) fn score(
    input: ScoreInput<'_>,
) -> (
    Level,
    f64,
    f64,
    f64,
    f64,
    Vec<FeatureScore>,
    Vec<Dampen>,
    Vec<Multiplier>,
) {
    let ScoreInput {
        rules,
        allowlist,
        use_context,
        obs,
        hits,
        trace,
        interpreter_anywhere,
    } = input;

    // Max per feature across layers. The same feature in the wrapper and the decoded
    // payload counts once; distinct features in different layers all count.
    let mut best: BTreeMap<String, Hit> = BTreeMap::new();
    for h in hits {
        match best.get(&h.feature) {
            Some(prev) if prev.weight >= h.weight => {}
            _ => {
                best.insert(h.feature.clone(), h);
            }
        }
    }

    let layers = trace
        .layers
        .len()
        .min(rules.computed.obfuscation_layers.max_layers);
    if layers > 0 && interpreter_anywhere {
        best.insert(
            "obfuscation_layers".into(),
            Hit {
                feature: "obfuscation_layers".into(),
                class: FeatureClass::Behavioral,
                weight: rules.computed.obfuscation_layers.weight_per_layer * layers as f64,
                layer: trace.layers.len(),
                evidence: trace
                    .layers
                    .iter()
                    .map(|l| l.decoders.join("+"))
                    .collect::<Vec<_>>()
                    .join(" > "),
            },
        );
    }

    let mut features: Vec<FeatureScore> = best
        .into_values()
        .map(|h| FeatureScore {
            feature: h.feature,
            class: h.class,
            raw: h.weight,
            weight: h.weight,
            layer: h.layer,
            evidence: h.evidence,
        })
        .collect();

    // Dampening. Each entry reduces only the features it names, never the verdict.
    let mut dampens = Vec::new();
    if let Some(al) = allowlist {
        for entry in al.entries.iter().filter(|e| e.matches(obs)) {
            for f in features
                .iter_mut()
                .filter(|f| entry.dampens.contains(&f.feature))
            {
                if f.weight <= 0.0 {
                    continue;
                }
                let before = f.weight;
                f.weight = (f.weight + entry.weight).max(0.0);
                tracing::info!(entry = %entry.id, feature = %f.feature, before, after = f.weight, "allowlist dampen");
                dampens.push(Dampen {
                    entry: entry.id.clone(),
                    feature: f.feature.clone(),
                    before,
                    after: f.weight,
                });
            }
        }
    }

    let base: f64 = features.iter().map(|f| f.weight).sum::<f64>() + 0.0; // avoid -0.0 from an empty sum

    let mut multipliers = Vec::new();
    if use_context {
        let m = &rules.multipliers;
        match obs.target {
            Target::RunDialog => multipliers.push(Multiplier {
                name: "run_dialog",
                factor: m.run_dialog,
            }),
            Target::QuickAccessMenu => multipliers.push(Multiplier {
                name: "quick_access_menu",
                factor: m.quick_access_menu,
            }),
            _ => {}
        }
        if let Origin::Browser {
            domain_class: DomainClass::Unknown,
            ..
        } = obs.origin
        {
            multipliers.push(Multiplier {
                name: "browser_unknown_origin",
                factor: m.browser_unknown_origin,
            });
        }
    }
    let score = multipliers.iter().fold(base, |s, m| s * m.factor);

    let adj = rules
        .thresholds
        .role_adjust
        .get(obs.role.as_str())
        .copied()
        .unwrap_or(0.0);
    let warn_t = rules.thresholds.warn + adj;
    let block_t = rules.thresholds.block + adj;
    let level = if score >= block_t {
        Level::Block
    } else if score >= warn_t {
        Level::Warn
    } else {
        Level::Clean
    };
    features.sort_by(|a, b| b.weight.total_cmp(&a.weight));
    (
        level,
        score,
        base,
        warn_t,
        block_t,
        features,
        dampens,
        multipliers,
    )
}
