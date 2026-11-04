use cfx_engine::{DomainClass, Engine, Observation, Origin, Target};
use cfx_eval::*;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cfx-eval", about = "Score corpora with the clickfixed engine")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Detection rate, FP rate, ablations, per-feature breakdown, latency.
    Run {
        #[arg(long, default_value = "corpus/malicious.csv")]
        malicious: PathBuf,
        #[arg(long, default_value = "corpus/benign.csv")]
        benign: PathBuf,
        /// Latency iterations per row.
        #[arg(long, default_value_t = 200)]
        iters: usize,
        /// Write a markdown report here.
        #[arg(long)]
        markdown: Option<PathBuf>,
        /// Print every miss and false positive.
        #[arg(long)]
        verbose: bool,
    },
    /// Explain the verdict for one command.
    Explain {
        text: String,
        #[arg(long, default_value = "unknown")]
        origin: String,
        #[arg(long, default_value = "unknown")]
        target: String,
        #[arg(long, default_value = "unknown")]
        role: String,
        /// Run the deep (Signal 3) path and print IOCs.
        #[arg(long)]
        deep: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Run {
            malicious,
            benign,
            iters,
            markdown,
            verbose,
        } => run(malicious, benign, iters, markdown, verbose),
        Cmd::Explain {
            text,
            origin,
            target,
            role,
            deep,
        } => {
            let engine = Engine::default();
            let obs = Observation::new(text)
                .origin(parse_origin(&origin))
                .target(parse_target(&target))
                .role(parse_role(&role));
            if deep {
                println!("{}", serde_json::to_string_pretty(&engine.analyze(&obs))?);
            } else {
                println!("{}", serde_json::to_string_pretty(&engine.fast_path(&obs))?);
            }
            Ok(())
        }
    }
}

fn run(
    mal_p: PathBuf,
    ben_p: PathBuf,
    iters: usize,
    md: Option<PathBuf>,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mal: Vec<Case> = load_malicious(&mal_p)?.iter().map(Case::from).collect();
    let ben: Vec<Case> = load_benign(&ben_p)?.iter().map(Case::from).collect();
    let mut out = String::new();
    let mut p = |s: String| {
        println!("{s}");
        out.push_str(&s);
        out.push('\n');
    };

    p(format!(
        "# clickfixed evaluation\n\nmalicious: {} rows ({}), benign: {} rows ({})\n",
        mal.len(),
        mal_p.display(),
        ben.len(),
        ben_p.display()
    ));
    p("## Detection / false positives (fast path)\n".into());
    p("| config | detected | blocked | FP (warn+) | FP block |\n|---|---|---|---|---|".into());
    let mut full_rates = None;
    for (name, cfg) in configs() {
        let engine = Engine::default().with_config(cfg);
        let r = evaluate(&engine, name, &mal, &ben);
        p(format!(
            "| {} | {}/{} ({:.1}%) | {} | {}/{} ({:.1}%) | {} |",
            name,
            r.detected,
            r.malicious,
            100.0 * r.detection_rate(),
            r.blocked,
            r.false_pos,
            r.benign,
            100.0 * r.fp_rate(),
            r.false_block
        ));
        if full_rates.is_none() {
            full_rates = Some(r);
        }
    }
    let full = full_rates.unwrap();

    p("\n## Misses (full config)\n".into());
    for m in &full.misses {
        p(format!(
            "- {} {} score={} features={:?}",
            m.id, m.label, m.score, m.features
        ));
    }
    if full.misses.is_empty() {
        p("none".into());
    }
    p("\n## False positives (full config)\n".into());
    for f in &full.fps {
        p(format!(
            "- {} {} {:?} score={} features={:?} dampened_by={:?}",
            f.id, f.label, f.level, f.score, f.features, f.dampened_by
        ));
    }
    if full.fps.is_empty() {
        p("none".into());
    }
    if verbose {
        for c in mal.iter().chain(ben.iter()) {
            let v = Engine::default().fast_path(&c.obs);
            eprintln!(
                "{} {:?} {:.2} {:?}",
                c.id,
                v.level,
                v.score,
                v.features.iter().map(|f| &f.feature).collect::<Vec<_>>()
            );
        }
    }

    let engine = Engine::default();
    p("\n## Per-feature contribution (full config)\n".into());
    p("| feature | malicious hits | benign hits | benign dampened | malicious weight | benign weight |\n|---|---|---|---|---|---|".into());
    for (f, s) in feature_breakdown(&engine, &mal, &ben) {
        p(format!(
            "| {f} | {} | {} | {} | {:.2} | {:.2} |",
            s.malicious_hits, s.benign_hits, s.benign_dampened, s.malicious_weight, s.benign_weight
        ));
    }

    let all: Vec<Case> = mal.iter().chain(ben.iter()).cloned().collect();
    let l = latency(&engine, &all, iters);
    p(format!(
        "\n## Fast-path latency\n\n{} samples: p50 {:.1} µs, p95 {:.1} µs, p99 {:.1} µs, max {:.1} µs, over 5 ms budget: {}\n",
        l.samples, l.p50_us, l.p95_us, l.p99_us, l.max_us, l.over_budget
    ));

    let reg = allowlist_regression(&mal);
    p("## Allowlist regression\n".into());
    if reg.is_empty() {
        p("PASS: no malicious row's verdict is lowered by any allowlist entry (as recorded and in attacker-best-case context).".into());
    } else {
        for (id, ctx, a, b) in &reg {
            p(format!(
                "FAIL {id} [{ctx}]: {a:?} with allowlist vs {b:?} without"
            ));
        }
    }

    // Keep these imports used for the explain path.
    let _ = (Origin::Unknown, DomainClass::Unknown, Target::Unknown);
    if let Some(path) = md {
        std::fs::write(&path, out)?;
        eprintln!("wrote {}", path.display());
    }
    Ok(())
}
