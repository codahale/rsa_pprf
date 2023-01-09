use criterion::{criterion_group, criterion_main, Criterion};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use rsa_pprf::PuncturablePrf;
use sha2::Sha256;

fn generate(c: &mut Criterion) {
    let mut g = c.benchmark_group("generate");
    let mut rng = ChaChaRng::seed_from_u64(0xDEAD_BEEF);

    for size in [1024, 2048, 4096] {
        g.bench_function(format!("{size}"), |b| {
            b.iter(|| PuncturablePrf::<Sha256>::generate(&mut rng, size, 32))
        });
    }

    g.finish()
}

fn eval(c: &mut Criterion) {
    let mut g = c.benchmark_group("eval");
    let mut rng = ChaChaRng::seed_from_u64(0xDEAD_BEEF);

    for size in [1024, 2048, 4096] {
        for punctures in [32, 64, 128, 256] {
            g.bench_function(format!("{size}/{punctures}"), |b| {
                let pprf = PuncturablePrf::<Sha256>::generate(&mut rng, size, punctures).unwrap();
                b.iter(|| pprf.eval(1))
            });
        }
    }

    g.finish()
}

criterion_group!(all, generate, eval);
criterion_main!(all);
