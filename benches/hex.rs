use criterion::{criterion_group, criterion_main, Criterion};
use textencoding::hex;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("encode", |b| {
        b.iter(|| {
            let data: [u8; 4] = [0xab, 0xbc, 0xbd, 0xcc];
            hex::encode(&data);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
