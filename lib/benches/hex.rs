use criterion::{criterion_group, criterion_main, Criterion};
use textencoding::hex;

fn criterion_benchmark(c: &mut Criterion) {
    let data = vec![0xaa_u8; 64];

    c.bench_function("encode", |b| {
        b.iter(|| {
            hex::encode_lower(&data);
        })
    });

    c.bench_function("encode_slice", |b| {
        let mut output = vec![0_u8; data.len() * 2];
        b.iter(|| {
            hex::encode_lower_slice(&data, &mut output).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
