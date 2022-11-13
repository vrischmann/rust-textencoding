use criterion::{criterion_group, criterion_main, Criterion};
use textencoding::hex;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("encode", |b| {
        let data: [u8; 4] = [0xab, 0xbc, 0xbd, 0xcc];
        b.iter(|| {
            hex::encode_lower(&data);
        })
    });

    c.bench_function("encode_slice", |b| {
        let data: [u8; 4] = [0xab, 0xbc, 0xbd, 0xcc];
        let mut output = vec![0_u8; data.len() * 2];
        b.iter(|| {
            hex::encode_lower_slice(&data, &mut output).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
