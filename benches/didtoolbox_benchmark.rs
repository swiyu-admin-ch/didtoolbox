use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use didtoolbox::{did_tdw, did_tdw_jsonschema};
use std::fs;
use std::path::Path;

pub fn criterion_benchmark_did_tdw(c: &mut Criterion) {
    let inputs = [10, 50, 100, 200];

    let mut did_tdw_group = c.benchmark_group("did_tdw");
    for i in inputs {
        did_tdw_group.bench_function(BenchmarkId::new("TrustDidWeb_read", i), |b| {
            b.iter(|| {
                let did_log_raw_filepath = format!{"test_data/generated_by_didtoolbox_java/v{:03}_did.jsonl", i};
                let did_url =
                    "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085";

                let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap();

                let _ = did_tdw::TrustDidWeb::read(black_box(did_url.to_string()), black_box(did_log_raw));
            })
        });
    }
    did_tdw_group.finish();
}

pub fn criterion_benchmark_did_tdw_jsonschema(c: &mut Criterion) {
    let inputs = [10, 50, 100, 200];

    let mut group = c.benchmark_group("did_tdw_jsonschema");
    for i in inputs {
        group.bench_function(BenchmarkId::new("DidLogEntryValidator_validate", i), |b| {
            b.iter(|| {
                let did_log_raw_filepath = format!{"test_data/generated_by_didtoolbox_java/v{:03}_did.jsonl", i};
                let did_url =
                    "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085";

                let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap();

                let _ = did_tdw_jsonschema::DidLogEntryValidator::default().validate(black_box(did_log_raw));
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    criterion_benchmark_did_tdw,
    criterion_benchmark_did_tdw_jsonschema
);
criterion_main!(benches);
