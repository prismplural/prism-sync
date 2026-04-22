use criterion::{criterion_group, criterion_main, Criterion};
use prism_sync_crypto::pq::HybridSignature;
use prism_sync_crypto::{DeviceSecret, DeviceSigningKey};

fn bench_hybrid_sign_verify(c: &mut Criterion) {
    let device_secret = DeviceSecret::generate();
    let device_id = "bench-device";
    let ed25519_kp = device_secret.ed25519_keypair(device_id).unwrap();
    let ml_dsa_kp = device_secret.ml_dsa_65_keypair(device_id).unwrap();

    // 4KB representative message (typical batch canonical data size)
    let message = vec![0x42u8; 4096];
    let context = b"sync_batch";

    // Extract inner signing keys for use with HybridSignature::sign_v3
    let ed25519_sk = ed25519_kp.into_signing_key();
    let ed25519_pk: [u8; 32] = ed25519_sk.verifying_key().to_bytes();
    let ml_dsa_pk = ml_dsa_kp.public_key_bytes();
    let ml_dsa_sk = ml_dsa_kp;

    // Pre-sign for verify benchmark
    let sig = HybridSignature::sign_v3(&message, context, &ed25519_sk, ml_dsa_sk.as_signing_key())
        .unwrap();

    // Pre-sign Ed25519-only over raw message for baseline comparison
    let ed25519_only_sig = {
        use ed25519_dalek::Signer;
        ed25519_sk.sign(&message).to_bytes().to_vec()
    };

    let mut group = c.benchmark_group("hybrid_signature");

    group.bench_function("sign_v3_hybrid", |b| {
        b.iter(|| {
            HybridSignature::sign_v3(&message, context, &ed25519_sk, ml_dsa_sk.as_signing_key())
                .unwrap()
        })
    });

    group.bench_function("verify_v3_hybrid", |b| {
        b.iter(|| sig.verify_v3(&message, context, &ed25519_pk, &ml_dsa_pk).unwrap())
    });

    // Ed25519-only baseline for comparison — sign/verify raw message directly
    group.bench_function("sign_ed25519_only", |b| {
        use ed25519_dalek::Signer;
        b.iter(|| ed25519_sk.sign(&message).to_bytes().to_vec())
    });

    group.bench_function("verify_ed25519_only", |b| {
        b.iter(|| DeviceSigningKey::verify(&ed25519_pk, &message, &ed25519_only_sig).unwrap())
    });

    group.finish();
}

criterion_group!(benches, bench_hybrid_sign_verify);
criterion_main!(benches);
