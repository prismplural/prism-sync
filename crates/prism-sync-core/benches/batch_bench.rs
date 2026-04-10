use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::SigningKey;
use prism_sync_core::batch_signature::{compute_payload_hash, sign_batch, verify_batch_signature};
use prism_sync_crypto::DeviceSecret;
use rand::rngs::OsRng;

fn bench_batch_sign_verify(c: &mut Criterion) {
    // Generate Ed25519 keypair
    let ed25519_sk = SigningKey::generate(&mut OsRng);
    let ed25519_pk: [u8; 32] = ed25519_sk.verifying_key().to_bytes();

    // Generate ML-DSA-65 keypair via DeviceSecret
    let device_secret = DeviceSecret::generate();
    let ml_dsa_kp = device_secret.ml_dsa_65_keypair("bench-device").unwrap();
    let ml_dsa_pk = ml_dsa_kp.public_key_bytes();

    // 4KB representative payload (typical batch canonical data size)
    let plaintext = vec![0x42u8; 4096];
    let payload_hash = compute_payload_hash(&plaintext);
    let nonce = [0u8; 24];
    let ciphertext = vec![0xAAu8; 4096];

    // Pre-sign for verify benchmark
    let envelope = sign_batch(
        &ed25519_sk,
        &ml_dsa_kp,
        "bench-sync-id-0000-0000-0000-000000000001",
        0,
        "bench-batch-id-0000-0000-0000-000000000001",
        "ops",
        "bench-device",
        0,
        &payload_hash,
        nonce,
        ciphertext.clone(),
    )
    .expect("sign_batch should succeed");

    // Print wire size comparison once (printed to stderr during benchmark run)
    let v3_sig_size = envelope.signature.len();
    eprintln!(
        "Wire size: V3 hybrid signature = {} bytes, Ed25519-only = 64 bytes ({:.1}x larger)",
        v3_sig_size,
        v3_sig_size as f64 / 64.0
    );

    let mut group = c.benchmark_group("batch_signature");

    group.bench_function("sign_batch_v3_hybrid", |b| {
        b.iter(|| {
            sign_batch(
                &ed25519_sk,
                &ml_dsa_kp,
                "bench-sync-id-0000-0000-0000-000000000001",
                0,
                "bench-batch-id-0000-0000-0000-000000000001",
                "ops",
                "bench-device",
                0,
                &payload_hash,
                nonce,
                ciphertext.clone(),
            )
            .unwrap()
        })
    });

    group.bench_function("verify_batch_signature_v3_hybrid", |b| {
        b.iter(|| {
            verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).unwrap()
        })
    });

    group.finish();
}

criterion_group!(benches, bench_batch_sign_verify);
criterion_main!(benches);
