use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use num_bigint::BigUint;
use p256::elliptic_curve::PrimeField;
use schnorr_rs::{
    identification::{Identification, IdentificationECP256},
    SignatureScheme, SignatureSchemeECP256,
};
use sha2::Sha256;
use std::ops::Mul;

criterion_main!(signature_scheme, identification_protocol);

criterion_group! {
    name = signature_scheme;
    config = Criterion::default().sample_size(20).measurement_time(Duration::from_secs(3));
    targets = bench_signature_with_dl, bench_signature_with_ec
}

criterion_group! {
    name = identification_protocol;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(1));
    targets =
        bench_identification_issue_params_with_dl,
        bench_identification_issue_certificate_with_dl,
        bench_identification_verification_request_with_dl,
        bench_identification_verification_challenge_with_dl,
        bench_identification_verification_response_with_dl,
        bench_identification_verification_with_dl,

        bench_identification_issue_params_with_ec,
        bench_identification_issue_certificate_with_ec,
        bench_identification_verification_request_with_ec,
        bench_identification_verification_challenge_with_ec,
        bench_identification_verification_response_with_ec,
        bench_identification_verification_with_ec,
}

fn bench_signature_with_dl(c: &mut Criterion) {
    let signature_scheme = SignatureScheme::<Sha256>::from_str(
        "170635838606142236835668582024526088839118584923917947104881361096573663241835425726334688227245750988284470206339098086628427330905070264154820140913414479495481939755079707182465802484020944276739164978360438985178968038653749024959908959885446602817557541340750337331201115159158715982367397805202392369959",
        "85317919303071118417834291012263044419559292461958973552440680548286831620917712863167344113622875494142235103169549043314213665452535132077410070456707239747740969877539853591232901242010472138369582489180219492589484019326874512479954479942723301408778770670375168665600557579579357991183698902601196184979",
        "144213202463066458950689095305115948799436864106778035179311009761777898846700415257265179855055640783875383274707858827879036088093691306491953244054442062637113833957623609837630797581860524549453053884680615629934658560796659252072641537163117203253862736053101508959059343335640009185013786003173143740486",
    )
    .unwrap();

    let public_key = bincode::deserialize::<schnorr_rs::dl::PublicKey>(&[
        32, 0, 0, 0, 0, 0, 0, 0, 184, 41, 249, 24, 101, 211, 222, 105, 144, 203, 73, 144, 221, 184,
        37, 148, 129, 76, 90, 104, 247, 30, 59, 80, 53, 167, 6, 59, 25, 56, 67, 139, 48, 152, 215,
        109, 107, 147, 208, 137, 1, 93, 32, 2, 187, 51, 156, 107, 87, 133, 149, 185, 199, 27, 71,
        227, 159, 182, 157, 0, 139, 250, 65, 230, 76, 56, 109, 2, 45, 157, 13, 188, 241, 155, 225,
        197, 109, 143, 244, 194, 89, 96, 39, 145, 108, 104, 213, 203, 125, 234, 232, 63, 128, 255,
        219, 97, 184, 193, 85, 225, 143, 67, 18, 181, 162, 153, 7, 173, 242, 167, 60, 107, 116,
        169, 126, 137, 125, 162, 207, 213, 97, 21, 57, 43, 228, 7, 26, 83,
    ])
    .unwrap();
    let signing_key = bincode::deserialize::<schnorr_rs::dl::SigningKey>(&[
        32, 0, 0, 0, 0, 0, 0, 0, 51, 75, 99, 240, 183, 8, 55, 60, 11, 113, 205, 14, 78, 90, 21,
        253, 135, 94, 85, 244, 20, 8, 155, 208, 231, 183, 143, 252, 237, 149, 185, 15, 195, 166,
        71, 149, 216, 67, 185, 158, 48, 26, 158, 244, 222, 208, 108, 142, 142, 95, 237, 150, 175,
        127, 225, 72, 32, 152, 161, 32, 165, 51, 226, 108, 182, 198, 138, 50, 98, 247, 188, 231,
        216, 100, 220, 35, 243, 176, 82, 158, 213, 231, 29, 20, 171, 211, 29, 124, 119, 200, 46,
        79, 173, 184, 184, 154, 66, 229, 132, 240, 58, 133, 157, 227, 172, 217, 61, 148, 212, 112,
        232, 78, 53, 73, 179, 12, 111, 56, 67, 115, 237, 55, 131, 77, 142, 189, 6, 107,
    ])
    .unwrap();
    let message = "Hello, world!";
    let mut rng = rand::thread_rng();

    c.bench_function("signature_with_dl", |b| {
        b.iter(|| {
            signature_scheme.sign(&mut rng, &signing_key, &public_key, message);
        })
    });
}

fn bench_signature_with_ec(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let signature_scheme = SignatureSchemeECP256::<Sha256>::new();

    let public_key = bincode::deserialize::<schnorr_rs::ec::PublicKey>(&[
        33, 0, 0, 0, 0, 0, 0, 0, 3, 245, 117, 253, 38, 220, 148, 189, 244, 2, 157, 25, 124, 84,
        226, 137, 208, 121, 144, 154, 210, 231, 60, 194, 154, 51, 39, 132, 139, 244, 135, 173, 153,
    ])
    .unwrap();
    let signing_key = bincode::deserialize::<schnorr_rs::ec::SigningKey>(&[
        45, 233, 160, 91, 10, 171, 188, 116, 44, 21, 59, 221, 31, 198, 0, 197, 53, 10, 232, 246,
        112, 116, 45, 175, 47, 197, 139, 125, 115, 52, 211, 12,
    ])
    .unwrap();
    let message = "Hello, world!";

    c.bench_function("signature_with_ec", |b| {
        b.iter(|| {
            signature_scheme.sign(&mut rng, &signing_key, &public_key, message);
        })
    });
}

fn bench_identification_issue_params_with_dl(c: &mut Criterion) {
    let (protocol, _, _, _, i) = setup_for_identification_tests();
    let mut rng = rand::thread_rng();

    c.bench_function("identification_issue_params_with_dl", |b| {
        b.iter(|| {
            protocol.issue_params(&mut rng, i.clone());
        });
    });
}

fn bench_identification_issue_params_with_ec(c: &mut Criterion) {
    let (protocol, _, _, _, i) = setup_for_identification_ec_tests();
    let rng = &mut rand::thread_rng();

    c.bench_function("identification_issue_params_with_ec", |b| {
        b.iter(|| {
            protocol.issue_params(rng, i.clone());
        });
    });
}

fn bench_identification_issue_certificate_with_dl(c: &mut Criterion) {
    let (protocol, scheme, pk, sk, i) = setup_for_identification_tests();
    let rng = &mut rand::thread_rng();

    let signer = schnorr_rs::ec::Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let (_, iss_params) = protocol.issue_params(rng, i.clone());
    c.bench_function("identification_issue_certificate_with_dl", |b| {
        b.iter(|| {
            protocol.issue_certificate(rng, &signer, iss_params.clone());
        });
    });
}

fn bench_identification_issue_certificate_with_ec(c: &mut Criterion) {
    let (protocol, scheme, pk, sk, i) = setup_for_identification_ec_tests();
    let rng = &mut rand::thread_rng();

    let signer = schnorr_rs::ec::Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let (_, iss_params) = protocol.issue_params(rng, i.clone());
    c.bench_function("identification_issue_certificate_with_ec", |b| {
        b.iter(|| {
            protocol.issue_certificate(rng, &signer, iss_params.clone());
        });
    });
}

fn bench_identification_verification_request_with_dl(c: &mut Criterion) {
    let (protocol, scheme, pk, sk, i) = setup_for_identification_tests();
    let rng = &mut rand::thread_rng();

    let signer = schnorr_rs::ec::Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let cert = {
        let (_, iss_params) = protocol.issue_params(rng, i.clone());
        protocol.issue_certificate(rng, &signer, iss_params)
    };

    c.bench_function("identification_verification_request_with_dl", |b| {
        b.iter(|| {
            protocol.verification_request(rng, cert.clone());
        });
    });
}

fn bench_identification_verification_request_with_ec(c: &mut Criterion) {
    let (protocol, scheme, pk, sk, i) = setup_for_identification_ec_tests();
    let rng = &mut rand::thread_rng();

    let signer = schnorr_rs::ec::Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let cert = {
        let (_, iss_params) = protocol.issue_params(rng, i.clone());
        protocol.issue_certificate(rng, &signer, iss_params)
    };

    c.bench_function("identification_verification_request_with_ec", |b| {
        b.iter(|| {
            protocol.verification_request(rng, cert.clone());
        });
    });
}

fn bench_identification_verification_challenge_with_dl(c: &mut Criterion) {
    let (protocol, scheme, pk, sk, i) = setup_for_identification_tests();
    let rng = &mut rand::thread_rng();

    let signer = schnorr_rs::ec::Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = schnorr_rs::ec::Verifier {
        scheme: &scheme,
        key: &pk,
    };

    let cert = {
        let (_, iss_params) = protocol.issue_params(rng, i.clone());
        protocol.issue_certificate(rng, &signer, iss_params)
    };

    let (_, ver_req) = protocol.verification_request(rng, cert.clone());
    c.bench_function("identification_verification_challenge_with_dl", |b| {
        b.iter(|| {
            protocol.verification_challenge(rng, &verifier, ver_req.clone());
        });
    });
}

fn bench_identification_verification_challenge_with_ec(c: &mut Criterion) {
    let (protocol, scheme, pk, sk, i) = setup_for_identification_ec_tests();
    let rng = &mut rand::thread_rng();

    let signer = schnorr_rs::ec::Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = schnorr_rs::ec::Verifier {
        scheme: &scheme,
        key: &pk,
    };

    let cert = {
        let (_, iss_params) = protocol.issue_params(rng, i.clone());
        protocol.issue_certificate(rng, &signer, iss_params)
    };

    let (_, ver_req) = protocol.verification_request(rng, cert.clone());
    c.bench_function("identification_verification_challenge_with_ec", |b| {
        b.iter(|| {
            protocol.verification_challenge(rng, &verifier, ver_req.clone());
        });
    });
}

fn bench_identification_verification_response_with_dl(c: &mut Criterion) {
    let (protocol, scheme, pk, sk, i) = setup_for_identification_tests();
    let rng = &mut rand::thread_rng();

    let signer = schnorr_rs::ec::Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = schnorr_rs::ec::Verifier {
        scheme: &scheme,
        key: &pk,
    };

    let (iss_secret, iss_params) = protocol.issue_params(rng, i.clone());
    let cert = protocol.issue_certificate(rng, &signer, iss_params);

    let (ver_secret, ver_req) = protocol.verification_request(rng, cert.clone());
    let challenge = protocol
        .verification_challenge(rng, &verifier, ver_req.clone())
        .unwrap();
    c.bench_function("identification_verification_response_with_dl", |b| {
        b.iter(|| {
            protocol.verification_response(
                challenge.clone(),
                iss_secret.clone(),
                ver_secret.clone(),
            );
        });
    });
}

fn bench_identification_verification_response_with_ec(c: &mut Criterion) {
    let (protocol, scheme, pk, sk, i) = setup_for_identification_ec_tests();
    let rng = &mut rand::thread_rng();

    let signer = schnorr_rs::ec::Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = schnorr_rs::ec::Verifier {
        scheme: &scheme,
        key: &pk,
    };

    let (iss_secret, iss_params) = protocol.issue_params(rng, i.clone());
    let cert = protocol.issue_certificate(rng, &signer, iss_params);

    let (ver_secret, ver_req) = protocol.verification_request(rng, cert.clone());
    let challenge = protocol
        .verification_challenge(rng, &verifier, ver_req.clone())
        .unwrap();
    c.bench_function("identification_verification_response_with_ec", |b| {
        b.iter(|| {
            protocol
                .verification_response(challenge.clone(), iss_secret.clone(), ver_secret.clone())
                .unwrap();
        });
    });
}

fn bench_identification_verification_with_dl(c: &mut Criterion) {
    let (protocol, scheme, pk, sk, i) = setup_for_identification_tests();
    let rng = &mut rand::thread_rng();
    let signer = schnorr_rs::ec::Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = schnorr_rs::ec::Verifier {
        scheme: &scheme,
        key: &pk,
    };

    let (iss_secret, iss_params) = protocol.issue_params(rng, i.clone());
    let cert = protocol.issue_certificate(rng, &signer, iss_params);

    let (ver_secret, ver_req) = protocol.verification_request(rng, cert.clone());
    let challenge = protocol
        .verification_challenge(rng, &verifier, ver_req.clone())
        .unwrap();
    let response =
        protocol.verification_response(challenge.clone(), iss_secret.clone(), ver_secret.clone());
    c.bench_function("identification_verification_with_dl", |b| {
        b.iter(|| {
            protocol.verification(ver_req.clone(), challenge.clone(), response.clone());
        });
    });
}

fn bench_identification_verification_with_ec(c: &mut Criterion) {
    let (protocol, scheme, pk, sk, i) = setup_for_identification_ec_tests();
    let rng = &mut rand::thread_rng();
    let signer = schnorr_rs::ec::Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = schnorr_rs::ec::Verifier {
        scheme: &scheme,
        key: &pk,
    };

    let (iss_secret, iss_params) = protocol.issue_params(rng, i.clone());
    let cert = protocol.issue_certificate(rng, &signer, iss_params);

    let (ver_secret, ver_req) = protocol.verification_request(rng, cert.clone());
    let challenge = protocol
        .verification_challenge(rng, &verifier, ver_req.clone())
        .unwrap();
    let response = protocol
        .verification_response(challenge.clone(), iss_secret.clone(), ver_secret.clone())
        .unwrap();
    c.bench_function("identification_verification_with_ec", |b| {
        b.iter(|| {
            protocol.verification(ver_req.clone(), challenge.clone(), response.clone());
        });
    });
}

// Helper structs and functions for testing

fn setup_for_identification_tests() -> (
    Identification,
    SignatureSchemeECP256<Sha256>,
    schnorr_rs::ec::PublicKey,
    schnorr_rs::ec::SigningKey,
    BigUint,
) {
    let protocol = Identification::from_str(
        "170635838606142236835668582024526088839118584923917947104881361096573663241835425726334688227245750988284470206339098086628427330905070264154820140913414479495481939755079707182465802484020944276739164978360438985178968038653749024959908959885446602817557541340750337331201115159158715982367397805202392369959",
        "85317919303071118417834291012263044419559292461958973552440680548286831620917712863167344113622875494142235103169549043314213665452535132077410070456707239747740969877539853591232901242010472138369582489180219492589484019326874512479954479942723301408778770670375168665600557579579357991183698902601196184979",
        "144213202463066458950689095305115948799436864106778035179311009761777898846700415257265179855055640783875383274707858827879036088093691306491953244054442062637113833957623609837630797581860524549453053884680615629934658560796659252072641537163117203253862736053101508959059343335640009185013786003173143740486",
    )
    .unwrap();
    let signature_scheme = SignatureSchemeECP256::<Sha256>::new();

    let public_key = bincode::deserialize::<schnorr_rs::ec::PublicKey>(&[
        33, 0, 0, 0, 0, 0, 0, 0, 3, 245, 117, 253, 38, 220, 148, 189, 244, 2, 157, 25, 124, 84,
        226, 137, 208, 121, 144, 154, 210, 231, 60, 194, 154, 51, 39, 132, 139, 244, 135, 173, 153,
    ])
    .unwrap();
    let signing_key = bincode::deserialize::<schnorr_rs::ec::SigningKey>(&[
        45, 233, 160, 91, 10, 171, 188, 116, 44, 21, 59, 221, 31, 198, 0, 197, 53, 10, 232, 246,
        112, 116, 45, 175, 47, 197, 139, 125, 115, 52, 211, 12,
    ])
    .unwrap();
    let i = BigUint::from(123u32);

    (protocol, signature_scheme, public_key, signing_key, i)
}

fn setup_for_identification_ec_tests() -> (
    IdentificationECP256,
    SignatureSchemeECP256<Sha256>,
    schnorr_rs::ec::PublicKey,
    schnorr_rs::ec::SigningKey,
    p256::AffinePoint,
) {
    let protocol = IdentificationECP256::new();
    let signature_scheme = SignatureSchemeECP256::<Sha256>::new();

    let public_key = bincode::deserialize::<schnorr_rs::ec::PublicKey>(&[
        33, 0, 0, 0, 0, 0, 0, 0, 3, 245, 117, 253, 38, 220, 148, 189, 244, 2, 157, 25, 124, 84,
        226, 137, 208, 121, 144, 154, 210, 231, 60, 194, 154, 51, 39, 132, 139, 244, 135, 173, 153,
    ])
    .unwrap();
    let signing_key = bincode::deserialize::<schnorr_rs::ec::SigningKey>(&[
        45, 233, 160, 91, 10, 171, 188, 116, 44, 21, 59, 221, 31, 198, 0, 197, 53, 10, 232, 246,
        112, 116, 45, 175, 47, 197, 139, 125, 115, 52, 211, 12,
    ])
    .unwrap();

    let i = p256::AffinePoint::GENERATOR
        .mul(
            p256::NonZeroScalar::new(p256::Scalar::from_u128(123))
                .unwrap()
                .as_ref(),
        )
        .to_affine();

    (protocol, signature_scheme, public_key, signing_key, i)
}
