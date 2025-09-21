use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use num_bigint::BigUint;
use p256::elliptic_curve::PrimeField;
use schnorr_rs::{
    identification::Identification, PublicKey, SchnorrGroup, SchnorrP256Group, SignatureScheme,
    Signer, SigningKey, Verifier,
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
    let (signature_scheme, public_key, signing_key) = test_signature_scheme();
    let message = "Hello, world!";
    let mut rng = rand::thread_rng();

    c.bench_function("signature_with_dl", |b| {
        b.iter(|| {
            signature_scheme.sign(&mut rng, &signing_key, &public_key, message);
        })
    });
}

fn bench_signature_with_ec(c: &mut Criterion) {
    let (signature_scheme, public_key, signing_key) = test_signature_scheme_p256();
    let message = "Hello, world!";
    let mut rng = rand::thread_rng();

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

    let signer = Signer {
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

    let signer = Signer {
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

    let signer = Signer {
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

    let signer = Signer {
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

    let signer = Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = Verifier {
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

    let signer = Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = Verifier {
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

    let signer = Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = Verifier {
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

    let signer = Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = Verifier {
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
            protocol.verification_response(
                challenge.clone(),
                iss_secret.clone(),
                ver_secret.clone(),
            );
        });
    });
}

fn bench_identification_verification_with_dl(c: &mut Criterion) {
    let (protocol, scheme, pk, sk, i) = setup_for_identification_tests();
    let rng = &mut rand::thread_rng();
    let signer = Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = Verifier {
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
    let signer = Signer {
        scheme: &scheme,
        key: &sk,
        pub_key: &pk,
    };

    let verifier = Verifier {
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
    c.bench_function("identification_verification_with_ec", |b| {
        b.iter(|| {
            protocol.verification(ver_req.clone(), challenge.clone(), response.clone());
        });
    });
}

// Helper structs and functions for testing

fn setup_for_identification_tests() -> (
    Identification<SchnorrGroup>,
    SignatureScheme<SchnorrGroup, Sha256>,
    PublicKey<SchnorrGroup>,
    SigningKey<SchnorrGroup>,
    BigUint,
) {
    let protocol = schnorr_rs::identification_protocol(
        "170635838606142236835668582024526088839118584923917947104881361096573663241835425726334688227245750988284470206339098086628427330905070264154820140913414479495481939755079707182465802484020944276739164978360438985178968038653749024959908959885446602817557541340750337331201115159158715982367397805202392369959",
        "85317919303071118417834291012263044419559292461958973552440680548286831620917712863167344113622875494142235103169549043314213665452535132077410070456707239747740969877539853591232901242010472138369582489180219492589484019326874512479954479942723301408778770670375168665600557579579357991183698902601196184979",
        "144213202463066458950689095305115948799436864106778035179311009761777898846700415257265179855055640783875383274707858827879036088093691306491953244054442062637113833957623609837630797581860524549453053884680615629934658560796659252072641537163117203253862736053101508959059343335640009185013786003173143740486",
    )
    .unwrap();
    let (signature_scheme, public_key, signing_key) = test_signature_scheme();

    let i = BigUint::from(123u32);

    (protocol, signature_scheme, public_key, signing_key, i)
}

fn setup_for_identification_ec_tests() -> (
    Identification<SchnorrP256Group>,
    SignatureScheme<SchnorrP256Group, Sha256>,
    PublicKey<SchnorrP256Group>,
    SigningKey<SchnorrP256Group>,
    p256::ProjectivePoint,
) {
    let protocol = schnorr_rs::identification_protocol_p256();
    let (signature_scheme, public_key, signing_key) = test_signature_scheme_p256();

    let i = p256::AffinePoint::GENERATOR.mul(
        p256::NonZeroScalar::new(p256::Scalar::from_u128(123))
            .unwrap()
            .as_ref(),
    );

    (protocol, signature_scheme, public_key, signing_key, i)
}

fn test_signature_scheme() -> (
    SignatureScheme<SchnorrGroup, Sha256>,
    PublicKey<SchnorrGroup>,
    SigningKey<SchnorrGroup>,
) {
    let signature_scheme = schnorr_rs::signature_scheme::<Sha256>(
        "170635838606142236835668582024526088839118584923917947104881361096573663241835425726334688227245750988284470206339098086628427330905070264154820140913414479495481939755079707182465802484020944276739164978360438985178968038653749024959908959885446602817557541340750337331201115159158715982367397805202392369959",
        "85317919303071118417834291012263044419559292461958973552440680548286831620917712863167344113622875494142235103169549043314213665452535132077410070456707239747740969877539853591232901242010472138369582489180219492589484019326874512479954479942723301408778770670375168665600557579579357991183698902601196184979",
        "144213202463066458950689095305115948799436864106778035179311009761777898846700415257265179855055640783875383274707858827879036088093691306491953244054442062637113833957623609837630797581860524549453053884680615629934658560796659252072641537163117203253862736053101508959059343335640009185013786003173143740486",
    )
    .unwrap();
    let (public_key, _): (PublicKey<SchnorrGroup>, _) = bincode::serde::decode_from_slice(
        &[
            128, 124, 3, 0, 142, 56, 102, 52, 5, 46, 9, 150, 46, 180, 204, 7, 156, 75, 98, 145, 42,
            248, 58, 5, 6, 4, 145, 154, 61, 69, 194, 253, 143, 35, 41, 135, 178, 11, 231, 120, 215,
            246, 121, 156, 137, 92, 243, 30, 80, 160, 7, 218, 120, 39, 194, 151, 117, 204, 241,
            219, 96, 181, 122, 30, 216, 49, 103, 123, 170, 43, 81, 224, 191, 194, 6, 77, 143, 222,
            36, 21, 132, 148, 69, 58, 203, 41, 98, 242, 209, 169, 226, 216, 114, 154, 42, 107, 159,
            243, 159, 95, 154, 122, 224, 11, 53, 98, 27, 78, 25, 141, 15, 148, 102, 49, 113, 205,
            228, 146, 240, 219, 122, 62, 35, 104, 230, 211, 254, 174, 55,
        ],
        bincode::config::standard(),
    )
    .unwrap();

    let (signing_key, _): (SigningKey<SchnorrGroup>, _) = bincode::serde::decode_from_slice(
        &[
            132, 128, 0, 0, 0, 131, 13, 112, 105, 209, 73, 209, 145, 94, 177, 55, 204, 155, 199,
            252, 236, 155, 241, 93, 18, 104, 28, 135, 55, 48, 116, 61, 57, 214, 45, 88, 199, 36,
            75, 0, 53, 34, 123, 86, 37, 82, 102, 154, 105, 166, 113, 178, 92, 30, 23, 220, 94, 212,
            204, 187, 163, 8, 182, 215, 162, 170, 13, 52, 200, 27, 239, 193, 116, 14, 121, 164,
            168, 195, 105, 217, 101, 218, 131, 49, 246, 114, 246, 43, 141, 175, 128, 195, 20, 28,
            53, 11, 28, 106, 25, 60, 176, 253, 97, 193, 231, 148, 190, 246, 114, 28, 69, 199, 153,
            66, 120, 89, 175, 226, 23, 88, 42, 23, 40, 205, 237, 230, 44, 88, 50, 211, 154, 23, 18,
        ],
        bincode::config::standard(),
    )
    .unwrap();

    (signature_scheme, public_key, signing_key)
}

fn test_signature_scheme_p256() -> (
    SignatureScheme<SchnorrP256Group, Sha256>,
    PublicKey<SchnorrP256Group>,
    SigningKey<SchnorrP256Group>,
) {
    let signature_scheme = schnorr_rs::signature_scheme_p256::<Sha256>();

    let (public_key, _): (PublicKey<SchnorrP256Group>, _) = bincode::serde::decode_from_slice(
        &[
            65, 4, 175, 172, 124, 206, 182, 44, 253, 231, 19, 162, 117, 209, 50, 219, 10, 101, 137,
            235, 35, 122, 154, 188, 20, 66, 142, 165, 161, 46, 20, 176, 26, 133, 191, 191, 158,
            145, 176, 176, 25, 228, 64, 63, 185, 84, 205, 22, 15, 228, 79, 184, 79, 249, 117, 191,
            155, 74, 147, 221, 131, 67, 238, 193, 241, 179,
        ],
        bincode::config::standard(),
    )
    .unwrap();
    let (signing_key, _): (SigningKey<SchnorrP256Group>, _) = bincode::serde::decode_from_slice(
        &[
            36, 32, 0, 0, 0, 247, 49, 243, 32, 231, 171, 65, 149, 240, 241, 126, 214, 151, 51, 100,
            178, 254, 95, 117, 136, 173, 216, 229, 133, 65, 160, 136, 208, 24, 237, 56, 191,
        ],
        bincode::config::standard(),
    )
    .unwrap();

    (signature_scheme, public_key, signing_key)
}
