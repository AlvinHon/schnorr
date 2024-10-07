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
    SignatureScheme<SchnorrP256Group, Sha256>,
    PublicKey<SchnorrP256Group>,
    SigningKey<SchnorrP256Group>,
    BigUint,
) {
    let protocol = schnorr_rs::identification_protocol(
        "170635838606142236835668582024526088839118584923917947104881361096573663241835425726334688227245750988284470206339098086628427330905070264154820140913414479495481939755079707182465802484020944276739164978360438985178968038653749024959908959885446602817557541340750337331201115159158715982367397805202392369959",
        "85317919303071118417834291012263044419559292461958973552440680548286831620917712863167344113622875494142235103169549043314213665452535132077410070456707239747740969877539853591232901242010472138369582489180219492589484019326874512479954479942723301408778770670375168665600557579579357991183698902601196184979",
        "144213202463066458950689095305115948799436864106778035179311009761777898846700415257265179855055640783875383274707858827879036088093691306491953244054442062637113833957623609837630797581860524549453053884680615629934658560796659252072641537163117203253862736053101508959059343335640009185013786003173143740486",
    )
    .unwrap();
    let (signature_scheme, public_key, signing_key) = test_signature_scheme_p256();

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
    let protocol = schnorr_rs::identificatio_protocol_p256();
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

    let public_key = bincode::deserialize::<PublicKey<SchnorrGroup>>(&[
        132, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 24, 180, 28, 68, 59, 14, 97, 98, 29, 83, 161, 62,
        6, 108, 187, 55, 62, 203, 67, 87, 141, 73, 109, 144, 17, 38, 236, 203, 41, 180, 143, 77,
        251, 158, 254, 103, 165, 249, 150, 29, 48, 183, 217, 202, 246, 233, 105, 99, 232, 186, 32,
        2, 120, 100, 78, 242, 238, 198, 141, 162, 27, 163, 236, 106, 168, 27, 57, 75, 244, 95, 194,
        43, 157, 247, 125, 85, 16, 160, 7, 35, 214, 141, 33, 170, 231, 170, 84, 127, 122, 63, 110,
        0, 15, 197, 135, 226, 65, 106, 252, 77, 80, 90, 161, 118, 78, 25, 168, 238, 100, 158, 91,
        123, 87, 227, 35, 97, 55, 239, 102, 192, 52, 17, 0, 164, 1, 212, 6, 107,
    ])
    .unwrap();
    let signing_key = bincode::deserialize::<SigningKey<SchnorrGroup>>(&[
        32, 0, 0, 0, 0, 0, 0, 0, 220, 167, 8, 158, 208, 13, 116, 68, 184, 232, 154, 120, 3, 29,
        178, 86, 37, 47, 152, 95, 96, 243, 171, 119, 204, 21, 31, 178, 7, 57, 252, 86, 91, 112, 64,
        149, 89, 117, 74, 175, 69, 75, 36, 131, 27, 102, 239, 168, 50, 80, 89, 117, 107, 50, 124,
        3, 33, 250, 104, 154, 85, 77, 74, 222, 105, 6, 207, 176, 58, 41, 216, 187, 65, 123, 72, 18,
        171, 255, 130, 20, 63, 131, 98, 35, 65, 128, 204, 115, 158, 156, 134, 165, 146, 17, 59,
        204, 211, 128, 16, 233, 72, 140, 248, 54, 2, 171, 12, 43, 39, 36, 48, 162, 161, 29, 118,
        161, 140, 234, 107, 243, 46, 120, 97, 126, 167, 10, 225, 110,
    ])
    .unwrap();

    (signature_scheme, public_key, signing_key)
}

fn test_signature_scheme_p256() -> (
    SignatureScheme<SchnorrP256Group, Sha256>,
    PublicKey<SchnorrP256Group>,
    SigningKey<SchnorrP256Group>,
) {
    let signature_scheme = schnorr_rs::signature_scheme_p256::<Sha256>();

    let public_key = bincode::deserialize::<PublicKey<SchnorrP256Group>>(&[
        69, 0, 0, 0, 0, 0, 0, 0, 65, 0, 0, 0, 4, 208, 37, 170, 124, 248, 211, 207, 92, 33, 54, 142,
        113, 110, 214, 54, 138, 234, 216, 159, 138, 236, 30, 99, 219, 118, 0, 241, 138, 234, 36,
        170, 55, 125, 55, 15, 102, 140, 103, 242, 115, 63, 80, 81, 171, 211, 85, 10, 36, 223, 193,
        77, 105, 41, 159, 245, 137, 70, 31, 45, 78, 66, 49, 149, 197,
    ])
    .unwrap();
    let signing_key = bincode::deserialize::<SigningKey<SchnorrP256Group>>(&[
        40, 189, 24, 229, 3, 47, 52, 152, 4, 125, 15, 44, 32, 43, 190, 34, 141, 24, 205, 87, 37,
        130, 169, 105, 209, 96, 147, 140, 165, 196, 65, 200,
    ])
    .unwrap();

    (signature_scheme, public_key, signing_key)
}
