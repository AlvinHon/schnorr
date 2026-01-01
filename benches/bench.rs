use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use dashu_int::UBig;
use schnorr_rs::{
    identification::Identification, Group, PublicKey, SchnorrGroup, SchnorrP256Group,
    SignatureScheme, Signer, SigningKey, Verifier,
};
use sha2::Sha256;

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
    UBig,
) {
    let protocol = schnorr_rs::identification_protocol(
        "170635838606142236835668582024526088839118584923917947104881361096573663241835425726334688227245750988284470206339098086628427330905070264154820140913414479495481939755079707182465802484020944276739164978360438985178968038653749024959908959885446602817557541340750337331201115159158715982367397805202392369959",
        "85317919303071118417834291012263044419559292461958973552440680548286831620917712863167344113622875494142235103169549043314213665452535132077410070456707239747740969877539853591232901242010472138369582489180219492589484019326874512479954479942723301408778770670375168665600557579579357991183698902601196184979",
        "144213202463066458950689095305115948799436864106778035179311009761777898846700415257265179855055640783875383274707858827879036088093691306491953244054442062637113833957623609837630797581860524549453053884680615629934658560796659252072641537163117203253862736053101508959059343335640009185013786003173143740486",
    )
    .unwrap();
    let (signature_scheme, public_key, signing_key) = test_signature_scheme();

    let i = UBig::from(123u32);

    (protocol, signature_scheme, public_key, signing_key, i)
}

fn setup_for_identification_ec_tests() -> (
    Identification<SchnorrP256Group>,
    SignatureScheme<SchnorrP256Group, Sha256>,
    PublicKey<SchnorrP256Group>,
    SigningKey<SchnorrP256Group>,
    schnorr_rs::group::p256::Point,
) {
    let protocol = schnorr_rs::identification_protocol_p256();
    let (signature_scheme, public_key, signing_key) = test_signature_scheme_p256();

    let i = SchnorrP256Group.mul_by_generator(&UBig::from(123u32));

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
            128, 123, 67, 16, 235, 80, 40, 118, 118, 112, 238, 216, 120, 1, 82, 238, 22, 116, 155,
            195, 225, 229, 77, 193, 61, 102, 212, 68, 166, 26, 217, 77, 221, 31, 55, 92, 0, 82,
            131, 151, 138, 222, 112, 118, 167, 233, 151, 31, 15, 66, 149, 146, 177, 186, 72, 148,
            153, 56, 27, 43, 7, 34, 181, 149, 136, 206, 126, 101, 84, 2, 215, 53, 67, 101, 111,
            176, 230, 141, 108, 229, 217, 170, 42, 127, 218, 217, 231, 63, 95, 153, 153, 18, 34,
            107, 41, 187, 50, 37, 55, 193, 108, 30, 72, 42, 246, 113, 15, 42, 67, 73, 5, 246, 177,
            122, 29, 71, 232, 151, 205, 211, 83, 177, 61, 212, 167, 214, 189, 242, 240,
        ],
        bincode::config::standard(),
    )
    .unwrap();

    let (signing_key, _): (SigningKey<SchnorrGroup>, _) = bincode::serde::decode_from_slice(
        &[
            132, 128, 0, 0, 0, 213, 162, 127, 147, 78, 146, 205, 225, 138, 137, 127, 243, 45, 36,
            96, 155, 156, 168, 249, 186, 145, 158, 250, 127, 185, 156, 83, 161, 96, 86, 149, 128,
            117, 218, 69, 169, 177, 207, 54, 211, 61, 11, 136, 173, 84, 162, 252, 13, 98, 89, 12,
            223, 111, 41, 173, 51, 4, 156, 174, 124, 198, 110, 140, 145, 12, 139, 127, 41, 66, 190,
            231, 120, 247, 246, 31, 139, 13, 235, 113, 83, 124, 249, 216, 50, 113, 138, 234, 138,
            23, 166, 144, 206, 141, 0, 112, 221, 192, 134, 61, 76, 178, 190, 49, 223, 195, 253, 78,
            12, 174, 213, 206, 131, 158, 46, 183, 89, 166, 181, 27, 46, 26, 153, 13, 118, 143, 161,
            102, 3,
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
            64, 155, 120, 94, 43, 128, 32, 254, 105, 64, 68, 157, 28, 85, 83, 0, 28, 7, 123, 204,
            175, 166, 233, 81, 234, 220, 115, 105, 107, 194, 75, 97, 109, 113, 124, 166, 120, 242,
            100, 142, 0, 90, 249, 1, 226, 14, 95, 196, 138, 133, 81, 212, 68, 141, 255, 239, 224,
            29, 0, 147, 107, 107, 212, 81, 69,
        ],
        bincode::config::standard(),
    )
    .unwrap();
    let (signing_key, _): (SigningKey<SchnorrP256Group>, _) = bincode::serde::decode_from_slice(
        &[
            36, 32, 0, 0, 0, 7, 98, 135, 31, 215, 62, 160, 11, 193, 182, 54, 227, 230, 18, 94, 202,
            10, 104, 240, 56, 9, 88, 141, 68, 80, 223, 109, 239, 127, 161, 83, 171,
        ],
        bincode::config::standard(),
    )
    .unwrap();

    (signature_scheme, public_key, signing_key)
}
