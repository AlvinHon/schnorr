use num_bigint::BigUint;

use schnorr_rs::{SignatureScheme, SignatureSchemeECP256};
use sha2::Sha256;

/// Test Schnorr Identification Protocol
#[test]
fn test_schnorr_identification_protocol() {
    use schnorr_rs::identification::Identification;
    let rng = &mut rand::thread_rng();

    // setup parameters and identity
    let identification = Identification::from_str(
            "170635838606142236835668582024526088839118584923917947104881361096573663241835425726334688227245750988284470206339098086628427330905070264154820140913414479495481939755079707182465802484020944276739164978360438985178968038653749024959908959885446602817557541340750337331201115159158715982367397805202392369959",
            "85317919303071118417834291012263044419559292461958973552440680548286831620917712863167344113622875494142235103169549043314213665452535132077410070456707239747740969877539853591232901242010472138369582489180219492589484019326874512479954479942723301408778770670375168665600557579579357991183698902601196184979",
            "144213202463066458950689095305115948799436864106778035179311009761777898846700415257265179855055640783875383274707858827879036088093691306491953244054442062637113833957623609837630797581860524549453053884680615629934658560796659252072641537163117203253862736053101508959059343335640009185013786003173143740486",
        )
        .unwrap();

    let signature_scheme = SignatureScheme::<Sha256>::from_str(
        "170635838606142236835668582024526088839118584923917947104881361096573663241835425726334688227245750988284470206339098086628427330905070264154820140913414479495481939755079707182465802484020944276739164978360438985178968038653749024959908959885446602817557541340750337331201115159158715982367397805202392369959",
        "85317919303071118417834291012263044419559292461958973552440680548286831620917712863167344113622875494142235103169549043314213665452535132077410070456707239747740969877539853591232901242010472138369582489180219492589484019326874512479954479942723301408778770670375168665600557579579357991183698902601196184979",
        "144213202463066458950689095305115948799436864106778035179311009761777898846700415257265179855055640783875383274707858827879036088093691306491953244054442062637113833957623609837630797581860524549453053884680615629934658560796659252072641537163117203253862736053101508959059343335640009185013786003173143740486",
    )
    .unwrap();
    let (signing_key, public_key) = signature_scheme.generate_key(rng);
    let signer = schnorr_rs::dl::Signer {
        scheme: &signature_scheme,
        key: &signing_key,
        pub_key: &public_key,
    };
    let verifier = schnorr_rs::dl::Verifier {
        scheme: &signature_scheme,
        key: &public_key,
    };

    let i = BigUint::from(123u32);

    // user interacts with issuer to get a certificate
    let (iss_secret, iss_params) = identification.issue_params(rng, i.clone());
    let cert = identification.issue_certificate(rng, &signer, iss_params);

    // user presents the certificate to the verifier
    let (ver_secret, ver_req) = identification.verification_request(rng, cert);
    // verifier challenges the user's knowledge of the secret
    let challenge = identification
        .verification_challenge(rng, &verifier, ver_req.clone())
        .unwrap();
    // user responds to the challenge
    let ver_res = identification.verification_response(challenge.clone(), iss_secret, ver_secret);
    // verifier verifies the response
    assert!(identification.verification(ver_req, challenge, ver_res));
}

/// Test Schnorr Identification Protocol based on elliptic curve cryptography
#[test]
fn test_schnorr_identification_protocol_ec() {
    use schnorr_rs::identification::IdentificationECP256 as Identification;
    use std::ops::Mul;
    let rng = &mut rand::thread_rng();

    // setup parameters and identity
    let schnorr = Identification::new();
    let signature_scheme = SignatureSchemeECP256::<Sha256>::new();
    let (signing_key, public_key) = signature_scheme.generate_key(rng);
    let signer = schnorr_rs::ec::Signer {
        scheme: &signature_scheme,
        key: &signing_key,
        pub_key: &public_key,
    };
    let verifier = schnorr_rs::ec::Verifier {
        scheme: &signature_scheme,
        key: &public_key,
    };

    let i = p256::AffinePoint::GENERATOR
        .mul(p256::NonZeroScalar::random(rng).as_ref())
        .to_affine();

    // user interacts with issuer to get a certificate
    let (iss_secret, iss_params) = schnorr.issue_params(rng, i.clone());
    let cert = schnorr.issue_certificate(rng, &signer, iss_params);

    // user presents the certificate to the verifier
    let (ver_secret, ver_req) = schnorr.verification_request(rng, cert);
    // verifier challenges the user's knowledge of the secret
    let challenge = schnorr
        .verification_challenge(rng, &verifier, ver_req.clone())
        .unwrap();
    // user responds to the challenge
    let ver_res = schnorr
        .verification_response(challenge.clone(), iss_secret, ver_secret)
        .unwrap();
    // verifier verifies the response
    assert!(schnorr.verification(ver_req, challenge, ver_res));
}

#[test]
fn test_signature_scheme() {
    let scheme = SignatureScheme::<Sha256>::from_str(
        "170635838606142236835668582024526088839118584923917947104881361096573663241835425726334688227245750988284470206339098086628427330905070264154820140913414479495481939755079707182465802484020944276739164978360438985178968038653749024959908959885446602817557541340750337331201115159158715982367397805202392369959",
        "85317919303071118417834291012263044419559292461958973552440680548286831620917712863167344113622875494142235103169549043314213665452535132077410070456707239747740969877539853591232901242010472138369582489180219492589484019326874512479954479942723301408778770670375168665600557579579357991183698902601196184979",
        "144213202463066458950689095305115948799436864106778035179311009761777898846700415257265179855055640783875383274707858827879036088093691306491953244054442062637113833957623609837630797581860524549453053884680615629934658560796659252072641537163117203253862736053101508959059343335640009185013786003173143740486",
    )
    .unwrap();
    let rng = &mut rand::thread_rng();

    let (key, public_key) = scheme.generate_key(rng);
    let message = "hello world".as_bytes();
    let signature = scheme.sign(rng, &key, &public_key, message);
    assert!(scheme.verify(&public_key, message, &signature));
}

#[test]
fn test_signature_scheme_ec() {
    let scheme = SignatureSchemeECP256::<Sha256>::new();

    let rng = &mut rand::thread_rng();
    let (key, public_key) = scheme.generate_key(rng);
    let message = "hello world".as_bytes();
    let signature = scheme.sign(rng, &key, &public_key, message);
    assert!(scheme.verify(&public_key, message, &signature));
}
