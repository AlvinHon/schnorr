//! Implementation of Schnorr Signature Schemes.
//!
//! This module provides two implementations of Schnorr Signature Schemes:
//! - Schnorr Signature Scheme based on discrete logarithm problem
//! - A variant of Schnorr Signature Scheme based on elliptic curve cryptography
//!
//! For the first scheme, use the type `SignatureScheme<H>` where `H` is a hash function,
//! while for the second scheme, use the type `SignatureSchemeECP256<H>` where `H` is a hash function.

pub mod dl;

pub mod ec;

pub type SignatureScheme<H> = dl::SignatureScheme<H>;
pub type SignatureSchemeECP256<H> = ec::SignatureScheme<H>;
