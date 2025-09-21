//! This module contains the definition of the struct `SchnorrP256Group` that implements trait `Group`.

use dashu::{
    base::ExtendedGcd,
    integer::{IBig, UBig},
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use super::Group;

/// Schnorr group over P-256 curve, implements the [Group](super::Group) trait by using group elements of types [Point] and [UBig](dashu::integer::UBig).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchnorrP256Group;

impl SchnorrP256Group {
    /// Returns the generator point of the P-256 curve.
    ///
    /// Ref: https://csrc.nist.gov/pubs/sp/800/186/final
    pub fn generator() -> Point {
        Point {
            x: GX.clone(),
            y: GY.clone(),
        }
    }

    /// Checks if a point is on the P-256 curve.
    pub fn is_on_curve(point: &Point) -> bool {
        if point.is_infinity() {
            return true; // The point at infinity is on the curve
        }
        let lhs = (point.y.clone() * point.y.clone()) % &P;
        let rhs =
            (point.x.clone() * point.x.clone() * point.x.clone() + &A * point.x.clone() + &B) % &P;
        lhs == rhs
    }
}

impl Group for SchnorrP256Group {
    type P = Point;
    type F = UBig;
    type DeserializeError = ();

    fn generator(&self) -> Self::P {
        Self::generator()
    }

    fn dot(&self, p1: &Self::P, p2: &Self::P) -> Self::P {
        add_points(p1, p2)
    }

    fn mul_by_generator(&self, scalar: &Self::F) -> Self::P {
        scalar_multiply(scalar, &self.generator())
    }

    fn mul(&self, p: &Self::P, scalar: &Self::F) -> Self::P {
        scalar_multiply(scalar, p)
    }

    fn add_mul_scalar(&self, s1: &Self::F, s2: &Self::F, s3: &Self::F) -> Self::F {
        (s1 + s2 * s3) % &N
    }

    fn neg(&self, scalar: &Self::F) -> Self::F {
        if scalar.is_zero() {
            UBig::ZERO
        } else {
            (&N - scalar) % &N
        }
    }

    fn is_equivalent_scalars(s1: &Self::F, s2: &Self::F) -> bool {
        s1 == s2
    }
    fn is_equivalent_points(p1: &Self::P, p2: &Self::P) -> bool {
        p1 == p2
    }

    fn map_point(point: &Self::P) -> Vec<u8> {
        point.x.to_le_bytes().to_vec()
    }

    fn map_to_scalar(bytes: &[u8]) -> Self::F {
        UBig::from_le_bytes(bytes)
    }

    fn serialize_scalar(scalar: &Self::F) -> Vec<u8> {
        scalar.to_le_bytes().to_vec()
    }

    fn serialize_point(point: &Self::P) -> Vec<u8> {
        point.to_slice().to_vec()
    }

    fn deserialize_scalar(bytes: &[u8]) -> Result<Self::F, ()> {
        Ok(UBig::from_le_bytes(bytes))
    }

    fn deserialize_point(bytes: &[u8]) -> Result<Self::P, ()> {
        if bytes.len() != 64 {
            return Err(());
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        let point = Point::from_slice(&arr);
        if Self::is_on_curve(&point) {
            Ok(point)
        } else {
            Err(())
        }
    }

    fn random_scalar<R: RngCore>(&self, rng: &mut R) -> Self::F {
        let mut bytes = [0u8; 32]; // because order N is 256 bits
        rng.fill_bytes(&mut bytes);
        UBig::from_le_bytes(&bytes) % &N
    }
    fn random_element<R: RngCore>(&self, rng: &mut R) -> Self::P {
        let scalar = self.random_scalar(rng);
        scalar_multiply(&scalar, &self.generator())
    }
}

// The parameters for the P-256 curve
// Ref: https://csrc.nist.gov/pubs/sp/800/186/final

static P: UBig = unsafe {
    UBig::from_static_words(&[18446744073709551615, 4294967295, 0, 18446744069414584321])
};
static A: UBig = unsafe {
    UBig::from_static_words(&[18446744073709551612, 4294967295, 0, 18446744069414584321])
};
static B: UBig = unsafe {
    UBig::from_static_words(&[
        4309448131093880907,
        7285987128567378166,
        12964664127075681980,
        6540974713487397863,
    ])
};
static GX: UBig = unsafe {
    UBig::from_static_words(&[
        17627433388654248598,
        8575836109218198432,
        17923454489921339634,
        7716867327612699207,
    ])
};
static GY: UBig = unsafe {
    UBig::from_static_words(&[
        14678990851816772085,
        3156516839386865358,
        10297457778147434006,
        5756518291402817435,
    ])
};
static N: UBig = unsafe {
    UBig::from_static_words(&[
        17562291160714782033,
        13611842547513532036,
        18446744073709551615,
        18446744069414584320,
    ])
};
// static H: UBig = UBig::ONE;

/// Represents a point on the P-256 elliptic curve.
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    x: UBig,
    y: UBig,
}

impl Point {
    pub fn from_slice(bytes: &[u8; 64]) -> Self {
        let x = UBig::from_le_bytes(&bytes[..32]);
        let y = UBig::from_le_bytes(&bytes[32..]);
        Point { x, y }
    }

    pub fn to_slice(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        let x_bytes = self.x.to_le_bytes();
        let y_bytes = self.y.to_le_bytes();
        bytes[..x_bytes.len()].copy_from_slice(&x_bytes);
        bytes[32..32 + y_bytes.len()].copy_from_slice(&y_bytes);
        bytes
    }
    fn is_infinity(&self) -> bool {
        self.x == UBig::ZERO && self.y == UBig::ZERO
    }

    fn infinity() -> Self {
        Point {
            x: UBig::ZERO,
            y: UBig::ZERO,
        }
    }
}

impl Serialize for Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.to_slice())
    }
}

impl<'de> Deserialize<'de> for Point {
    fn deserialize<D>(deserializer: D) -> Result<Point, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PointVisitor;
        impl serde::de::Visitor<'_> for PointVisitor {
            type Value = Point;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array of length 64")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Point, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 64 {
                    return Err(E::custom("Invalid length for Point"));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(Point::from_slice(&arr))
            }
        }
        deserializer.deserialize_bytes(PointVisitor)
    }
}

// Arithmetic operations on the elliptic curve points

fn mod_inverse(a: &UBig, m: &UBig) -> UBig {
    if a == &UBig::ZERO {
        return UBig::ZERO; // Inverse does not exist
    }
    let (g, mut r, _) = a.gcd_ext(m);

    assert!(g == UBig::ONE, "Inverse does not exist");

    if r < IBig::ZERO {
        r += m.clone();
    }

    r.into_parts().1
}

fn add_points(p1: &Point, p2: &Point) -> Point {
    if p1.is_infinity() {
        return p2.clone();
    }
    if p2.is_infinity() {
        return p1.clone();
    }

    if p1.x == p2.x && p1.y == (&P - &p2.y) % &P {
        // This means the points are vertical, resulting in the point at infinity
        return Point::infinity();
    }

    let lambda = if p1.x == p2.x && p1.y == p2.y {
        // Point doubling
        let numerator = (UBig::from(3u32) * &p1.x * &p1.x + &A) % &P;
        let denominator = (UBig::from(2u32) * &p1.y) % &P;
        (numerator * mod_inverse(&denominator, &P)) % &P
    } else {
        // Point addition
        let numerator = if p2.y < p1.y {
            (&p2.y + &P - &p1.y) % &P
        } else {
            (&p2.y - &p1.y) % &P
        };
        let denominator = if p2.x < p1.x {
            (&p2.x + &P - &p1.x) % &P
        } else {
            (&p2.x - &p1.x) % &P
        };
        (numerator * mod_inverse(&denominator, &P)) % &P
    };

    let x3 = {
        let lambda2 = (&lambda * &lambda) % &P;
        let x_d = (&p1.x + &p2.x) % &P;

        if lambda2 < x_d {
            (&lambda2 + &P - &x_d) % &P
        } else {
            (&lambda2 - &x_d) % &P
        }
    };
    let y3 = {
        let part1 = if p1.x < x3 {
            (&lambda * (&p1.x + &P - &x3)) % &P
        } else {
            (&lambda * (&p1.x - &x3)) % &P
        };
        if part1 < p1.y {
            (&part1 + &P - &p1.y) % &P
        } else {
            (&part1 - &p1.y) % &P
        }
    };

    Point { x: x3, y: y3 }
}

fn scalar_multiply(scalar: &UBig, point: &Point) -> Point {
    let mut result = Point::infinity();
    let mut temp_point = point.clone();
    let mut k = scalar % &N;

    while k > UBig::ZERO {
        if &k % UBig::from(2u32) == UBig::ONE {
            result = add_points(&result, &temp_point);
        }
        temp_point = add_points(&temp_point, &temp_point);
        k >>= 1; // Divide k by 2
    }

    result
}

#[cfg(test)]
mod test {
    use super::*;

    use dashu::integer::UBig;
    use p256::{elliptic_curve::group::Group, Scalar};
    use rand::RngCore;
    use std::ops::Mul;

    fn random_test_point<R: RngCore>(rng: &mut R) -> Point {
        <SchnorrP256Group as crate::Group>::random_element(&SchnorrP256Group, rng)
    }

    fn random_test_scalar<R: RngCore>(rng: &mut R) -> UBig {
        <SchnorrP256Group as crate::Group>::random_scalar(&SchnorrP256Group, rng)
    }

    #[test]
    fn test_serde() {
        let rng = &mut rand::thread_rng();
        let point = random_test_point(rng);
        let serialized = point.to_slice();
        let deserialized = Point::from_slice(&serialized);
        assert_eq!(point, deserialized);
    }

    #[test]
    fn test_arithmetic() {
        // check if the P256 arithmetic is correct
        let g = SchnorrP256Group::generator();
        assert!(SchnorrP256Group::is_on_curve(&g)); // check if the base point is on the curve
        let result = scalar_multiply(&N, &g);
        assert_eq!(result.x, UBig::ZERO);
        assert_eq!(result.y, UBig::ZERO);
    }

    #[test]
    fn test_point_addition() {
        let rng = &mut rand::thread_rng();
        let g = SchnorrP256Group::generator();

        let mut start_point = g.clone();
        for _ in 0..100 {
            let s1 = random_test_scalar(rng);
            let s2 = random_test_scalar(rng);

            let p1 = scalar_multiply(&s1, &start_point);
            assert!(SchnorrP256Group::is_on_curve(&p1)); // check if the point is on the curve
            let p2 = scalar_multiply(&s2, &start_point);
            assert!(SchnorrP256Group::is_on_curve(&p2)); // check if the point is on the curve
            let result = add_points(&p1, &p2);
            assert!(SchnorrP256Group::is_on_curve(&result)); // check if the result is on the curve

            start_point = result;
        }
    }

    #[test]
    fn test_consistency_with_p256_crate() {
        let p256_crate_g = p256::ProjectivePoint::generator();
        let g = SchnorrP256Group::generator();
        assert!(is_point_equal(&g, &p256_crate_g));

        let rng = &mut rand::thread_rng();

        let mut start_point = g.clone();
        let mut start_point_p256 = p256_crate_g.clone();
        for _ in 0..100 {
            // scalar multiplication
            let s1 = rng.next_u64();
            let p1 = scalar_multiply(&UBig::from(s1), &start_point);
            let p1_p256 = start_point_p256.mul(Scalar::from(s1));
            assert!(is_point_equal(&p1, &p1_p256));

            // point addition
            let s2 = rng.next_u64();
            let p2 = scalar_multiply(&UBig::from(s2), &start_point);
            let p2_p256 = start_point_p256.mul(Scalar::from(s2));
            let result = add_points(&p1, &p2);
            let result_p256 = p1_p256 + p2_p256;
            assert!(is_point_equal(&result, &result_p256));

            start_point = result;
            start_point_p256 = result_p256;
        }
    }

    fn is_point_equal(p1: &Point, p2: &p256::ProjectivePoint) -> bool {
        montgomery_form(p1) == p256_point_to_xy(p2)
    }

    // Montgomery form; i.e., FieldElement(a) = aR mod p, with R = 2^256.
    fn montgomery_form(p: &Point) -> (UBig, UBig) {
        let r = UBig::from(1u32) << 256; // R = 2^256
        let x_montgomery = (p.x.clone() * r.clone()) % &P;
        let y_montgomery = (p.y.clone() * r.clone()) % &P;
        (x_montgomery, y_montgomery)
    }

    fn p256_point_to_xy(p: &p256::ProjectivePoint) -> (UBig, UBig) {
        let a = p.to_affine();
        let a_str = format!("{:?}", a);
        let re = regex::Regex::new(
        r"AffinePoint \{ x: FieldElement\((0x[0-9a-fA-F]+)\), y: FieldElement\((0x[0-9a-fA-F]+)\)",
    )
    .unwrap();
        let caps = re.captures(&a_str).unwrap();
        let x_str = &caps[1];
        let y_str = &caps[2];
        let x = UBig::from_str_radix(&x_str[2..], 16).unwrap();
        let y = UBig::from_str_radix(&y_str[2..], 16).unwrap();
        (x, y)
    }
}
