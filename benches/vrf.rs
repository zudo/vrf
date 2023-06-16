#![feature(test)]
extern crate test;
use rand_core::OsRng;
use sha2::Sha224;
use sha2::Sha256;
use sha2::Sha512;
use test::Bencher;
use vrf::scalar_random;
use vrf::RISTRETTO_BASEPOINT_POINT;
use vrf::VRF;
#[bench]
fn sign(b: &mut Bencher) {
    let rng = &mut OsRng;
    let secret = scalar_random(rng);
    let alpha = [0, 1, 2, 3];
    b.iter(|| VRF::sign::<Sha512, Sha256>(rng, &secret, &alpha));
}
#[bench]
fn verify(b: &mut Bencher) {
    let rng = &mut OsRng;
    let secret = scalar_random(rng);
    let public = secret * RISTRETTO_BASEPOINT_POINT;
    let alpha = [0, 1, 2, 3];
    let vrf = VRF::sign::<Sha512, Sha256>(rng, &secret, &alpha);
    let beta = vrf.beta::<Sha224>();
    b.iter(|| vrf.verify::<Sha512, Sha256, Sha224>(&public, &alpha, &beta));
}
#[bench]
fn beta(b: &mut Bencher) {
    let rng = &mut OsRng;
    let secret = scalar_random(rng);
    let alpha = [0, 1, 2, 3];
    let vrf = VRF::sign::<Sha512, Sha256>(rng, &secret, &alpha);
    b.iter(|| vrf.beta::<Sha224>());
}
