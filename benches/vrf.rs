#![feature(test)]
extern crate test;
use rand_core::OsRng;
use sha2::Sha224;
use sha2::Sha256;
use sha2::Sha512;
use test::Bencher;
use vrf::scalar;
use vrf::G;
use vrf::VRF;
#[bench]
fn sign(b: &mut Bencher) {
    let csprng = &mut OsRng;
    let secret = scalar::random(csprng).to_bytes();
    let alpha = [0, 1, 2, 3];
    b.iter(|| VRF::sign::<Sha512, Sha256>(csprng, secret, &alpha));
}
#[bench]
fn verify(b: &mut Bencher) {
    let csprng = &mut OsRng;
    let secret = scalar::random(csprng);
    let public = (G * secret).compress().to_bytes();
    let secret = secret.to_bytes();
    let alpha = [0, 1, 2, 3];
    let vrf = VRF::sign::<Sha512, Sha256>(csprng, secret, &alpha);
    let beta = vrf.beta::<Sha224>();
    b.iter(|| vrf.verify::<Sha512, Sha256, Sha224>(&public, &alpha, &beta));
}
#[bench]
fn beta(b: &mut Bencher) {
    let csprng = &mut OsRng;
    let secret = scalar::random(csprng).to_bytes();
    let alpha = [0, 1, 2, 3];
    let vrf = VRF::sign::<Sha512, Sha256>(csprng, secret, &alpha);
    b.iter(|| vrf.beta::<Sha224>());
}
