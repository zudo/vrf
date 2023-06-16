use rand_core::OsRng;
use sha2::Sha224;
use sha2::Sha256;
use sha2::Sha512;
use vrf::scalar_random;
use vrf::RISTRETTO_BASEPOINT_POINT;
use vrf::VRF;
fn main() {
    let rng = &mut OsRng;
    let secret = scalar_random(rng);
    let public = secret * RISTRETTO_BASEPOINT_POINT;
    let alpha = [0; 32];
    let vrf = VRF::sign::<Sha512, Sha256>(rng, &secret, &alpha);
    let beta = vrf.beta::<Sha224>();
    println!("public {}", hex::encode(public.compress().to_bytes()));
    println!("beta {}", hex::encode(beta));
    println!("pi {}", hex::encode(vrf.to_bytes()));
    println!(
        "verify {}",
        vrf.verify::<Sha512, Sha256, Sha224>(&public, &alpha, &beta)
    );
}
