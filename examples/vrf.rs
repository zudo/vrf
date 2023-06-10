use rand_core::OsRng;
use sha2::Sha224;
use sha2::Sha256;
use sha2::Sha512;
use vrf::Secret;
use vrf::VRF;
fn main() {
    let rng = &mut OsRng;
    let secret = Secret::new(rng);
    let public = secret.public();
    let alpha = [0; 32];
    let vrf = VRF::sign::<Sha512, Sha256>(rng, &secret, &alpha);
    let beta = vrf.beta::<Sha224>();
    println!("public {}", hex::encode(public.to_bytes()));
    println!("beta {}", hex::encode(beta));
    println!("pi {}", hex::encode(vrf.to_bytes()));
    println!(
        "verify {}",
        vrf.verify::<Sha512, Sha256, Sha224>(&public, &alpha, &beta)
    );
}
