use rand_core::OsRng;
use sha2::Sha224;
use sha2::Sha256;
use sha2::Sha512;
use vrf::scalar;
use vrf::G;
use vrf::VRF;
fn main() {
    let rng = &mut OsRng;
    let secret = scalar::random(rng);
    let public = (G * secret).compress().to_bytes();
    let secret = secret.to_bytes();
    let alpha = [0; 32];
    let vrf = VRF::sign::<Sha512, Sha256>(rng, secret, &alpha);
    let beta = vrf.beta::<Sha224>();
    println!("public {}", hex::encode(public));
    println!("beta {}", hex::encode(beta));
    println!("pi {}", hex::encode(bincode::serialize(&vrf).unwrap()));
    println!(
        "verify {}",
        vrf.verify::<Sha512, Sha256, Sha224>(&public, &alpha, &beta)
    );
}
