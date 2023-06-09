use rand_core::OsRng;
use sha2::Sha224;
use sha2::Sha256;
use sha2::Sha512;
use vrf::scalar;
use vrf::VRF;
fn main() {
    let rng = &mut OsRng;
    let secret = scalar::random(rng).to_bytes();
    let alpha = [0; 32];
    let vrf_0 = VRF::sign::<Sha512, Sha256>(rng, secret, &alpha);
    let vrf_1 = VRF::sign::<Sha512, Sha256>(rng, secret, &alpha);
    let beta_0 = vrf_0.beta::<Sha224>();
    let beta_1 = vrf_1.beta::<Sha224>();
    println!("beta_0 {}", hex::encode(beta_0));
    println!("beta_1 {}", hex::encode(beta_1));
    assert_eq!(beta_0, beta_1); // beta is deterministic
    println!("pi_0 {}", hex::encode(bincode::serialize(&vrf_0).unwrap()));
    println!("pi_1 {}", hex::encode(bincode::serialize(&vrf_1).unwrap()));
    assert_ne!(vrf_0, vrf_1); // pi is not deterministic because of blinding
}
