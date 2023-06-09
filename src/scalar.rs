use curve25519_dalek::Scalar;
use rand_core::CryptoRngCore;
pub fn random<CSPRNG: CryptoRngCore>(csprng: &mut CSPRNG) -> Scalar {
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}
