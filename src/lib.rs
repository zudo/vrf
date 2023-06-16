use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::RistrettoPoint;
use digest::generic_array::typenum::U32;
use digest::generic_array::typenum::U64;
use digest::generic_array::GenericArray;
use digest::Digest;
use rand_core::CryptoRngCore;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
pub fn point_from_slice(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes).unwrap().decompress()
}
pub fn scalar_random(rng: &mut impl CryptoRngCore) -> Scalar {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}
pub fn scalar_from_canonical(bytes: [u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(bytes).into()
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VRF {
    gamma: RistrettoPoint,
    c: Scalar,
    s: Scalar,
}
impl VRF {
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        bytes[..32].copy_from_slice(self.gamma.compress().as_bytes());
        bytes[32..64].copy_from_slice(self.c.as_bytes());
        bytes[64..].copy_from_slice(self.s.as_bytes());
        bytes
    }
    pub fn from_slice(bytes: &[u8; 96]) -> Option<VRF> {
        let gamma = point_from_slice(&bytes[..32].try_into().unwrap())?;
        let c = scalar_from_canonical(bytes[32..64].try_into().unwrap())?;
        let s = scalar_from_canonical(bytes[64..].try_into().unwrap())?;
        Some(VRF { gamma, c, s })
    }
    pub fn sign<Hash512: Digest<OutputSize = U64>, Hash256: Digest<OutputSize = U32>>(
        rng: &mut impl CryptoRngCore,
        secret: &Scalar,
        alpha: impl AsRef<[u8]>,
    ) -> VRF {
        let alpha = alpha.as_ref();
        let a = RistrettoPoint::from_uniform_bytes(
            &Hash512::new().chain_update(alpha).finalize().into(),
        );
        let gamma = secret * a;
        let r = scalar_random(rng);
        let c = Scalar::from_bytes_mod_order(
            Hash256::new()
                .chain_update(alpha)
                .chain_update((secret * G).compress().to_bytes())
                .chain_update(gamma.compress().to_bytes())
                .chain_update((r * G).compress().to_bytes())
                .chain_update((r * a).compress().to_bytes())
                .finalize()
                .into(),
        );
        let s = r - c * secret;
        VRF { gamma, c, s }
    }
    pub fn verify<
        Hash512: Digest<OutputSize = U64>,
        Hash256: Digest<OutputSize = U32>,
        Hash: Digest,
    >(
        &self,
        public: &RistrettoPoint,
        alpha: impl AsRef<[u8]>,
        beta: impl AsRef<[u8]>,
    ) -> bool {
        let alpha = alpha.as_ref();
        let beta = beta.as_ref();
        let a = RistrettoPoint::from_uniform_bytes(
            &Hash512::new().chain_update(alpha).finalize().into(),
        );
        let c = Scalar::from_bytes_mod_order(
            Hash256::new()
                .chain_update(alpha)
                .chain_update(public.compress().to_bytes())
                .chain_update(self.gamma.compress().to_bytes())
                .chain_update((self.c * public + self.s * G).compress().to_bytes())
                .chain_update((self.c * self.gamma + self.s * a).compress().to_bytes())
                .finalize()
                .into(),
        );
        c.as_bytes() == self.c.as_bytes() && beta == self.beta::<Hash>().as_slice()
    }
    pub fn beta<Hash: Digest>(&self) -> GenericArray<u8, <Hash>::OutputSize> {
        Hash::new()
            .chain_update(self.gamma.compress().to_bytes())
            .finalize()
    }
}
pub struct As(Scalar);
#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use rand_core::OsRng;
    use sha2::Sha224;
    use sha2::Sha256;
    use sha2::Sha512;
    pub const ALPHA_0: &[u8] = b"hello from";
    pub const ALPHA_1: &str = "zudo";
    lazy_static! {
        static ref SECRET_0: Scalar = scalar_random(&mut OsRng);
        static ref SECRET_1: Scalar = scalar_random(&mut OsRng);
        static ref PUBLIC_0: RistrettoPoint = *SECRET_0 * G;
        static ref PUBLIC_1: RistrettoPoint = *SECRET_1 * G;
    }
    #[test]
    fn sign_verify() {
        let rng = &mut OsRng;
        let vrf_0 = VRF::sign::<Sha512, Sha256>(rng, &SECRET_0, &ALPHA_0);
        let vrf_1 = VRF::sign::<Sha512, Sha256>(rng, &SECRET_0, &ALPHA_0);
        assert_eq!(vrf_0.gamma, vrf_1.gamma);
        assert_ne!(vrf_0.c, vrf_1.c);
        assert_ne!(vrf_0.s, vrf_1.s);
        let beta_0 = vrf_0.beta::<Sha224>();
        let beta_1 = vrf_1.beta::<Sha224>();
        assert_eq!(beta_0, beta_1);
        assert!(vrf_0.verify::<Sha512, Sha256, Sha224>(&PUBLIC_0, &ALPHA_0, &beta_0));
        assert!(vrf_1.verify::<Sha512, Sha256, Sha224>(&PUBLIC_0, &ALPHA_0, &beta_1));
    }
    #[test]
    fn sign_verify_fake() {
        let rng = &mut OsRng;
        let vrf = VRF::sign::<Sha512, Sha256>(rng, &SECRET_0, &ALPHA_0);
        let beta = vrf.beta::<Sha224>();
        assert!(!vrf.verify::<Sha512, Sha256, Sha224>(&PUBLIC_1, &ALPHA_0, &beta));
        assert!(!vrf.verify::<Sha512, Sha256, Sha224>(&PUBLIC_0, &ALPHA_1, &beta));
    }
    #[test]
    fn to_bytes_from_slice() {
        let rng = &mut OsRng;
        let vrf = VRF::sign::<Sha512, Sha256>(rng, &SECRET_0, ALPHA_0);
        let secret_bytes = SECRET_0.to_bytes();
        let public_bytes = PUBLIC_0.compress().to_bytes();
        let vrf_bytes = vrf.to_bytes();
        assert_eq!(*SECRET_0, scalar_from_canonical(secret_bytes).unwrap());
        assert_eq!(*PUBLIC_0, point_from_slice(&public_bytes).unwrap());
        assert_eq!(vrf, VRF::from_slice(&vrf_bytes).unwrap());
    }
}
