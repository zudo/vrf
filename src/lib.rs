pub mod point;
pub mod scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::RistrettoPoint;
use digest::generic_array::typenum::U32;
use digest::generic_array::typenum::U64;
use digest::generic_array::GenericArray;
use digest::Digest;
use rand_core::CryptoRngCore;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Public(RistrettoPoint);
impl Public {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
    pub fn from_slice(bytes: &[u8; 32]) -> Option<Public> {
        Some(Public(point::from_slice(bytes)?))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Secret(Scalar);
impl Secret {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
    pub fn from_canonical(bytes: [u8; 32]) -> Option<Secret> {
        Some(Secret(scalar::from_canonical(bytes)?))
    }
    pub fn public(&self) -> Public {
        Public(self.0 * G)
    }
    pub fn new(rng: &mut impl CryptoRngCore) -> Secret {
        Secret(scalar::random(rng))
    }
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
        let gamma = point::from_slice(&bytes[..32].try_into().unwrap())?;
        let c = scalar::from_canonical(bytes[32..64].try_into().unwrap())?;
        let s = scalar::from_canonical(bytes[64..].try_into().unwrap())?;
        Some(VRF { gamma, c, s })
    }
    pub fn sign<Hash512: Digest<OutputSize = U64>, Hash256: Digest<OutputSize = U32>>(
        rng: &mut impl CryptoRngCore,
        secret: &Secret,
        alpha: impl AsRef<[u8]>,
    ) -> VRF {
        let alpha = alpha.as_ref();
        let a = RistrettoPoint::from_uniform_bytes(
            &Hash512::new().chain_update(alpha).finalize().into(),
        );
        let gamma = secret.0 * a;
        let k = scalar::random(rng);
        let u = k * G;
        let v = k * a;
        let h = Hash256::new()
            .chain_update(alpha)
            .chain_update(secret.public().0.compress().to_bytes())
            .chain_update(gamma.compress().to_bytes())
            .chain_update(u.compress().to_bytes())
            .chain_update(v.compress().to_bytes())
            .finalize()
            .into();
        let c = Scalar::from_bytes_mod_order(h);
        let s = k - c * secret.0;
        VRF { gamma, c, s }
    }
    pub fn verify<
        Hash512: Digest<OutputSize = U64>,
        Hash256: Digest<OutputSize = U32>,
        Hash: Digest,
    >(
        &self,
        public: &Public,
        alpha: impl AsRef<[u8]>,
        beta: impl AsRef<[u8]>,
    ) -> bool {
        let alpha = alpha.as_ref();
        let beta = beta.as_ref();
        let a = RistrettoPoint::from_uniform_bytes(
            &Hash512::new().chain_update(alpha).finalize().into(),
        );
        let u = self.c * public.0 + self.s * G;
        let v = self.c * self.gamma + self.s * a;
        let h = Hash256::new()
            .chain_update(alpha)
            .chain_update(public.0.compress().to_bytes())
            .chain_update(self.gamma.compress().to_bytes())
            .chain_update(u.compress().to_bytes())
            .chain_update(v.compress().to_bytes())
            .finalize()
            .into();
        let c = Scalar::from_bytes_mod_order(h);
        c.as_bytes() == self.c.as_bytes() && beta == self.beta::<Hash>().as_slice()
    }
    pub fn beta<Hash: Digest>(&self) -> GenericArray<u8, <Hash>::OutputSize> {
        Hash::new()
            .chain_update(self.gamma.compress().to_bytes())
            .finalize()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use sha2::Sha224;
    use sha2::Sha256;
    use sha2::Sha512;
    #[test]
    fn sign_verify() {
        let rng = &mut OsRng;
        let secret = Secret::new(rng);
        let public = secret.public();
        let alpha = [0, 1, 2, 3];
        let vrf_0 = VRF::sign::<Sha512, Sha256>(rng, &secret, &alpha);
        let vrf_1 = VRF::sign::<Sha512, Sha256>(rng, &secret, &alpha);
        assert_eq!(vrf_0.gamma, vrf_1.gamma);
        assert_ne!(vrf_0.c, vrf_1.c);
        assert_ne!(vrf_0.s, vrf_1.s);
        let beta_0 = vrf_0.beta::<Sha224>();
        let beta_1 = vrf_1.beta::<Sha224>();
        assert_eq!(beta_0, beta_1);
        assert!(vrf_0.verify::<Sha512, Sha256, Sha224>(&public, &alpha, &beta_0));
        assert!(vrf_1.verify::<Sha512, Sha256, Sha224>(&public, &alpha, &beta_1));
    }
    #[test]
    fn sign_verify_fake() {
        let rng = &mut OsRng;
        let secret = Secret::new(rng);
        let public = secret.public();
        let alpha = [0, 1, 2, 3];
        let vrf = VRF::sign::<Sha512, Sha256>(rng, &secret, &alpha);
        let beta = vrf.beta::<Sha224>();
        let secret_fake = Secret::new(rng);
        let public_fake = secret_fake.public();
        let alpha_fake = [3, 2, 1, 0];
        assert!(!vrf.verify::<Sha512, Sha256, Sha224>(&public_fake, &alpha, &beta));
        assert!(!vrf.verify::<Sha512, Sha256, Sha224>(&public, &alpha_fake, &beta));
    }
    #[test]
    fn to_bytes_from_slice() {
        let rng = &mut OsRng;
        let secret = Secret::new(rng);
        let public = secret.public();
        let vrf = VRF::sign::<Sha512, Sha256>(rng, &secret, &[]);
        let secret_bytes = secret.to_bytes();
        let public_bytes = public.to_bytes();
        let vrf_bytes = vrf.to_bytes();
        assert_eq!(secret, Secret::from_canonical(secret_bytes).unwrap());
        assert_eq!(public, Public::from_slice(&public_bytes).unwrap());
        assert_eq!(vrf, VRF::from_slice(&vrf_bytes).unwrap());
    }
}
