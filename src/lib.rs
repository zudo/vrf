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
use serde::Deserialize;
use serde::Serialize;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Copy, Clone)]
pub struct VRF {
    d: [u8; 32], // gamma
    h: [u8; 32], // c
    j: [u8; 32], // s
}
impl VRF {
    pub fn sign<Hash512: Digest<OutputSize = U64>, Hash256: Digest<OutputSize = U32>>(
        rng: &mut impl CryptoRngCore,
        secret: [u8; 32],
        alpha: &[u8],
    ) -> VRF {
        let a = Scalar::from_bytes_mod_order(secret);
        let b = (G * a).compress().to_bytes();
        let c = RistrettoPoint::from_uniform_bytes(
            &Hash512::new().chain_update(alpha).finalize().into(),
        );
        let d = (c * a).compress().to_bytes();
        let e = scalar::random(rng);
        let f = (G * e).compress().to_bytes();
        let g = (c * e).compress().to_bytes();
        let h = Hash256::new()
            .chain_update(alpha)
            .chain_update(b)
            .chain_update(d)
            .chain_update(f)
            .chain_update(g)
            .finalize()
            .into();
        let i = Scalar::from_bytes_mod_order(h);
        let j = (e - i * a).to_bytes();
        VRF { d, h, j }
    }
    pub fn verify<
        Hash512: Digest<OutputSize = U64>,
        Hash256: Digest<OutputSize = U32>,
        Hash: Digest,
    >(
        &self,
        public: &[u8; 32],
        alpha: &[u8],
        beta: &[u8],
    ) -> bool {
        let b = match point::from(public) {
            Some(x) => x,
            None => return false,
        };
        let d = match point::from(&self.d) {
            Some(x) => x,
            None => return false,
        };
        let c = RistrettoPoint::from_uniform_bytes(
            &Hash512::new().chain_update(alpha).finalize().into(),
        );
        let h = Scalar::from_bytes_mod_order(self.h);
        let j = Scalar::from_bytes_mod_order(self.j);
        let f = (b * h + G * j).compress().to_bytes();
        let g = (d * h + c * j).compress().to_bytes();
        beta == self.beta::<Hash>().as_slice()
            && self.h
                == Hash256::new()
                    .chain_update(alpha)
                    .chain_update(public)
                    .chain_update(self.d)
                    .chain_update(f)
                    .chain_update(g)
                    .finalize()
                    .as_slice()
    }
    pub fn beta<Hash: Digest>(&self) -> GenericArray<u8, <Hash>::OutputSize> {
        Hash::new().chain_update(self.d).finalize()
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
    fn test() {
        let rng = &mut OsRng;
        let secret = scalar::random(rng);
        let public = (G * secret).compress().to_bytes();
        let public_fake = (G * scalar::random(rng)).compress().to_bytes();
        let secret = secret.to_bytes();
        let alpha = [0, 1, 2, 3];
        let alpha_fake = [3, 2, 1, 0];
        let vrf_0 = VRF::sign::<Sha512, Sha256>(rng, secret, &alpha);
        let vrf_1 = VRF::sign::<Sha512, Sha256>(rng, secret, &alpha);
        assert_eq!(vrf_0.d, vrf_1.d);
        assert_ne!(vrf_0.h, vrf_1.h);
        assert_ne!(vrf_0.j, vrf_1.j);
        let beta_0 = vrf_0.beta::<Sha224>();
        let beta_1 = vrf_1.beta::<Sha224>();
        assert_eq!(beta_0, beta_1);
        assert!(vrf_0.verify::<Sha512, Sha256, Sha224>(&public, &alpha, &beta_0));
        assert!(vrf_1.verify::<Sha512, Sha256, Sha224>(&public, &alpha, &beta_1));
        let vrf = VRF::sign::<Sha512, Sha256>(rng, secret, &alpha);
        let beta = vrf.beta::<Sha224>();
        assert!(!vrf.verify::<Sha512, Sha256, Sha224>(&public_fake, &alpha, &beta));
        assert!(!vrf.verify::<Sha512, Sha256, Sha224>(&public, &alpha_fake, &beta));
    }
}
