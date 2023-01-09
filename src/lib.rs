#![no_std]
#![doc = include_str!("../README.md")]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    unused_lifetimes,
    unused_qualifications,
    missing_debug_implementations,
    clippy::cognitive_complexity,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::semicolon_if_nothing_returned
)]

use core::fmt::Debug;
use core::marker::PhantomData;

use digest::{Digest, Output};
use fixedbitset::FixedBitSet;
use num_bigint_dig::RandBigInt;
use num_traits::One;
use primal::Primes;
use rand_core::{CryptoRng, RngCore};
use rsa::{BigUint, PublicKeyParts, RsaPrivateKey};
use serde::{Deserialize, Serialize};

pub use rsa::errors::Error;

/// A puncturable PRF using an RSA accumulator.
#[derive(Serialize, Deserialize)]
pub struct PuncturablePrf<D: Digest> {
    n: BigUint,
    g: BigUint,
    pub(crate) r: FixedBitSet,
    _digest: PhantomData<D>,
}

impl<D: Digest> PuncturablePrf<D> {
    /// Generates a new [`PuncturablePrf`] instance using a modulus and bitset of the given sizes.
    ///
    /// # Errors
    ///
    /// Returns an error if modulus generation fails.
    pub fn generate(
        mut rng: impl RngCore + CryptoRng,
        modulus_size_bits: usize,
        punctures: usize,
    ) -> Result<PuncturablePrf<D>, Error> {
        let n = RsaPrivateKey::new(&mut rng, modulus_size_bits)?.to_public_key().n().clone();
        let g = rng.gen_biguint_below(&n);
        Ok(PuncturablePrf {
            n,
            g,
            r: FixedBitSet::with_capacity(punctures),
            _digest: Default::default(),
        })
    }

    /// Returns the PRF output for the given input `x`. Returns `None` if the PRF has been punctured
    /// for `x`.
    pub fn eval(&self, x: usize) -> Option<Output<D>> {
        // Punctured at x, cannot evaluate output.
        if self.r[x] {
            return None;
        }

        // Calculate the product of all odd (i.e. >2) primes, excluding the ones which have already
        // been punctured and the current xth prime.
        let p_x = Primes::all().skip(1).take(self.r.len()).enumerate().fold(
            BigUint::one(),
            |acc, (i, p_i)| {
                if self.r[i] || i == x {
                    acc
                } else {
                    acc * p_i
                }
            },
        );

        // Calculate y = g^{p_x} mod N.
        let y = self.g.modpow(&p_x, &self.n);

        // Return H(y).
        Some(D::new().chain_update(y.to_bytes_le()).finalize())
    }

    /// Punctures the PRF for the given output `x`.
    pub fn punc(&mut self, x: usize) {
        // Cannot re-puncture at x.
        if self.r[x] {
            return;
        }

        // Find the xth odd prime.
        let p_x = Primes::all().skip(1).take(self.r.len()).nth(x).unwrap();

        // Set g=g^{p_x} mod N.
        self.g = self.g.modpow(&p_x.into(), &self.n);

        // Record the puncture in the bitset.
        self.r.set(x, true);
    }

    /// Returns the number of possible inputs.
    pub fn input_count(&self) -> usize {
        self.r.len()
    }

    /// Returns the number of inputs which have not been punctured.
    pub fn unpunctured_input_count(&self) -> usize {
        self.input_count() - self.punctured_input_count()
    }

    /// Returns the number of inputs which have been punctured.
    pub fn punctured_input_count(&self) -> usize {
        self.r.count_ones(..)
    }
}

impl<D: Digest> Debug for PuncturablePrf<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PuncturablePrf")
            .field("n", &self.n)
            .field("g", &format_args!("[redacted]"))
            .field("r", &format_args!("[redacted]"))
            .field("_digest", &self._digest)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::*;

    #[test]
    fn modified_bitset() {
        // Create a PPRF.
        let mut pprf = PuncturablePrf::<Sha256>::generate(rand::thread_rng(), 512, 32).unwrap();

        // Evaluate it at an input.
        let k1 = pprf.eval(1);

        // Puncture the input.
        pprf.punc(1);

        // Reset the bitset, simulating either a serialization error or a malicious actor.
        pprf.r.clear();

        // Re-evaluate the input.
        let k1_p = pprf.eval(1);

        assert_ne!(k1, k1_p, "punctured evaluation must not equal unpunctured evaluation");
    }
}
