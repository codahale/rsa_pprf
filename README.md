# rsa-pprf

A puncturable pseudo-random function (PRF) based on the RSA accumulator.

## ⚠️ WARNING: You should not use this. ⚠️

Neither the design nor the implementation of this library have been independently evaluated or
audited. I am not your cryptographic engineer; I'm not even a cryptographic engineer.

## Puncturable PRFs

A pseudo-random function (PRF) is a function `F` which takes a secret key `K` and returns a value
`Y` which is indistinguishable from random to any adversary who does not know `K`.

A puncturable PRF (PPRF) extends the concept of the PRF to include a range of input values `X0…XN`
such that `F(K, X)` and `F(K, X′)` return distinct values. In addition, a puncture function `G` is
included which accepts a `K` and `X` and returns a `K′` such that `F(K, X) ≠ F(K′, X)` only for that
value of `X` (i.e. all other values of `X` are unchanged).

## Design

`rsa-pprf` implements a puncturable PRF based on the RSA accumulator as described in [AGJ19][].

Initialization requires a cryptographic hash algorithm `H` (e.g. SHA-256), an RSA key length `N`
(e.g.  2048), and the number of possible punctures `R`.  First, RSA modulus `n` is constructed from
two random safe primes `p` and `q` and the primes are discarded.  Next, a random element `g` is
selected from `(0,n)`. Finally, a bitset `r` is initialized with the length of possible punctures.

Evaluating the PRF requires an index `x`, in the range `[0,R)`. First, the product `P_x` of the
first `x-1` odd (i.e. `>2`) primes (except for those which have been registered as punctured in `r`)
is calculated. Finally, the value `H(g^P_x mod n)` is returned.

Puncturing the PRF requires an index `x`, in the range `[0,R)`. First, the `x`-th odd prime `p_x` is
calculated. Next, `g` is updated to `g=g^p_x mod n`. Finally, the `x`-th bit in the PRF's bitset is
set to `1`.

[AGJ19]: https://eprint.iacr.org/2019/228.pdf

In essence, the design uses an RSA accumulator to accumulate punctured primes while using
unpunctured primes to produce output. This construction is secure given the Strong RSA Assumption is
true: calculating `g′=g^x mod n` is easy given `g` and `x` but hard given `g′`.

## Usage

```rust
use rand::thread_rng;
use rsa_pprf::PuncturablePrf;
use sha2::Sha256;

// Generate a new PPRF.
let mut pprf = PuncturablePrf::<Sha256>::generate(&mut thread_rng(), 1024, 32).unwrap();
assert_eq!(pprf.input_count(), 32);
assert_eq!(pprf.punctured_input_count(), 0);
assert_eq!(pprf.unpunctured_input_count(), 32);

// Evaluate some inputs.
let k0 = pprf.eval(0);
let k1 = pprf.eval(1);
let k2 = pprf.eval(2);
let k3 = pprf.eval(3);
assert!(k0.is_some() && k1.is_some() && k2.is_some() && k3.is_some());

// Puncture some inputs.
pprf.punc(1);
pprf.punc(2);

// Ensure punctured inputs don't evaluate.
assert_eq!(pprf.eval(1), None);
assert_eq!(pprf.eval(2), None);

// Ensure unpunctured inputs successfully re-evaluate.
assert_eq!(pprf.eval(0), k0);
assert_eq!(pprf.eval(3), k3);

// See the counts change.
assert_eq!(pprf.input_count(), 32);
assert_eq!(pprf.punctured_input_count(), 2);
assert_eq!(pprf.unpunctured_input_count(), 30);
```

## License

Copyright © 2023 Coda Hale

Distributed under the Apache License 2.0 or MIT License.
