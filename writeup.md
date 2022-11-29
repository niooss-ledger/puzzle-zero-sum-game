# Write-up for ZK Hack III puzzle #1: Zero-Sum Game

- Author: Nicolas IOOSS
- Date: 2022-11-25
- Puzzle: <https://zkhack.dev/zkhackIII/puzzleT1.html>, <https://github.com/ZK-Hack/puzzle-zero-sum-game>
- Write-up link: <https://gist.github.com/niooss-ledger/1a0f7241e90b0f60b1ddad66e6760af9>

## 1. Subject

```text
Bob has designed a new private payments protocol design, where every note comes with a secret
polynomial f whose sum over a specific set is zero. This is enforced using a sumcheck protocol.
Once a note is spent, f is modified to a different polynomial whose sum isn't zero. One day,
after an interesting conversation with her friends, Alice got an idea for an attack that can
potentially allow her to double spend notes.

Alice successfully double spent a note. Can you figure out how she did it?

Be very careful, if the verifier somehow learns the sum of the modified f,
they can deanonymize you.

In the rest of protocol that is not described here, the masking polynomial used by
the prover is opened twice. Therefore, the masking polynomial cannot be a
constant polynomial.

To see examples of sumcheck, you can review the protocol described in
https://github.com/arkworks-rs/marlin/blob/master/diagram/diagram.pdf.
```

The [GitHub repository](https://github.com/ZK-Hack/puzzle-zero-sum-game) is a Rust project.
It can be compiled and run using `cargo run` (with Rust 1.65.0).
Doing so displays the subject and an error:

```text
thread 'main' panicked at 'not yet implemented', src/prover.rs:30:5
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

This is because the execution reaches a `todo!();` macro in [`src/prover.rs`](https://github.com/ZK-Hack/puzzle-zero-sum-game/blob/12d90679a6bf1d5ac1212b19ffdea35a755ecad7/src/prover.rs#L24-L30): the participants are supposed to add some Rust code in a function named `prove` returning a `Proof` object.

What is this program about? What do we need to prove?

## 2. Understanding the Problem

The puzzle starts by executing [function `main()` in `src/main.rs`](https://github.com/ZK-Hack/puzzle-zero-sum-game/blob/12d90679a6bf1d5ac1212b19ffdea35a755ecad7/src/main.rs#L26).
This function initializes some variables before invoking `prove(...)` to craft a `Proof` object.
Then `verify(...)` is used to validate the generated proof.
Currently this does not work because `prove` is not implemented.
Nevertheless `verify` is implemented, in [`src/verify.rs`](https://github.com/ZK-Hack/puzzle-zero-sum-game/blob/12d90679a6bf1d5ac1212b19ffdea35a755ecad7/src/verifier.rs#L13).
It manipulates few variables to perform some computations, generate some random numbers, and check that two variables hold the same value.
What is going on?

First thing first, [`src/main.rs`](https://github.com/ZK-Hack/puzzle-zero-sum-game/blob/12d90679a6bf1d5ac1212b19ffdea35a755ecad7/src/main.rs#L7) uses the type `F` extensively.
It is defined as being the type `Fr` exported by the library `ark_bls12_381`:

```rust
use ark_bls12_381::{Bls12_381, Fr as F};
```

The [documentation of this library](https://docs.rs/ark-bls12-381/0.3.0/ark_bls12_381/index.html) states that it implements the BLS12-381 curve.
In this implementation, `ark_bls12_381::Fr` represents the type of elements of the scalar field.
A variable of this type is a number modulo $r$ = 52435875175126190479447740508185965837690552500527637822603658699938581184513.

Function `main()` starts by creating an object which represents a *general evaluation domain*:

```rust
let domain_size = 16;
let domain = GeneralEvaluationDomain::new(domain_size).unwrap();
```

The type of `domain` is [documented](https://docs.rs/ark-poly/0.3.0/ark_poly/domain/trait.EvaluationDomain.html) as being *a domain over which finite field (I)FFTs can be performed* (*FFT* means [Fast Fourier Transform](https://en.wikipedia.org/wiki/Fast_Fourier_transform) and *IFFT* is an inverse FFT).
In practice, `domain` is a set of 16 numbers $\\{1, \omega, \omega^2, \omega^3, ... \omega^{15}\\}$ which are the 16th roots of unity modulo $r$: $\omega$ is a number such that $\omega^{16} = 1 \mod r$.
In [`arkworks` library](https://github.com/arkworks-rs), the root of unity which is used is $7^{(r - 1) / 16}$.

This can be verified with some Rust code which computes $\omega$, displays its 16 powers and compares them with `domain.element(i)`:

```rust
use ark_bls12_381::{Fr as F, FrParameters};
use ark_ff::fields::{FftField, Field};
use ark_ff::{BigInteger, FpParameters};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

fn main() {
    let domain_size = 16;
    let domain = GeneralEvaluationDomain::<F>::new(domain_size).unwrap();

    println!("F modulus = {}", FrParameters::MODULUS);
    // This displays the modulus:
    // F modulus = 73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

    // Compute w
    let mut exp_for_root = FrParameters::MODULUS.clone();
    exp_for_root.divn(4); // Compute MODULUS >> 4, which is (MODULUS - 1)/16
    let w = F::from(7u64).pow(exp_for_root);
    println!("w = {}", w);
    // w = Fp256 "(20B1CE9140267AF9DD1C0AF834CEC32C17BEB312F20B6F7653EA61D87742BCCE)"

    // Check that w was computed correctly
    assert_eq!(F::multiplicative_generator(), F::from(7u64));
    assert_eq!(F::get_root_of_unity(16).unwrap(), w);

    for i in 0..16u64 {
        println!("w^{} = {}", i, w.pow([i]));
        assert_eq!(w.pow([i]), domain.element(i as usize));
    }
}
```

The 16 roots are displayed in hexadecimal:

```text
w^0 = Fp256 "(0000000000000000000000000000000000000000000000000000000000000001)"
w^1 = Fp256 "(20B1CE9140267AF9DD1C0AF834CEC32C17BEB312F20B6F7653EA61D87742BCCE)"
w^2 = Fp256 "(345766F603FA66E78C0625CD70D77CE2B38B21C28713B7007228FD3397743F7A)"
w^3 = Fp256 "(1EDC919EC91F38AC5CCD4631F16EDBA4967A6B6CFB0FACA4807B811A823F728D)"
w^4 = Fp256 "(00000000000000008D51CCCE760304D0EC030002760300000001000000000000)"
w^5 = Fp256 "(4F2C596E753E4FCC6E92A9C460AFCA4A1EF4E672EBC1E1BB95DF4B360411FE73)"
w^6 = Fp256 "(1333B22E5CE11044BABC5AFFCA86BF658E74903694B04FD86037FE81AE99502E)"
w^7 = Fp256 "(38C7F2DD7E0C63FCCABF643EDA8951F257BC96AF334C36BCA1ABB31FB37786B9)"
w^8 = Fp256 "(73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000000)"
w^9 = Fp256 "(533BD8C1E977024E561DCD0FD4D314D93BFEF0F00DF2EC88AC159E2688BD4333)"
w^10 = Fp256 "(3F96405D25A31660A733B23A98CA5B22A032824078EAA4FE8DD702CB688BC087)"
w^11 = Fp256 "(551115B4607E449BD66C91D61832FC60BD43389604EEAF5A7F847EE47DC08D74)"
w^12 = Fp256 "(73EDA753299D7D47A5E80B39939ED33467BAA40089FB5BFEFFFEFFFF00000001)"
w^13 = Fp256 "(24C14DE4B45F2D7BC4A72E43A8F20DBB34C8BD90143C7A436A20B4C8FBEE018E)"
w^14 = Fp256 "(60B9F524CCBC6D03787D7D083F1B189FC54913CC6B4E0C269FC8017D5166AFD3)"
w^15 = Fp256 "(3B25B475AB91194B687A73C92F188612FC010D53CCB225425E544CDF4C887948)"
```

Back to the puzzle, `main` creates a polynomial $f(X)$ and computes its sum over `domain`:

```rust
let f = DensePolynomial::from_coefficients_slice(&coeffs);
let mut real_sum = F::zero();
for h in domain.elements() {
    real_sum += f.evaluate(&h);
}
```

In the description, this sum is supposed to be zero.
But here, it is not.
This does not prevent `main` from constructing a `statement` which describes that this sum is zero:

```rust
let sum = F::zero();
// ...
let statement = Statement {
    domain,
    f: f_commitment[0].commitment().clone(),
    sum,
};
```

Function `prove` is then called to generate a proof of this statement, which is later verified by function `verify`.
This proof relies on a [Marlin-KZG10 polynomial commitment scheme](https://docs.rs/ark-poly-commit/0.3.0/ark_poly_commit/marlin/marlin_pc/struct.MarlinKZG10.html):

```rust
use ark_poly_commit::marlin_pc::MarlinKZG10;
pub type PC = MarlinKZG10<Bls12_381, DensePolynomial<F>>;

// ...

let f = LabeledPolynomial::new("f".into(), f.clone(), None, Some(1));
let (f_commitment, f_rand) = PC::commit(&ck, &[f.clone()], Some(&mut rng)).unwrap();
```

This commitment enables the Prover (who knows the polynomial $f(X)$ ) to prove some properties on $f(X)$ without revealing it.
This explains why it is part of the statement: the Prover wants to prove that the sum of $f(X)$ over the 16th roots of unity is zero, without revealing $f(X)$.

As the puzzle is requesting to craft a proof for a false statement, there must be something wrong with the verifier.

## 3. Understanding the Verifier

In [`src/verifier.rs`](https://github.com/ZK-Hack/puzzle-zero-sum-game/blob/12d90679a6bf1d5ac1212b19ffdea35a755ecad7/src/verifier.rs#L13), function `verify` starts with instantiating a Fiat-Shamir random-number generator implemented in [`src/rng.rs`](https://github.com/ZK-Hack/puzzle-zero-sum-game/blob/12d90679a6bf1d5ac1212b19ffdea35a755ecad7/src/rng.rs).

```rust
let mut fs_rng = FS::initialize(&to_bytes![&PROTOCOL_NAME, statement].unwrap());
fs_rng.absorb(&to_bytes![proof.s, proof.h, proof.g].unwrap());

let xi = F::rand(&mut fs_rng);
let opening_challenge = F::rand(&mut fs_rng);
```

Using the Fiat-Shamir transformation is a way to transform some interactive Zero-Knowledge protocols into non-interactive ones.
In the puzzle, function `verify` implements a non-interactive protocol matching an interactive one where the verifier receives the statement object and 3 polynomial commitments (`proof.s, proof.h, proof.g`) and sends back to the receiver 2 numbers (`xi` and `opening_challenge`).

The [`proof` structure](https://github.com/ZK-Hack/puzzle-zero-sum-game/blob/12d90679a6bf1d5ac1212b19ffdea35a755ecad7/src/data_structures.rs#L18-L27) contains 8 fields.

```rust
pub struct Proof<F: Field, PC: PolynomialCommitment<F, DensePolynomial<F>>> {
    pub f_opening: F,
    pub s: PC::Commitment,
    pub s_opening: F,
    pub g: PC::Commitment,
    pub g_opening: F,
    pub h: PC::Commitment,
    pub h_opening: F,
    pub pc_proof: PC::BatchProof,
}
```

There are 3 polynomial commitments and other values used in a call to function `PC::batch_check`.
The [documentation of this function](https://docs.rs/ark-poly-commit/0.3.0/ark_poly_commit/marlin/marlin_pc/struct.MarlinKZG10.html#method.batch_check) explains this function ensures the committed polynomials were really evaluated at `xi` to give `f_opening`, `s_opening`, `g_opening` and `h_opening`.

Moreover, `verify` defines a variable `g` to:

```rust
    let g = LabeledCommitment::new(
        "g".into(),
        proof.g.clone(),
        Some(statement.domain.size() - 2),
    );
```

This makes `PC::batch_check` also verify that the committed polynomial was of degree lower or equal to `statement.domain.size() - 2` (which is 16 - 2 = 14 in the puzzle).

Finally, `verify` computes two values and ensures they are the same:

```rust
let card_inverse = statement.domain.size_as_field_element().inverse().unwrap();
let lhs = proof.s_opening + proof.f_opening;
let rhs = {
    let x_gx = xi * proof.g_opening;
    let zh_eval = statement.domain.evaluate_vanishing_polynomial(xi);

    x_gx + proof.h_opening * zh_eval + statement.sum * card_inverse
};

if lhs != rhs {
    return Err(Error::IncorrectSum);
}
```

* `card_inverse` is the inverse of the size (also called *cardinal*) of the domain, in the field which is used (`F`).
* `lhs` is the Left-Hand Side of the equation and `rhs` the Right-Hand Side.
* All the opening variables are values of the commit polynomials at `xi`.
* `statement.domain.evaluate_vanishing_polynomial` evaluates the *vanishing polynomial* of `domain` over `xi`.
  With a domain with the 16th roots of unity, the vanishing polynomial is defined to be $V(X) = X^{16} - 1$.

With mathematics notations, let's call the polynomials $f(X)$, $s(X)$, $g(X)$ and $h(X)$ and the evaluation point $\xi$.
The previous code verifies:

$$s(\xi) + f(\xi) = \xi g(\xi) + h(\xi) V(\xi) + \frac{sum}{16}\mbox{ (modulo $r$)}$$

In summary, function `verify` implement the verifier side of the non-interactive protocol transformed from this interactive protocol:

```text
Prover                                      Verifier

Commit f
Send statement with the commitment of f
        ---------------------------------->
Generate polynomials s, g, h
Commit s, g, h
Send commitments
        ---------------------------------->
                                            Randomly draw xi, opening_challenge
                                            Send xi, opening_challenge
        <----------------------------------
Evaluate f, s, g, h on xi
Batch-proof the evaluations
  with Marlin-KZG10
  (this uses opening_challenge)
Send the proof with the evaluations
        ---------------------------------->
                                            Verify the batch-proof
                                            Verify a relation on the evaluations
```

As $\xi$ is known only after all polynomials are committed, the last verification enables the verifier to ensure (in a probabilistic way) that the Prover knew $f(X)$, $s(X)$, $g(X)$ and $h(X)$ such that:

$$s(X) + f(X) = X g(X) + h(X) \left(X^{16} - 1\right) + \frac{sum}{16}$$

How is this related to the objective of proving that the sum of $f(X)$ on the domain is zero?

## 4. The Univariate Sumcheck Protocol

In the Zero-Knowledge literature, a sumcheck protocol is a protocol which proves that the sum of several evaluation of a polynomial is a defined value.
The puzzle uses a specific kind of sumcheck protocols called *univariate sumcheck protocol*, where the polynomial uses a single variable.
It aims at proving that the sum of $f(X)$ on the domain $D$ is zero.
Mathematically, this is written:

$$\sum_{\alpha \in D} f(\alpha) = 0$$

This case is described in section 2.2 "A sumcheck protocol for univariate polynomials" of an article titled "Aurora: Transparent Succinct Arguments for R1CS" published in 2018: <https://eprint.iacr.org/2018/828>.
In this article, the degree $d$ of $f(X)$ is compared with the size of the evaluation domain, written $|D|$ here ( $|H|$ in the article).
When $d < |D|$, the problem is described as being simpler.
Why?

In the case of using roots of unity, there is an important property: the sum of a polynomial over all the roots removes many coefficients of the polynomial.
More precisely, when working with the 16th roots of unity $D = \\{1, \omega, \omega^2, \omega^3, ... \omega^{15}\\}$:

$$\sum_{\alpha \in D} \alpha = \sum_{i=0}^{15} \omega^i = \frac{\omega^{16} - 1}{\omega - 1} = \frac{1 - 1}{\omega - 1} = 0$$

$$\sum_{\alpha \in D} \alpha^2 = \sum_{i=0}^{15} \left(\omega^i\right)^2 = \sum_{i=0}^{15} \left(\omega^2\right)^i = \frac{\left(\omega^2\right)^{16} - 1}{\omega^2 - 1} = \frac{1 - 1}{\omega^2 - 1} = 0$$

Moreover:

$$\sum_{\alpha \in D} \alpha^0 = \sum_{i=0}^{15} 1 = 16$$

As the sequence $1, \omega, \omega^2, \omega^3, ...$ loops over all the 16th roots of unity before reaching again $\omega^{16} = 1$, this can be generalized as:

$$
\forall k, \sum_{\alpha \in D} \alpha^k = \left\\{\begin{array}{ll}
  16 & \mbox{ if $k$ is a multiple of 16} \\
  0 & \mbox { otherwise}
\end{array}\right.
$$

By writing $f_i$ the coefficient $i$ of $f(X)$ (which means that $f(X) = \sum_i f_i X^i$):

$$\sum_{\alpha \in D} f(\alpha) = \sum_{\alpha \in D}\sum_k f_k \alpha^k =\sum_k f_k \sum_{\alpha \in D} \alpha^k = 16 f_0 + 16 f_{16} + 16 f_{32} + ...$$

If the degree of $f(X)$ is lower than the size of the domain ( $d < |D| = 16$ ), this sum is $16 f_0$ and proving that it is zero is equivalent to proving that the first coefficient of $f(X)$ is zero.
Some Zero-Knowledge protocols do so by proving there exist a polynomial $g(X)$ such that $f(X) = X g(X)$.
This is equivalent because:

* If $f_0 = 0$, $g(X) = f_1 + f_2 X + f_3 X^2 ...$ verifies $f(X) = X g(X)$.
* If $f(X) = X g(X)$, $f_0 = f(0) = 0 g(0) = 0$.

In the general case where the degree of $f(X)$ can be higher than the size of the domain, there is a trick to go back to the previous case.
It involves the vanishing polynomial of the domain, which is polynomial which evaluates to zero over the domain:

$$V(X) = \prod_{\alpha \in D} (X - \alpha) = X^{16} - 1$$

By performing the Euclidean division of $f(X)$ by $V(X)$, we can compute a quotient polynomial $q(X)$ and a reminder $r(X)$ such that:

$$f(X) = q(X) V(X) + r(X) \mbox{ and } \deg(r) < \deg(V)$$

Then, for all root $\alpha \in D$, $V(\alpha) = 0$ so $f(\alpha) = r(\alpha)$.

Therefore $\sum_{\alpha \in D} f(\alpha) = \sum_{\alpha \in D} r(\alpha)$ and $\deg(r) < \deg(V) = 16$.

It follows that proving that the sum of $f(X)$ over the domain is zero is equivalent of proving that the sum of $r(X)$ over the domain is zero, which is also the same as proving that there exists a polynomial $g(X)$ such that $r(X) = X g(X)$.
Moreover the degree of $g(X)$ is $\deg(g) = \deg(X g) - 1 = \deg(r) - 1 < 16 - 1 = 15$.

By combining with the Euclidean division definition and by naming the quotient $h(X)$ instead of $q(X)$, it follows that for any polynomial $f(X)$:

$$\sum_{\alpha \in D} f(\alpha) = 0 \Leftrightarrow \exists g(X), h(X): f(X) = X g(X) + h(X) \left(X^{16} - 1\right) \mbox{ and } \deg(g) < 15$$

And this is almost what the Verifier of the puzzle verifies!
The Verifier also adds a term $\frac{sum}{16}$ to the expression, because more generally, if $\sum_{\alpha \in D} f(\alpha) = sum$, $sum = \sum_{\alpha \in D} r(\alpha) = 16 r_0$, so:

$$r(X) = X g(X) + r_0 = X g(X) + \frac{sum}{16}$$

$$f(X) = r(X) + h(X) \left(X^{16} - 1\right) = X g(X) + h(X) \left(X^{16} - 1\right) + \frac{sum}{16}$$

The puzzle Verifier also adds a polynomial $s(X)$ and computes $s(X) + f(X)$.
Doing so is similar to some hiding mechanisms in Zero-Knowledge protocols.
It can be used to avoid leaking information about $f(X)$ while ensuring the properties the protocol wants to prove.
But here, there is no restriction on $s(X)$ and its introduction changes the equation and the equivalence relations.
Does this break the protocol?
The next section will provide an answer.

## 5. Attacking the Protocol

This write-up started by presenting the puzzle.
We saw in the first sections that the puzzle implements a Verifier which ensures that the sum of a polynomial $f(X)$ over the 16th roots of unity (of the scalar field of the BLS12-381 curve) is zero.
To do so, it verifies that the Prover knew three polynomials $s(X)$, $g(X)$ and $h(X)$ such that, with a statement which includes a $sum$ which is set to zero:

$$s(X) + f(X) = X g(X) + h(X) \left(X^{16} - 1\right) + \frac{sum}{16}$$

$$\deg(g) <= 14$$

(This last equation is verified in the Marlin-KZG10 polynomial commitment scheme by specifying a maximal degree for $g$ in [`src/verifier.rs`](https://github.com/ZK-Hack/puzzle-zero-sum-game/blob/12d90679a6bf1d5ac1212b19ffdea35a755ecad7/src/verifier.rs#L30-L34))

The previous section explained the rational between the univarate sumcheck protocol and these equations.

Now, how do we attack this protocol?
More precisely, can we forge a false proof accepted by the Verifier?

By looking at the equations, the answer is straightforward: by setting $s(X)$ such that it cancels the sum term, the equation is always valid whatever the real sum of $f(X)$.

More precisely, here is an attack:

1. Compute $sum = \sum_{\alpha \in D} f(\alpha)$ (this is the value of `real_sum` in [`src/main.rs`](https://github.com/ZK-Hack/puzzle-zero-sum-game/blob/12d90679a6bf1d5ac1212b19ffdea35a755ecad7/src/main.rs#L75-L79))
2. Set $s(X) = -\frac{sum}{16}$ as a constant polynomial. Doing so, the sum of $s(X) + f(X)$ over the domain is zero.
3. Compute $h(X)$ and $r(X)$ as the quotient and remainder of the Euclidean division of $s(X) + f(X)$ by the vanishing polynomial. This is what [method `DensePolynomial::divide_by_vanishing_poly`](https://docs.rs/ark-poly/0.3.0/ark_poly/polynomial/univariate/struct.DensePolynomial.html#method.divide_by_vanishing_poly) is computing.
4. The first coefficient of $r(X)$ should be zero. Compute $g(X)$ from the other coefficients, such that $r(X) = X g(X)$. The degree of $g(X)$ should be at most 14.
5. Commit the polynomials, generate the Fiat-Shamir random numbers and invoke [`PolynomialCommitment::batch_open`](https://docs.rs/ark-poly-commit/0.3.0/ark_poly_commit/trait.PolynomialCommitment.html#method.batch_open) to create a Marlin-KZG10 polynomial commitment compatible with the Verifier.
6. Craft a `Proof` structure with everything which was computed.

This works but it is not an acceptable solution.
Indeed, the Prover contains a comment in [`src/prover.rs`](https://github.com/ZK-Hack/puzzle-zero-sum-game/blob/12d90679a6bf1d5ac1212b19ffdea35a755ecad7/src/prover.rs#L28):

```rust
/*
In the rest of protocol that is not described here, the masking polynomial is opened twice.
Therefore, the masking polynomial cannot be a constant polynomial.
*/
```

The masking polynomial refers to $s(X)$, and building a constant polynomial is exactly what we did in the attack.

There exist many ways to work around this limitation:

* We can generate random coefficients for $s(X)$.
  We want the sum of $s(X) + f(X)$ over the domain to be zero and if its degree is lesser than 32, this sum is $16(s_0 + s_{16} + f_0 + f_{16})$ (the previous section explained why).
  All the coefficients of $s(X)$ but $s_0$ can be randomly-generated.
  Then $s_0$ can be computed from $s_0 = -s_{16} - f_0 - f_{16}$.
* We can also take the problem the other way round and randomly generate $g(X)$ and $h(X)$.
  Then $s(X) = X g(X) + h(X) \left(X^{16} - 1\right) - f(X)$ is very unlikely to be a constant polynomial and the final steps of the attack (5. and 6.) can be achieved.

Here we will focus on the second alternative.
In [`src/main.rs`](https://github.com/ZK-Hack/puzzle-zero-sum-game/blob/12d90679a6bf1d5ac1212b19ffdea35a755ecad7/src/main.rs#L39-L71), $f(X)$ is defined as a polynomial of degree 30.
If $g(X)$ and $h(X)$ are chosen with 3 random coefficients each, they are of degree lesser or equal to 2.
This way, $s(X)$ is necessarily of degree 30 too when computing it.

In Rust, here is a Prover which implements the attack generating a proof that the sum of $f(X)$ over the domain is `statement.sum`, even when the real sum is different.

```rust
use ark_ff::to_bytes;
use ark_ff::FftField;
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, UVPolynomial};
use ark_poly_commit::{LabeledCommitment, LabeledPolynomial, PolynomialCommitment, QuerySet};
use ark_std::rand::RngCore;
use std::ops::Neg;

use crate::{
    data_structures::{Proof, Statement},
    error::Error,
    rng::FiatShamirRng,
    PROTOCOL_NAME,
};

pub fn prove<
    F: FftField + PrimeField,
    PC: PolynomialCommitment<F, DensePolynomial<F>>,
    FS: FiatShamirRng,
    R: RngCore,
>(
    ck: &PC::CommitterKey,
    statement: &Statement<F, PC>,
    f: &LabeledPolynomial<F, DensePolynomial<F>>,
    f_rand: &PC::Randomness,
    rng: &mut R,
) -> Result<Proof<F, PC>, Error<PC::Error>> {
    // Randomly generate g and h
    let g = DensePolynomial::from_coefficients_slice(&[F::rand(rng), F::rand(rng), F::rand(rng)]);
    let h = DensePolynomial::from_coefficients_slice(&[F::rand(rng), F::rand(rng), F::rand(rng)]);

    // Polynomial "X"
    let x_poly = DensePolynomial::from_coefficients_slice(&[F::zero(), F::from(1u64)]);

    // Inverse of cardinal of domain (here it is "1/16")
    let card_inverse = statement.domain.size_as_field_element().inverse().unwrap();

    // Craft s such that: s + f = Xg + hV + sum/domain.size
    let s: DensePolynomial<F> = x_poly.naive_mul(&g)
        + h.mul_by_vanishing_poly(statement.domain)
        + DensePolynomial::from_coefficients_slice(&[statement.sum * card_inverse])
        + f.polynomial().clone().neg();

    // Commit s, g, h
    let s = LabeledPolynomial::new("s".into(), s.clone(), None, Some(1));
    let g = LabeledPolynomial::new(
        "g".into(),
        g.clone(),
        Some(statement.domain.size() - 2),
        Some(1),
    );
    let h = LabeledPolynomial::new("h".into(), h.clone(), None, Some(1));

    let (commitments, randoms) =
        PC::commit(&ck, &[s.clone(), g.clone(), h.clone()], Some(rng)).unwrap();
    assert_eq!(commitments.len(), 3);
    assert_eq!(randoms.len(), 3);
    let s_comm = &commitments[0];
    let g_comm = &commitments[1];
    let h_comm = &commitments[2];
    let s_rand = &randoms[0];
    let g_rand = &randoms[1];
    let h_rand = &randoms[2];

    // Generate 2 numbers through Fiat-Shamir transformation
    let mut fs_rng = FS::initialize(&to_bytes![&PROTOCOL_NAME, statement].unwrap());
    fs_rng.absorb(&to_bytes![s_comm, h_comm, g_comm].unwrap());
    let xi = F::rand(&mut fs_rng);
    let opening_challenge = F::rand(&mut fs_rng);

    // Open the polynomials at xi
    let point_label = String::from("xi");
    let query_set = QuerySet::from([
        ("f".into(), (point_label.clone(), xi)),
        ("h".into(), (point_label.clone(), xi)),
        ("g".into(), (point_label.clone(), xi)),
        ("s".into(), (point_label, xi)),
    ]);

    // Craft a polynomial commitment
    let pc_proof = PC::batch_open(
        ck,
        [f, &s, &h, &g],
        &[
            LabeledCommitment::new("f".into(), statement.f.clone(), None),
            s_comm.clone(),
            h_comm.clone(),
            g_comm.clone(),
        ],
        &query_set,
        opening_challenge,
        [f_rand, s_rand, h_rand, g_rand],
        Some(rng),
    )
    .map_err(Error::from_pc_err)?;

    // Return the proof
    Ok(Proof {
        f_opening: f.evaluate(&xi),
        s: s_comm.commitment().clone(),
        s_opening: s.evaluate(&xi),
        g: g_comm.commitment().clone(),
        g_opening: g.evaluate(&xi),
        h: h_comm.commitment().clone(),
        h_opening: h.evaluate(&xi),
        pc_proof,
    })
}
```
