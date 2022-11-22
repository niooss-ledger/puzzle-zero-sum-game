use ark_ff::to_bytes;
use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::EvaluationDomain;
use ark_poly::Polynomial;
use ark_poly::UVPolynomial;
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
    F: FftField,
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
    /*
        ADD YOUR CODE HERE
    */
    /*
    In the rest of protocol that is not described here, the masking polynomial is opened twice. Therefore, the masking polynomial cannot be a constant polynomial.
    */
    // Inverse of cardinal of domain
    let card_inverse = statement.domain.size_as_field_element().inverse().unwrap();
    let h = DensePolynomial::from_coefficients_slice(&[F::rand(rng), F::rand(rng), F::rand(rng)]);
    let g = DensePolynomial::from_coefficients_slice(&[F::rand(rng), F::rand(rng), F::rand(rng)]);

    // Polynomial "X"
    let x_poly = DensePolynomial::from_coefficients_slice(&[F::zero(), F::from(1u64)]);

    // Craft s such that: s + f = Xg + h*Vanishing + sum/domain.size
    let s: DensePolynomial<F> = x_poly.naive_mul(&g)
        + h.mul_by_vanishing_poly(statement.domain)
        + DensePolynomial::from_coefficients_slice(&[statement.sum * card_inverse])
        + f.polynomial().clone().neg();
    println!("f.degree = {}", f.polynomial().degree());
    println!("g.degree = {}", g.degree());
    println!("h.degree = {}", h.degree());
    println!("s.degree = {}", s.degree());

    let s = LabeledPolynomial::new("s".into(), s.clone(), None, Some(1));
    let (s_commitment, s_rand) = PC::commit(&ck, &[s.clone()], Some(rng)).unwrap();

    let g = LabeledPolynomial::new(
        "g".into(),
        g.clone(),
        Some(statement.domain.size() - 2),
        Some(1),
    );
    let (g_commitment, g_rand) = PC::commit(&ck, &[g.clone()], Some(rng)).unwrap();

    let h = LabeledPolynomial::new("h".into(), h.clone(), None, Some(1));
    let (h_commitment, h_rand) = PC::commit(&ck, &[h.clone()], Some(rng)).unwrap();

    let mut fs_rng = FS::initialize(&to_bytes![&PROTOCOL_NAME, statement].unwrap());
    fs_rng.absorb(&to_bytes![s_commitment, h_commitment, g_commitment].unwrap());
    let xi = F::rand(&mut fs_rng);
    let opening_challenge = F::rand(&mut fs_rng);

    let point_label = String::from("xi");
    let query_set = QuerySet::from([
        ("f".into(), (point_label.clone(), xi)),
        ("h".into(), (point_label.clone(), xi)),
        ("g".into(), (point_label.clone(), xi)),
        ("s".into(), (point_label, xi)),
    ]);

    let f_comm = LabeledCommitment::new("f".into(), statement.f.clone(), None);
    let s_comm = s_commitment[0].clone();
    let h_comm = h_commitment[0].clone();
    let g_comm = g_commitment[0].clone();
    println!("f_comm.degree_bound = {:?}", f_comm.degree_bound());
    println!("s_comm.degree_bound = {:?}", s_comm.degree_bound());
    println!("h_comm.degree_bound = {:?}", h_comm.degree_bound());
    println!("g_comm.degree_bound = {:?}", g_comm.degree_bound());

    let pc_proof = PC::batch_open(
        ck,
        [f, &s, &h, &g],
        &[
            f_comm.clone(),
            s_comm.clone(),
            h_comm.clone(),
            g_comm.clone(),
        ],
        &query_set,
        opening_challenge,
        [f_rand, &s_rand[0], &h_rand[0], &g_rand[0]],
        Some(rng),
    )
    .map_err(Error::from_pc_err)?;

    Ok(Proof {
        f_opening: f.evaluate(&xi),
        s: s_commitment[0].commitment().clone(),
        s_opening: s.evaluate(&xi),
        g: g_commitment[0].commitment().clone(),
        g_opening: g.evaluate(&xi),
        h: h_commitment[0].commitment().clone(),
        h_opening: h.evaluate(&xi),
        pc_proof,
    })
}
