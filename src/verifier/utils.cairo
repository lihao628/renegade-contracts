use traits::{Into, TryInto};
use option::OptionTrait;
use array::{ArrayTrait, SpanTrait};
use ec::{ec_point_unwrap, ec_point_non_zero, ec_point_zero};

use alexandria_linalg::dot::dot;
use renegade_contracts::{
    transcript::{Transcript, TranscriptTrait, TranscriptProtocol, TRANSCRIPT_SEED},
    utils::math::elt_wise_mul
};

use super::{
    types::{SparseWeightMatrix, SparseWeightMatrixTrait, Proof}, scalar::{Scalar, ScalarTrait},
};


/// This computes the `i`th element of the `s` vector using the `u` challenge scalars.
/// The explanation for this calculation can be found [here](https://doc-internal.dalek.rs/bulletproofs/inner_product_proof/index.html#verifiers-algorithm)
fn get_s_elem(u: Span<Scalar>, i: usize) -> Scalar {
    let mut res = 1.into();
    let mut j = 0;
    let mut two_to_j: u128 = 1;
    let k = u.len();
    loop {
        if j == k {
            break;
        }

        if i.into() & two_to_j == 0 {
            // If jth bit of i is 0, then we multiply by u[k - 1 - j]^-1
            res *= u.at(k - 1 - j).inverse();
        } else {
            // If jth bit of i is 1, then we multiply by u[k - 1 - j]
            res *= *u.at(k - 1 - j);
        };

        j += 1;
        two_to_j *= 2;
    };

    res
}

// "Squeezes" the challenge scalars from the proof
// TODO: Should we be validating that EC points are not the identity?
// TODO: Absorb labels/domain separators
// TODO: Absorb identity points for A_I2, A_O2, S2
// TODO: Squeeze u challenge scalar for 2-phase circuit (confusing variable naming)
fn squeeze_challenge_scalars(
    proof: @Proof, witness_commitments: Span<EcPoint>, m: usize, n_plus: usize
) -> (Array<Scalar>, Array<Scalar>) {
    let mut challenge_scalars = ArrayTrait::new();
    let mut u = ArrayTrait::new();

    let mut transcript = TranscriptTrait::new(TRANSCRIPT_SEED);

    transcript.r1cs_domain_sep();

    // TODO: Assert consistent iteration order of witness b/w prover
    let mut i = 0;
    loop {
        if i == m {
            break;
        };

        transcript.validate_and_append_point('V', *witness_commitments.at(i));

        i += 1;
    };

    transcript.append_u64('m', m.into());

    transcript.validate_and_append_point('A_I1', *proof.A_I1);
    transcript.validate_and_append_point('A_O1', *proof.A_O1);
    transcript.validate_and_append_point('S1', *proof.S1);

    // Since we're only doing 1-phase circuits, we use the 1-phase
    // domain separator, and A_I2, A_O2, & S2 are all the identity point
    transcript.r1cs_1phase_domain_sep();
    let ident = ec_point_zero();
    transcript.append_point('A_I2', ident);
    transcript.append_point('A_O2', ident);
    transcript.append_point('S2', ident);

    challenge_scalars.append(transcript.challenge_scalar('y'));
    challenge_scalars.append(transcript.challenge_scalar('z'));

    transcript.validate_and_append_point('T_1', *proof.T_1);
    transcript.validate_and_append_point('T_3', *proof.T_3);
    transcript.validate_and_append_point('T_4', *proof.T_4);
    transcript.validate_and_append_point('T_5', *proof.T_5);
    transcript.validate_and_append_point('T_6', *proof.T_6);

    challenge_scalars.append(transcript.challenge_scalar('u'));
    challenge_scalars.append(transcript.challenge_scalar('x'));

    transcript.append_scalar('t_x', *proof.t_hat);
    transcript.append_scalar('t_x_blinding', *proof.t_blind);
    transcript.append_scalar('e_blinding', *proof.e_blind);

    challenge_scalars.append(transcript.challenge_scalar('w'));

    // IPP scalars

    transcript.innerproduct_domain_sep(n_plus.into());

    let mut i = 0;
    let k = proof.L.len();
    loop {
        if i == k {
            break;
        };

        transcript.validate_and_append_point('L', *proof.L.at(i));
        transcript.validate_and_append_point('R', *proof.R.at(i));
        u.append(transcript.challenge_scalar('u'));

        i += 1;
    };

    // Squeeze r
    challenge_scalars.append(transcript.challenge_scalar('r'));

    (challenge_scalars, u)
}

/// Calculates the value delta = <y^{n+}[0:n] * w_R_flat, w_L_flat> used in verification
// TODO: Because this requires flattening the matrices, it may need to be split across multiple EC points
// TODO: Can make this more efficient by pre-computing all powers of z & selectively using in dot products
// (will need all powers of z across both of W_L, W_R)
// TODO: Technically, only need powers of y for which the corresponding column of W_R & W_L is non-zero
fn calc_delta(
    n: usize,
    y_inv_powers_to_n: Span<Scalar>,
    z: Scalar,
    W_L: @SparseWeightMatrix,
    W_R: @SparseWeightMatrix
) -> Scalar {
    // Flatten W_L, W_R using z
    let w_L_flat = W_L.flatten(z, n);
    let w_R_flat = W_R.flatten(z, n);

    // \delta = <y^n * w_R_flat, w_L_flat>
    dot(elt_wise_mul(y_inv_powers_to_n, w_R_flat.span()).span(), w_L_flat.span())
}
