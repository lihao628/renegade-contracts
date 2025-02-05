//! Test helpers specific to the Renegade protocol circuits and their statements

use alloc::vec::Vec;
use alloy_primitives::{Address, U256};

use ark_std::UniformRand;
use common::{
    constants::{NUM_BYTES_ADDRESS, NUM_BYTES_U256, WALLET_SHARES_LEN},
    custom_serde::ScalarSerializable,
    types::{
        ExternalTransfer, Proof, PublicSigningKey, ScalarField, ValidCommitmentsStatement,
        ValidMatchSettleStatement, ValidReblindStatement, ValidWalletUpdateStatement,
        VerificationKey,
    },
};
use core::iter;
use eyre::{eyre, Result};
use rand::Rng;
use serde::Serialize;

use crate::proof_system::{convert_jf_proof_and_vkey, gen_jf_proof_and_vkey};

pub enum Circuit {
    ValidWalletCreate,
    ValidWalletUpdate,
    ValidCommitments,
    ValidReblind,
    ValidMatchSettle,
}

pub trait RenegadeStatement: Serialize + ScalarSerializable {
    fn dummy(rng: &mut impl Rng) -> Self;
}

impl RenegadeStatement for ValidWalletUpdateStatement {
    fn dummy(rng: &mut impl Rng) -> Self {
        ValidWalletUpdateStatement {
            old_shares_nullifier: ScalarField::rand(rng),
            new_private_shares_commitment: ScalarField::rand(rng),
            new_public_shares: dummy_wallet_shares(rng),
            merkle_root: ScalarField::rand(rng),
            external_transfer: Some(dummy_external_transfer(rng)),
            old_pk_root: dummy_public_signing_key(rng),
            timestamp: rng.gen(),
        }
    }
}

impl RenegadeStatement for ValidCommitmentsStatement {
    fn dummy(rng: &mut impl Rng) -> Self {
        ValidCommitmentsStatement {
            balance_send_index: rng.gen(),
            balance_receive_index: rng.gen(),
            order_index: rng.gen(),
        }
    }
}

impl RenegadeStatement for ValidReblindStatement {
    fn dummy(rng: &mut impl Rng) -> Self {
        ValidReblindStatement {
            original_shares_nullifier: ScalarField::rand(rng),
            reblinded_private_shares_commitment: ScalarField::rand(rng),
            merkle_root: ScalarField::rand(rng),
        }
    }
}

impl RenegadeStatement for ValidMatchSettleStatement {
    fn dummy(rng: &mut impl Rng) -> Self {
        ValidMatchSettleStatement {
            party0_modified_shares: dummy_wallet_shares(rng),
            party1_modified_shares: dummy_wallet_shares(rng),
            party0_send_balance_index: rng.gen(),
            party0_receive_balance_index: rng.gen(),
            party0_order_index: rng.gen(),
            party1_send_balance_index: rng.gen(),
            party1_receive_balance_index: rng.gen(),
            party1_order_index: rng.gen(),
        }
    }
}

fn dummy_wallet_shares(rng: &mut impl Rng) -> [ScalarField; WALLET_SHARES_LEN] {
    iter::repeat(ScalarField::rand(rng))
        .take(WALLET_SHARES_LEN)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn dummy_address(rng: &mut impl Rng) -> Address {
    Address::from_slice(
        iter::repeat(u8::rand(rng))
            .take(NUM_BYTES_ADDRESS)
            .collect::<Vec<_>>()
            .as_slice(),
    )
}

fn dummy_u256(rng: &mut impl Rng) -> U256 {
    U256::from_be_bytes::<NUM_BYTES_U256>(
        iter::repeat(u8::rand(rng))
            .take(NUM_BYTES_U256)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    )
}

fn dummy_external_transfer(rng: &mut impl Rng) -> ExternalTransfer {
    ExternalTransfer {
        account_addr: dummy_address(rng),
        mint: dummy_address(rng),
        amount: dummy_u256(rng),
        is_withdrawal: rng.gen(),
    }
}

fn dummy_public_signing_key(rng: &mut impl Rng) -> PublicSigningKey {
    PublicSigningKey {
        x: [ScalarField::rand(rng), ScalarField::rand(rng)],
        y: [ScalarField::rand(rng), ScalarField::rand(rng)],
    }
}

pub fn circuit_bundle_from_statement<S: RenegadeStatement>(
    statement: &S,
    num_public_inputs: usize,
) -> Result<(VerificationKey, Proof)> {
    let public_inputs = statement
        .serialize_to_scalars()
        .map_err(|_| eyre!("failed to serialize statement to scalars"))?;
    let (jf_proof, jf_vkey) = gen_jf_proof_and_vkey(num_public_inputs, &public_inputs)?;
    let (proof, vkey) = convert_jf_proof_and_vkey(jf_proof, jf_vkey);

    Ok((vkey, proof))
}

pub fn dummy_circuit_bundle<S: RenegadeStatement>(
    num_public_inputs: usize,
    rng: &mut impl Rng,
) -> Result<(S, VerificationKey, Proof)> {
    let statement = S::dummy(rng);
    let (vkey, proof) = circuit_bundle_from_statement(&statement, num_public_inputs)?;
    Ok((statement, vkey, proof))
}
