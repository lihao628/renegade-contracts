//! The darkpool smart contract, responsible for maintaining the set of nullified wallets,
//! verifying the various proofs of the Renegade protocol, and handling deposits / withdrawals.

use alloc::vec::Vec;
use common::{
    constants::HASH_OUTPUT_SIZE,
    serde_def_types::SerdeScalarField,
    types::{
        MatchPayload, ScalarField, ValidMatchSettleStatement, ValidWalletCreateStatement,
        ValidWalletUpdateStatement,
    },
};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{aliases::B256, Address},
    call::static_call,
    crypto::keccak,
    prelude::*,
    storage::{StorageAddress, StorageBool, StorageFixedBytes, StorageMap},
};

use crate::{
    constants::{
        VALID_COMMITMENTS_CIRCUIT_ID, VALID_MATCH_SETTLE_CIRCUIT_ID, VALID_REBLIND_CIRCUIT_ID,
        VALID_WALLET_CREATE_CIRCUIT_ID, VALID_WALLET_UPDATE_CIRCUIT_ID,
    },
    utils::serialize_statement_for_verification,
};

pub type SolScalar = B256;

#[solidity_storage]
#[cfg_attr(feature = "darkpool", entrypoint)]
pub struct DarkpoolContract {
    /// The address of the verifier contract
    verifier_address: StorageAddress,

    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    nullifier_set: StorageMap<SolScalar, StorageBool>,

    /// The set of verification keys hashes, representing a mapping from a circuit ID
    /// to the Keccak256 hash of a serialized verification key
    verification_key_hashes: StorageMap<u8, StorageFixedBytes<HASH_OUTPUT_SIZE>>,
}

#[external]
impl DarkpoolContract {
    // ----------
    // | CONFIG |
    // ----------

    /// Stores the given address for the verifier contract
    pub fn set_verifier_address(&mut self, address: Address) -> Result<(), Vec<u8>> {
        self.verifier_address.set(address);
        Ok(())
    }

    /// Sets the verification key for the `VALID_WALLET_CREATE` circuit
    pub fn set_valid_wallet_create_vkey_hash(&mut self, vkey_hash: B256) -> Result<(), Vec<u8>> {
        self.set_vkey_hash(VALID_WALLET_CREATE_CIRCUIT_ID, vkey_hash);
        Ok(())
    }

    /// Sets the verification key for the `VALID_WALLET_UPDATE` circuit
    pub fn set_valid_wallet_update_vkey_hash(&mut self, vkey_hash: B256) -> Result<(), Vec<u8>> {
        self.set_vkey_hash(VALID_WALLET_UPDATE_CIRCUIT_ID, vkey_hash);
        Ok(())
    }

    /// Sets the verification key for the `VALID_COMMITMENTS` circuit
    pub fn set_valid_commitments_vkey_hash(&mut self, vkey_hash: B256) -> Result<(), Vec<u8>> {
        self.set_vkey_hash(VALID_COMMITMENTS_CIRCUIT_ID, vkey_hash);
        Ok(())
    }

    /// Sets the verification key for the `VALID_REBLIND` circuit
    pub fn set_valid_reblind_vkey_hash(&mut self, vkey_hash: B256) -> Result<(), Vec<u8>> {
        self.set_vkey_hash(VALID_REBLIND_CIRCUIT_ID, vkey_hash);
        Ok(())
    }

    /// Sets the verification key for the `VALID_MATCH_SETTLE` circuit
    pub fn set_valid_match_settle_vkey_hash(&mut self, vkey_hash: B256) -> Result<(), Vec<u8>> {
        self.set_vkey_hash(VALID_MATCH_SETTLE_CIRCUIT_ID, vkey_hash);
        Ok(())
    }

    // -----------
    // | GETTERS |
    // -----------

    /// Checks whether the given nullifier is spent
    pub fn is_nullifier_spent(&self, nullifier: SolScalar) -> Result<bool, Vec<u8>> {
        Ok(self.nullifier_set.get(nullifier))
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Adds a new wallet to the commitment tree
    // TODO: Return new tree root
    pub fn new_wallet(
        &mut self,
        _wallet_blinder_share: SolScalar,
        vkey: Bytes,
        proof: Bytes,
        valid_wallet_create_statement_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_wallet_create_statement: ValidWalletCreateStatement =
            postcard::from_bytes(valid_wallet_create_statement_bytes.as_slice()).unwrap();

        let public_inputs = serialize_statement_for_verification(&valid_wallet_create_statement)
            .unwrap()
            .into();

        assert!(
            self.verify(VALID_WALLET_CREATE_CIRCUIT_ID, vkey, proof, public_inputs)?,
            "`VALID_WALLET_CREATE` proof invalid"
        );

        // TODO: Compute wallet commitment and insert to Merkle tree
        // TODO: Emit wallet updated event w/ wallet blinder share

        Ok(())
    }

    /// Update a wallet in the commitment tree
    // TODO: Return new tree root
    pub fn update_wallet(
        &mut self,
        _wallet_blinder_share: SolScalar,
        vkey: Bytes,
        proof: Bytes,
        valid_wallet_update_statement_bytes: Bytes,
        _public_inputs_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        let valid_wallet_update_statement: ValidWalletUpdateStatement =
            postcard::from_bytes(valid_wallet_update_statement_bytes.as_slice()).unwrap();

        // TODO: Assert that the Merkle root for which inclusion is proven in `VALID_WALLET_UPDATE`
        // is a valid historical root

        // TODO: Hash public inputs and verify signature (requires parsing pk_root from public inputs)

        let public_inputs = serialize_statement_for_verification(&valid_wallet_update_statement)
            .unwrap()
            .into();

        assert!(
            self.verify(VALID_WALLET_UPDATE_CIRCUIT_ID, vkey, proof, public_inputs)?,
            "`VALID_WALLET_UPDATE` proof invalid"
        );

        // TODO: Compute wallet commitment and insert to Merkle tree

        self.mark_nullifier_spent(valid_wallet_update_statement.old_shares_nullifier)?;

        // TODO: Execute external transfers
        // TODO: Emit wallet updated event w/ wallet blinder share

        Ok(())
    }

    /// Settles a matched order between two parties,
    /// inserting the updated wallets into the commitment tree
    // TODO: Return new tree root
    #[allow(clippy::too_many_arguments)]
    pub fn process_match_settle(
        &mut self,
        party_0_match_payload: Bytes,
        party_0_valid_commitments_proof: Bytes,
        party_0_valid_reblind_proof: Bytes,
        party_1_match_payload: Bytes,
        party_1_valid_commitments_proof: Bytes,
        party_1_valid_reblind_proof: Bytes,
        valid_match_settle_proof: Bytes,
        valid_match_settle_statement: Bytes,
        valid_commitments_vkey: Bytes,
        valid_reblind_vkey: Bytes,
        valid_match_settle_vkey: Bytes,
    ) -> Result<(), Vec<u8>> {
        let party_0_match_payload: MatchPayload =
            postcard::from_bytes(party_0_match_payload.as_slice()).unwrap();

        let party_1_match_payload: MatchPayload =
            postcard::from_bytes(party_1_match_payload.as_slice()).unwrap();

        let valid_match_settle_statement: ValidMatchSettleStatement =
            postcard::from_bytes(valid_match_settle_statement.as_slice()).unwrap();

        // TODO: Assert that the Merkle roots for which inclusion is proven in `VALID_REBLIND`
        // are valid historical roots

        let party_0_valid_commitments_public_inputs = serialize_statement_for_verification(
            &party_0_match_payload.valid_commitments_statement,
        )
        .unwrap()
        .into();

        assert!(
            self.verify(
                VALID_COMMITMENTS_CIRCUIT_ID,
                valid_commitments_vkey.clone(),
                party_0_valid_commitments_proof,
                party_0_valid_commitments_public_inputs
            )?,
            "Party 0 `VALID_COMMITMENTS` proof invalid"
        );

        let party_1_valid_commitments_public_inputs = serialize_statement_for_verification(
            &party_1_match_payload.valid_commitments_statement,
        )
        .unwrap()
        .into();

        assert!(
            self.verify(
                VALID_COMMITMENTS_CIRCUIT_ID,
                valid_commitments_vkey,
                party_1_valid_commitments_proof,
                party_1_valid_commitments_public_inputs
            )?,
            "Party 1 `VALID_COMMITMENTS` proof invalid"
        );

        let party_0_valid_reblind_public_inputs =
            serialize_statement_for_verification(&party_0_match_payload.valid_reblind_statement)
                .unwrap()
                .into();

        assert!(
            self.verify(
                VALID_REBLIND_CIRCUIT_ID,
                valid_reblind_vkey.clone(),
                party_0_valid_reblind_proof,
                party_0_valid_reblind_public_inputs
            )?,
            "Party 0 `VALID_REBLIND` proof invalid"
        );

        let party_1_valid_reblind_public_inputs =
            serialize_statement_for_verification(&party_1_match_payload.valid_reblind_statement)
                .unwrap()
                .into();

        assert!(
            self.verify(
                VALID_REBLIND_CIRCUIT_ID,
                valid_reblind_vkey,
                party_1_valid_reblind_proof,
                party_1_valid_reblind_public_inputs
            )?,
            "Party 1 `VALID_REBLIND` proof invalid"
        );

        let valid_match_settle_public_inputs =
            serialize_statement_for_verification(&valid_match_settle_statement)
                .unwrap()
                .into();
        assert!(
            self.verify(
                VALID_MATCH_SETTLE_CIRCUIT_ID,
                valid_match_settle_vkey,
                valid_match_settle_proof,
                valid_match_settle_public_inputs
            )?,
            "`VALID_MATCH_SETTLE` proof invalid"
        );

        // TODO: Compute wallet commitments and insert to Merkle tree

        self.mark_nullifier_spent(
            party_0_match_payload
                .valid_reblind_statement
                .original_shares_nullifier,
        )?;
        self.mark_nullifier_spent(
            party_1_match_payload
                .valid_reblind_statement
                .original_shares_nullifier,
        )?;

        // TODO: Emit wallet updated events w/ wallet blinder shares

        Ok(())
    }
}

/// Internal helper methods
impl DarkpoolContract {
    /// Sets the verification key for the given circuit ID
    pub fn set_vkey_hash(&mut self, circuit_id: u8, vkey_hash: B256) {
        // TODO: Assert well-formedness of the verification key

        self.verification_key_hashes.insert(circuit_id, vkey_hash);
    }

    /// Marks the given nullifier as spent
    pub fn mark_nullifier_spent(&mut self, nullifier: ScalarField) -> Result<(), Vec<u8>> {
        let nullifier_ser: SolScalar = SolScalar::from_slice(
            postcard::to_allocvec(&SerdeScalarField(nullifier))
                .unwrap()
                .as_slice(),
        );

        assert!(
            !self.nullifier_set.get(nullifier_ser),
            "Nullifier already spent"
        );

        self.nullifier_set.insert(nullifier_ser, true);
        Ok(())
    }

    /// Verifies the given proof using the given public inputs,
    /// and using the stored verification key associated with the circuit ID
    pub fn verify(
        &mut self,
        circuit_id: u8,
        vkey: Bytes,
        proof: Bytes,
        public_inputs: Bytes,
    ) -> Result<bool, Vec<u8>> {
        let vkey_hash = self.verification_key_hashes.get(circuit_id);
        assert!(!vkey_hash.is_zero(), "No verification key for circuit ID");
        assert_eq!(vkey_hash, keccak(&vkey), "Invalid verification key");

        let verifier_address = self.verifier_address.get();
        let verification_bundle_ser = [vkey.0, proof.0, public_inputs.0].concat();
        let result = static_call(self, verifier_address, &verification_bundle_ser)?;

        Ok(result[0] != 0)
    }
}
