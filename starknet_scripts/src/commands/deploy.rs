//! Script to deploy the Darkpool & associated contracts (Merkle, NullifierSet)

use std::collections::HashMap;

use eyre::Result;
use starknet::core::types::FieldElement;
use tracing::{debug, info, warn};

use crate::{
    cli::{Contract, DeployArgs},
    commands::utils::{
        deploy_darkpool, deploy_merkle, deploy_nullifier_set, deploy_usdc_erc20, dump_deployments,
        initialize, setup_account, MERKLE_HEIGHT,
    },
};

use super::utils::ScriptAccount;

/// Deploy and initialize a set of contracts specified in the CLI
pub async fn deploy_and_initialize(args: DeployArgs) -> Result<()> {
    // Setup account
    debug!("Setting up account...");
    let address_felt = FieldElement::from_hex_be(&args.address)?;
    let account = setup_account(address_felt, args.private_key.clone(), args.network.clone())?;

    let mut addr_map = HashMap::new();
    for contract in args.contracts.iter().copied() {
        let addr = deploy_and_initialize_contract(contract, &account, args.clone()).await?;
        addr_map.insert(contract, addr);
    }

    if args.dump_deployments {
        dump_deployments(addr_map)?;
    }
    Ok(())
}

/// Deploy and initialize a single contract
///
/// Returns the deployed contract's address
async fn deploy_and_initialize_contract(
    contract: Contract,
    account: &ScriptAccount,
    args: DeployArgs,
) -> Result<FieldElement> {
    let DeployArgs {
        darkpool_class_hash,
        merkle_class_hash,
        nullifier_set_class_hash,
        initialize: should_initialize,
        artifacts_path,
        ..
    } = args;

    let deployed_addr = match contract {
        Contract::Darkpool => {
            let (
                darkpool_address,
                darkpool_class_hash_felt,
                merkle_class_hash_felt,
                nullifier_set_class_hash_felt,
                transaction_hash,
            ) = deploy_darkpool(
                darkpool_class_hash,
                merkle_class_hash,
                nullifier_set_class_hash,
                artifacts_path,
                account,
            )
            .await?;

            info!(
                "Darkpool contract successfully deployed & initialized!\n\
                Darkpool contract address: {:#64x}\n\
                Darkpool class hash: {:#64x}\n\
                Merkle class hash: {:#64x}\n\
                Nullifier set class hash: {:#64x}\n\
                Transaction hash: {:#64x}\n",
                darkpool_address,
                darkpool_class_hash_felt,
                merkle_class_hash_felt,
                nullifier_set_class_hash_felt,
                transaction_hash,
            );

            if should_initialize {
                // Initialize darkpool
                debug!("Initializing darkpool contract...");
                let calldata = vec![
                    merkle_class_hash_felt,
                    nullifier_set_class_hash_felt,
                    FieldElement::from(MERKLE_HEIGHT),
                ];
                let initialization_result = initialize(account, darkpool_address, calldata).await?;

                info!(
                    "Darkpool contract initialized!\n\
                    Transaction hash: {:#64x}\n",
                    initialization_result.transaction_hash,
                );
            }

            darkpool_address
        }
        Contract::Merkle => {
            let (merkle_address, merkle_class_hash_felt, transaction_hash) =
                deploy_merkle(merkle_class_hash, artifacts_path, account).await?;

            info!(
                "Merkle contract successfully deployed!\n\
                Merkle contract address: {:#64x}\n\
                Merkle class hash: {:#64x}\n\
                Transaction hash: {:#64x}\n",
                merkle_address, merkle_class_hash_felt, transaction_hash,
            );

            if should_initialize {
                // Initialize merkle
                debug!("Initializing merkle contract...");
                let calldata = vec![FieldElement::from(MERKLE_HEIGHT)];
                let initialization_result = initialize(account, merkle_address, calldata).await?;

                info!(
                    "Merkle contract successfully initialized!\n\
                    Transaction hash: {:#64x}\n",
                    initialization_result.transaction_hash,
                );
            }

            merkle_address
        }
        Contract::NullifierSet => {
            let (nullifier_set_address, nullifier_set_class_hash_felt, transaction_hash) =
                deploy_nullifier_set(nullifier_set_class_hash, artifacts_path, account).await?;

            info!(
                "Nullifier set contract successfully deployed!\n\
                Nullifier set contract address: {:#64x}\n\
                Nullifier set class hash: {:#64x}\n\
                Transaction hash: {:#64x}\n",
                nullifier_set_address, nullifier_set_class_hash_felt, transaction_hash,
            );

            nullifier_set_address
        }

        Contract::USDC => {
            warn!("USDC ERC20 deployment should *only* be used for testing");
            let (usdc_address, usdc_class_hash, transaction_hash) =
                deploy_usdc_erc20(artifacts_path, account).await?;

            info!(
                "USDC contract successfully deployed!\n\
                USDC contract address: {:#64x}\n\
                USDC class hash: {:#64x}\n\
                Transaction hash: {:#64x}\n",
                usdc_address, usdc_class_hash, transaction_hash,
            );

            usdc_address
        }
    };

    Ok(deployed_addr)
}
