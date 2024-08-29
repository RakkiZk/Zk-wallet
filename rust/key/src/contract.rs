#![doc = include_str!("../README.md")]

#[macro_use]
extern crate pbc_contract_codegen;
extern crate pbc_contract_common;
extern crate ed25519_dalek;
extern crate sha2;
extern crate hex;

use ed25519_dalek::{SecretKey, PublicKey};
use sha2::{Sha512, Digest};
use hex::encode;
use pbc_contract_common::address::Address;
use pbc_contract_common::context::ContractContext;
use pbc_contract_common::events::EventGroup;
use pbc_contract_common::zk::{ZkState, ZkStateChange, ZkInputDef};
use pbc_contract_codegen::{state, init, zk_on_secret_input};
use crate::zk_compute::store_private_key;

use pbc_contract_common::shortname::ShortnameZkVariableInputted;

use read_write_state_derive::ReadWriteState;
use create_type_spec_derive::CreateTypeSpec;

mod zk_compute;

#[derive(ReadWriteState, Debug)]
#[repr(C)]
struct SecretVarMetadata {
    variable_type: SecretVarType,
}

#[derive(ReadWriteState, Debug, PartialEq)]
#[repr(u8)]
enum SecretVarType {
    PublicKey = 1,
    PrivateKey = 2,
}

#[derive(ReadWriteState, CreateTypeSpec, Clone)]
struct KeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[state]
struct ContractState {
    owner: Address,
    key_pair: Vec<KeyPair>,
    counter: u64,
}

#[init(zk = true)]
fn initialize(ctx: ContractContext, _zk_state: ZkState<SecretVarMetadata>) -> (ContractState, Vec<EventGroup>) {
    let state = ContractState {
        owner: ctx.sender,
        key_pair: Vec::new(),
        counter: 0,
    };

    (state, vec![])
}

#[zk_on_secret_input(shortname = 0x02)]
fn generate_key_action(
    context: ContractContext,
    mut state: ContractState,
    zk_state: ZkState<SecretVarMetadata>,
) -> (ContractState, Vec<EventGroup>, ZkInputDef<SecretVarMetadata, [u8; 2]>) {
    assert!(
        context.sender == state.owner,
        "Only the owner can generate keys."
    );

    let seed = b"fixed_deterministic_seed";
    let dynamic_component = state.counter.to_be_bytes();
    
    // Use a unique identifier combining sender address and contract address
    let unique_id = [
        context.sender.to_string().as_bytes(),
        context.contract_address.to_string().as_bytes(),
        &state.counter.to_be_bytes(),
    ].concat();
    
    

    let (secret_key, public_key) = generate_key_pair(seed, &dynamic_component, &unique_id);

    // Store private key in ZK context
    let sbi_key = store_private_key(secret_key);
    
    // Update the contract state with the public key only
    state.key_pair.push(KeyPair {
        public_key: public_key.to_vec(),
        private_key: vec![],
    });

    // Define ZK input
    let input_def = ZkInputDef::with_metadata(
        None,
        SecretVarMetadata {
            variable_type: SecretVarType::PrivateKey,
        },
    );

    // Prepare the ZK state changes
    let mut zk_state_changes = vec![];
    zk_state_changes.push(ZkStateChange::ContractDone);

    state.counter += 1;

    (state, vec![], input_def)
}

/// Generates a key pair (public and private keys)
fn generate_key_pair(seed: &[u8], dynamic_component: &[u8], unique_id: &[u8]) -> ([u8; 32], [u8; 32]) {
    // Combine the seed, dynamic component, and a unique identifier
    let mut hasher = Sha512::new();
    hasher.update(seed);
    hasher.update(dynamic_component);
    hasher.update(unique_id); // Include unique identifier to ensure uniqueness
    let hash = hasher.finalize();

    let secret_key_bytes = &hash[..32];
    let secret_key = SecretKey::from_bytes(secret_key_bytes)
        .expect("32 bytes, within curve order");

    let public_key = PublicKey::from(&secret_key);

    let mut secret_key_arr = [0u8; 32];
    secret_key_arr.copy_from_slice(secret_key_bytes);

    let mut public_key_arr = [0u8; 32];
    public_key_arr.copy_from_slice(&public_key.to_bytes());

    (secret_key_arr, public_key_arr)
}

