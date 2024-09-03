#![doc = include_str!("../README.md")]

#[macro_use]
extern crate pbc_contract_codegen;
extern crate pbc_contract_common;
extern crate sha2;
extern crate secp256k1;
extern crate hex;

use secp256k1::{Secp256k1, SecretKey as SecpSecretKey, PublicKey as SecpPublicKey};
use sha2::{Sha512, Digest};
use hex::encode;
use pbc_contract_common::address::Address;
use pbc_contract_common::context::ContractContext;
use pbc_contract_common::events::EventGroup;
use pbc_contract_common::zk::{ZkState, ZkStateChange, ZkInputDef};
use pbc_contract_codegen::{state, init, zk_on_secret_input};
use create_type_spec_derive::CreateTypeSpec;
use read_write_state_derive::ReadWriteState;
use pbc_contract_common::avl_tree_map::AvlTreeMap;

#[derive(ReadWriteState, Debug)]
#[repr(C)]
struct SecretVarMetadata {
    variable_type: SecretVarType,
    uid: u64,
}

#[derive(ReadWriteState, Debug, PartialEq)]
#[repr(u8)]
enum SecretVarType {
    PublicKey = 1,
    PrivateKey = 2,
}

#[derive(ReadWriteState, CreateTypeSpec, Clone)]
struct KeyPair {
    uid: u64,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[state]
struct ContractState {
    owner: Address,
    key_pair: AvlTreeMap<u64, KeyPair>, 
    counter: u64,
}

#[init(zk = true)]
fn initialize(ctx: ContractContext, _zk_state: ZkState<SecretVarMetadata>) -> (ContractState, Vec<EventGroup>) {
    let state = ContractState {
        owner: ctx.sender,
        key_pair: AvlTreeMap::new(),
        counter: 0,
    };

    (state, vec![])
}

#[zk_on_secret_input(shortname = 0x02)]
fn generate_key_action(
    context: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<SecretVarMetadata>,
) -> (ContractState, Vec<EventGroup>, ZkInputDef<SecretVarMetadata, [u8; 2]>) {
    assert!(
        context.sender == state.owner,
        "Only the owner can generate keys."
    );

    // Generate a deterministic key pair
    let (secret_key, public_key) = generate_key_pair(state.counter);

    // Generate a UID for the key pair
    let uid = state.counter;

    // Update the contract state with the key pair including UID
    state.key_pair.insert(uid, KeyPair {
        uid,
        public_key: public_key.to_vec(),
        private_key: vec![], 
    });

    // Define ZK input with UID
    let input_def = ZkInputDef::with_metadata(
        None,
        SecretVarMetadata {
            variable_type: SecretVarType::PrivateKey,
            uid,
        },
    );

    // Prepare the ZK state changes
    let mut zk_state_changes = vec![];
    zk_state_changes.push(ZkStateChange::ContractDone);

    // Increment the counter
    state.counter += 1;

    (state, vec![], input_def)
}

/// Generates a deterministic key pair (public and private keys) using a fixed counter
fn generate_key_pair(counter: u64) -> ([u8; 32], [u8; 33]) {
    // Use a fixed seed combined with the counter to generate deterministic key
    let seed = b"fixed_deterministic_seed";
    let mut hasher = Sha512::new();
    hasher.update(seed);
    hasher.update(&counter.to_be_bytes());
    let hash = hasher.finalize();

    let secret_key_bytes = &hash[..32];
    let secret_key = SecpSecretKey::from_slice(secret_key_bytes)
        .expect("32 bytes, within curve order");
    let secp = Secp256k1::new();
    let public_key = SecpPublicKey::from_secret_key(&secp, &secret_key);

    let mut secret_key_arr = [0u8; 32];
    secret_key_arr.copy_from_slice(secret_key_bytes);

    let mut public_key_arr = [0u8; 33];
    public_key_arr.copy_from_slice(&public_key.serialize());

    (secret_key_arr, public_key_arr)
}
