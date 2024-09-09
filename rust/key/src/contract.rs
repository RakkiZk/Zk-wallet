extern crate pbc_contract_common;
extern crate sha2;
extern crate secp256k1;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use secp256k1::{Secp256k1, SecretKey as SecpSecretKey, PublicKey as SecpPublicKey, Message, ecdsa::Signature};
use sha2::{Sha512, Sha256, Digest};
use pbc_contract_common::address::Address;
use pbc_contract_common::context::ContractContext;
use pbc_contract_common::events::EventGroup;
use pbc_contract_common::zk::{ZkState, ZkStateChange, ZkInputDef};
use pbc_contract_codegen::{state, init, zk_on_secret_input};
use create_type_spec_derive::CreateTypeSpec;
use read_write_state_derive::ReadWriteState;
use pbc_contract_common::avl_tree_map::AvlTreeMap;
use serde::{Serialize, Deserialize};

use pbc_zk::SecretBinary;
use pbc_zk::zk_compute;
use crate::zk_compute::store_private_key;
use crate::zk_compute::store_signature;
mod zk_compute;

#[derive(ReadWriteState, Debug, Serialize, Deserialize)]
#[repr(C)]
struct SecretVarMetadata {
    variable_type: SecretVarType,
    uid: u64,
}

#[derive(ReadWriteState, Debug, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
enum SecretVarType {
    PublicKey = 1,
    PrivateKey = 2,
    SignatureVerification = 3,
}

#[derive(ReadWriteState, CreateTypeSpec, Clone, Serialize, Deserialize)]
struct KeyPair {
    uid: u64,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[state]
struct ContractState {
    owner: Address,
    key_pair: AvlTreeMap<u64, KeyPair>,
    signed_messages: AvlTreeMap<u64, [u8; 64]>,
    counter: u64,
}

#[init(zk = true)]
fn initialize(ctx: ContractContext, _zk_state: ZkState<SecretVarMetadata>) -> (ContractState, Vec<EventGroup>) {
    let state = ContractState {
        owner: ctx.sender,
        key_pair: AvlTreeMap::new(),
        signed_messages: AvlTreeMap::new(),
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

    let (secret_key, public_key) = generate_key_pair(state.counter);
    let secret_key_arr = secret_key;
    

    let _sbi_private_key = store_private_key(secret_key_arr);

    let uid = state.counter;
    let message = format!("UID: {}, PublicKey: {:?}", uid, public_key);
    let message_hash = sha256(&message);
    let signature = sign_message(secret_key_arr, &message_hash).expect("Signing failed");
    
    // Encrypt the signature
    let encrypted_signature = store_signature(signature);

    state.key_pair.insert(uid, KeyPair {
        uid,
        public_key: public_key.to_vec(),
        private_key: vec![],
    });

    state.signed_messages.insert(uid, encrypted_signature.signature);

    let input_def = ZkInputDef::with_metadata(
        None,
        SecretVarMetadata {
            variable_type: SecretVarType::PrivateKey,
            uid,
        },
    );

    state.counter += 1;
    (state, vec![], input_def)
}


#[zk_on_secret_input(shortname = 0x03)]
fn verify_signature_action(
    context: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<SecretVarMetadata>,
    uid: u64,               
    public_key: [u8; 33],   
    signature: [u8; 64], 
) -> (ContractState, Vec<EventGroup>, ZkInputDef<SecretVarMetadata, [u8; 2]>) {
    assert!(
        context.sender == state.owner,
        "Only the owner can verify signatures."
    );

    // Look up the key pair and message signature by UID
    let key_pair = state.key_pair.get(&uid).expect("UID not found");
    let stored_signature = state.signed_messages.get(&uid).expect("Signature not found");

    // Construct the message to verify
    let message = format!("UID: {}, PublicKey: {:?}", uid, key_pair.public_key);
    let message_hash = sha256(&message);

    // Convert public key and signature from input
    let public_key = SecpPublicKey::from_slice(&public_key).expect("Invalid public key");
    let signature = Signature::from_compact(&signature).expect("Invalid signature");

    // Verify the signature
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(&message_hash).expect("Invalid message hash");
    let verified = secp.verify_ecdsa(&message, &signature, &public_key).is_ok();

    assert!(verified, "Signature verification failed.");

    // Define ZK input with UID
    let input_def = ZkInputDef::with_metadata(
        None,
        SecretVarMetadata {
            variable_type: SecretVarType::SignatureVerification,
            uid,
        },
    );

    // Prepare the ZK state changes
    let mut zk_state_changes = vec![];
    zk_state_changes.push(ZkStateChange::ContractDone);

    (state, vec![], input_def)
}


/// Generates a deterministic key pair (public and private keys) using a fixed counter
fn generate_key_pair(counter: u64) -> ([u8; 32], [u8; 33]) {
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

/// Signs a message using the provided private key.
pub fn sign_message(secret_key: [u8; 32], message: &[u8]) -> Result<[u8; 64], &'static str> {
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(message).map_err(|_| "Invalid message")?;
    let secret_key = SecpSecretKey::from_slice(&secret_key).map_err(|_| "Invalid secret key")?;
    let signature = secp.sign_ecdsa(&message, &secret_key);

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature.serialize_compact());

    Ok(sig_bytes)
}

/// Verifies a signature using the provided public key and message.
fn verify_signature(
    public_key: &SecpPublicKey,
    message: &[u8],
    signature: [u8; 64]
) -> Result<bool, &'static str> {
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(message).map_err(|_| "Invalid message")?;
    let signature = Signature::from_compact(&signature).map_err(|_| "Invalid signature")?;
    Ok(secp.verify_ecdsa(&message, &signature, &public_key).is_ok())
}

/// Computes the SHA-256 hash of the input data.
fn sha256(input: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
