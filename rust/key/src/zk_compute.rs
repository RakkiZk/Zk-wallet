use pbc_zk::*;

// Define the struct for storing private keys
pub struct SbiPrivateKey {
    private_key: [u8; 32],
}

// Function to securely store a private key using SBI32
pub fn store_private_key(private_key: [u8; 32]) -> SbiPrivateKey {
    SbiPrivateKey { private_key }
}

// Function to retrieve a private key from SbiPrivateKey
pub fn retrieve_private_key(sbi_key: SbiPrivateKey) -> [u8; 32] {
    sbi_key.private_key
}

// Define the struct for storing signatures
pub struct SbiSignature {
    pub signature: [u8; 64], 
}

// Function to store a signature
pub fn store_signature(signature: [u8; 64]) -> SbiSignature {
    SbiSignature { signature }
}

// Function for storing the private key
#[zk_compute(shortname = 0x61)]
pub fn store_private_key_action(private_key: [u8; 32]) -> [u8; 32] {
    let stored_private_key = store_private_key(private_key);
    stored_private_key.private_key
}

// Function for storing the signature
#[zk_compute(shortname = 0x62)]
pub fn store_signature_action(signature: [u8; 64]) -> [u8; 64] {
    let stored_signature = store_signature(signature);
    stored_signature.signature
}
