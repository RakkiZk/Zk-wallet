use pbc_zk::*;

// Define the type for storing private key
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

// Example of using the stored private key
#[zk_compute(shortname = 0x61)]
pub fn use_stored_private_key() -> [u8; 32] {
    let private_key = SbiPrivateKey {
        private_key: [0u8; 32], 
    };

    retrieve_private_key(private_key)
}
