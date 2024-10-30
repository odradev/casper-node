//! Functions with cryptographic utils.

use casper_types::{api_error, bytesrepr::ToBytes, AsymmetricType, HashAlgorithm, PublicKey, Signature, BLAKE2B_DIGEST_LENGTH};

use crate::{ext_ffi, unwrap_or_revert::UnwrapOrRevert};

/// Computes digest hash, using provided algorithm type.
pub fn generic_hash<T: AsRef<[u8]>>(input: T, algo: HashAlgorithm) -> [u8; 32] {
    let mut ret = [0; 32];

    let result = unsafe {
        ext_ffi::casper_generic_hash(
            input.as_ref().as_ptr(),
            input.as_ref().len(),
            algo as u8,
            ret.as_mut_ptr(),
            BLAKE2B_DIGEST_LENGTH,
        )
    };
    api_error::result_from(result).unwrap_or_revert();
    ret
}

pub fn recover_secp256k1<T: AsRef<[u8]>>(
    data: T,
    signature: &Signature,
    v: u8
) -> PublicKey {
    let mut buffer = [0; PublicKey::SECP256K1_LENGTH];
    let signature_bytes = signature.to_bytes().unwrap();

    let result = unsafe {
        ext_ffi::casper_recover_secp256k1(
            data.as_ref().as_ptr(),
            data.as_ref().len(),
            signature_bytes.as_ptr(),
            signature_bytes.len(),
            buffer.as_mut_ptr(),
            v
        )
    };

    api_error::result_from(result).unwrap_or_revert();

    PublicKey::secp256k1_from_bytes(buffer).unwrap()
}
