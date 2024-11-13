// SPDX-License-Identifier: MIT
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::utils;
use base32::{decode as base32_decode, encode as base32_encode, Alphabet};
use bs58::{decode as base58_decode, encode as base58_encode, Alphabet as Alphabet58};
use hex;
use hex::ToHex;
use serde_jcs::{to_string as jcs_to_string, to_vec as jcs_from_str};
use sha2::{Digest, Sha256};

pub const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
pub const MKEY_CONTEXT: &str = "https://w3id.org/security/multikey/v1";
pub const SCID_PLACEHOLDER: &str = "{SCID}";
pub const SCID_MIN_LENGTH: usize = 32;
pub const DATE_TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.3f%z";
// See https://www.w3.org/TR/vc-di-eddsa/#ed25519verificationkey2020
pub const EDDSA_VERIFICATION_KEY_TYPE: &str = "Ed25519VerificationKey2020";

pub fn convert_to_multibase_base64(data: &[u8]) -> String {
    let b64 = URL_SAFE_NO_PAD.encode(data);
    return format!("u{}", b64);
}

pub fn convert_from_multibase_base64(multibase: &str, result: &mut [u8]) -> () {
    if !multibase.starts_with("u") {
        panic!("Invalid multibase format");
    }
    let raw = multibase.chars().skip(1).collect::<String>();
    match URL_SAFE_NO_PAD.decode_slice(raw, result) {
        Ok(_) => (),
        Err(_) => panic!("Entered base 64 content {} is invalid", multibase),
    }
}

pub fn generate_jcs_hash_from_value(value: &serde_json::Value) -> String {
    let json_doc = value.to_string();
    let jcs_doc = jcs_from_str(&json_doc).unwrap();
    let utf8_doc: String = String::from_utf8(jcs_doc).unwrap();
    let mut doc_hasher = Sha256::new();
    doc_hasher.update(utf8_doc);
    doc_hasher.finalize().encode_hex()
}

pub fn generate_jcs_hash(json: &str) -> String {
    match jcs_to_string(&json) {
        Ok(jcs) => {
            let mut hasher = Sha256::new();
            hasher.update(jcs.as_bytes());
            let hash: String = hasher.finalize().encode_hex();
            //
            // According to https://github.com.mcas.ms/decentralized-identity/trustdidweb/blob/63e21b69d84f7d9344f4e6ef4809e7823975c965/spec/specification.md#generate-scid:
            // To generate the required [[ref: SCID]] for a did:tdw DID, the DID Controller MUST execute the following function:
            //    base58btc(multihash(JCS(preliminary log entry with placeholders), <hash algorithm>))
            //
            let encoded = base58_encode(hash)
                //.with_alphabet(Alphabet58::BITCOIN) // default
                .as_cb58(None)
                .into_string();
            if encoded.len() < utils::SCID_MIN_LENGTH {
                panic!(
                    "Invalid scid length. A minimum of {} is required",
                    utils::SCID_MIN_LENGTH
                );
            }
            return encoded;
        }
        Err(_) => panic!("Invalid json couldn't canonicalize"),
    }
}
