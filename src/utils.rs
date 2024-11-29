// SPDX-License-Identifier: MIT

use crate::utils;
use bs58::{decode as base58_decode, encode as base58_encode, Alphabet as Alphabet58};
use hex;
use hex::ToHex;
use serde_jcs::{to_string as jcs_to_string, to_vec as jcs_from_str};
use sha2::{Digest, Sha256};

pub const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
pub const MKEY_CONTEXT: &str = "https://w3id.org/security/multikey/v1";
pub const SCID_PLACEHOLDER: &str = "{SCID}";
pub const SCID_MIN_LENGTH: usize = 32;
// See https://www.w3.org/TR/vc-di-eddsa/#ed25519verificationkey2020
pub const EDDSA_VERIFICATION_KEY_TYPE: &str = "Ed25519VerificationKey2020";

pub fn convert_to_multibase_base58btc(data: &[u8]) -> String {
    let encoded = base58_encode(data)
        .with_alphabet(Alphabet58::BITCOIN) // it is the default alphabet, but still (to ensure spec conformity)
        .into_string();
    // See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#name-base-58-bitcoin-encoding
    format!("z{}", encoded)
}

pub fn convert_from_multibase_base58btc(multibase: &str, result: &mut [u8]) {
    if !multibase.starts_with("z") {
        panic!("Invalid multibase format for base58btc");
    }
    let raw = multibase.chars().skip(1).collect::<String>(); // get rid of the multibase code
    match base58_decode(raw)
        .with_alphabet(bs58::Alphabet::BITCOIN) // it is the default alphabet, but still (to ensure spec conformity)
        .onto(result) // decode into the given buffer
    {
        Ok(_) => (),
        // e.g. "buffer provided to decode base58 encoded string into was too small"
        Err(err) => panic!("Entered base58btc content is invalid: {err}"),
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
            // Since v0.3 (https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
            //            Change base32 encoding with base58btc, as it offers a better expansion rate.
            // More here: https://identity.foundation/trustdidweb/v0.3/#generate-scid
            //            To generate the required [[ref: SCID]] for a did:tdw DID, the DID Controller MUST execute the following function:
            //            base58btc(multihash(JCS(preliminary log entry with placeholders), <hash algorithm>))
            let encoded = base58_encode(hash)
                .with_alphabet(Alphabet58::BITCOIN) // it is the default alphabet, but still (to ensure spec conformity)
                .into_string();
            if encoded.len() < utils::SCID_MIN_LENGTH {
                panic!(
                    "Invalid scid length. A minimum of {} is required",
                    utils::SCID_MIN_LENGTH
                );
            }

            // According to https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog:
            //              Use multihash in the SCID to differentiate the different hash function outputs.
            //              See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#name-base-58-bitcoin-encoding
            //
            // According to https://github.com/multiformats/multibase/blob/master/README.md#reserved-terms:
            //              Q (U+0051) - Base58-encoded sha2-256 multihashes used by libp2p/ipfs for peer IDs and CIDv0.
            format!("Q{}", encoded)
        }
        Err(_) => panic!("Invalid json couldn't canonicalize"),
    }
}
