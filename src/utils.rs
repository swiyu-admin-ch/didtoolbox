// SPDX-License-Identifier: MIT

use crate::utils;
use bs58::{decode as base58_decode, encode as base58_encode, Alphabet as Alphabet58};
use hex;
use hex::ToHex;
// CAUTION Using the serde_jcs crate here may cause:
//         "not yet implemented: Handle number str (u128/i128)".
//         (in case of numeric json properties, e.g. witnessThreshold)
use serde_json_canonicalizer::to_string as jcs_to_string;
//use serde_jcs::{to_string as jcs_to_string, to_vec as jcs_from_str};
use sha2::{Digest, Sha256};

pub const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
pub const MKEY_CONTEXT: &str = "https://w3id.org/security/multikey/v1";
pub const SCID_PLACEHOLDER: &str = "{SCID}";
pub const SCID_MIN_LENGTH: usize = 32;

pub fn to_multibase_base58btc(data: &[u8]) -> String {
    let encoded = base58_encode(data)
        .with_alphabet(Alphabet58::BITCOIN) // it is the default alphabet, but still (to ensure spec conformity)
        .into_string();
    // See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#name-base-58-bitcoin-encoding
    format!("z{}", encoded)
}

pub fn from_multibase_base58btc(multibase: &str, result: &mut [u8]) {
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

pub fn hash_canonical(json: &serde_json::Value) -> String {
    let jcs = jcs_to_string(json).unwrap();
    let mut doc_hasher = Sha256::new();
    doc_hasher.update(jcs);
    doc_hasher.finalize().encode_hex()
}

pub fn base58btc_encode_multihash(json: &serde_json::Value) -> String {
    match jcs_to_string(json) {
        Ok(jcs) => {
            let mut hasher = Sha256::new();
            // WORKAROUND (":ff" -> ":") in case of numeric json properties (e.g. witnessThreshold)
            hasher.update(jcs.replace(":ff", ":"));
            let digest = hasher.clone().finalize().as_slice().to_owned();

            // According to https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog:
            //              Use multihash in the SCID to differentiate the different hash function outputs.
            //              See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#name-base-58-bitcoin-encoding

            // https://www.w3.org/TR/controller-document/#multihash
            let multihash_header: &[u8] = &[
                0x12u8, // hash algorithm (sha2-256) identifier: SHA-2 with 256 bits (32 bytes) of output, as defined by [RFC6234]
                digest.len() as u8, // hash size (in bytes)
            ];
            let multihash_digest = [multihash_header, digest.as_slice()].concat();

            //
            // Since v0.3 (https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
            //            Change base32 encoding with base58btc, as it offers a better expansion rate.
            // More here: https://identity.foundation/trustdidweb/v0.3/#generate-scid
            //            To generate the required [[ref: SCID]] for a did:tdw DID, the DID Controller MUST execute the following function:
            //            base58btc(multihash(JCS(preliminary log entry with placeholders), <hash algorithm>))
            let encoded = base58_encode(multihash_digest)
                .with_alphabet(Alphabet58::BITCOIN) // it is the default alphabet, but still (to ensure spec conformity)
                .into_string();
            if encoded.len() < utils::SCID_MIN_LENGTH {
                panic!(
                    "Invalid scid length. A minimum of {} is required",
                    utils::SCID_MIN_LENGTH
                );
            }
            encoded
        }
        Err(_) => panic!("Invalid json couldn't canonicalize"),
    }
}
