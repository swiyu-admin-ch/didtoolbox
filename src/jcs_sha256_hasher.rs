// SPDX-License-Identifier: MIT

use bs58::{encode as base58_encode, Alphabet as Alphabet58};
use hex;
use hex::ToHex;
//use serde::{Deserialize, Serialize};
// CAUTION Beware that using the "serde_jcs" crate here may cause
//         "not yet implemented: Handle number str (u128/i128)" error
//         in case of numeric json properties, e.g. "witnessThreshold".
use serde_json::error::Error as JsonError;
use serde_json_canonicalizer::to_string as jcs_to_string;
use sha2::{Digest, Sha256};

/// A helper capable of SHA2-256 hashing of canonical JSON structures.
//#[derive(Default, Clone)]
pub struct JcsSha256Hasher {
    hasher: Sha256,
}
impl JcsSha256Hasher {
    /// The default constructor featuring a SHA2-256 hasher instance.
    pub(crate) fn default() -> Self {
        JcsSha256Hasher {
            hasher: Sha256::new(),
        }
    }

    /// Serialize the given data structure as a JCS UTF-8 string and calculate SHA2-256 hash out of it.
    /// The hash encoded as hex strict representation is returned. Lower case letters are used (e.g. f9b4ca)
    ///
    /// # Errors
    ///
    /// Serialization can fail if `T`'s implementation of `Serialize` decides to
    /// fail, or if `T` contains a map with non-string keys.
    pub fn encode_hex(&mut self, json: &serde_json::Value) -> Result<String, JsonError> {
        self.hasher.reset();
        let jcs_string = jcs_to_string(json)?;
        self.hasher.update(jcs_string);
        Ok(self.hasher.clone().finalize().encode_hex())
    }

    /// Implementation of the multihash specification (https://www.w3.org/TR/controller-document/#multihash).
    /// Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
    pub fn encode_multihash(&mut self, s: String) -> &'static [u8] {
        self.hasher.reset();
        self.hasher.update(s);
        let digest = self.hasher.clone().finalize();

        // According to https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog:
        //              Use multihash in the SCID to differentiate the different hash function outputs.
        //              See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#name-base-58-bitcoin-encoding

        // multihash is an implementation of the multihash specification (https://www.w3.org/TR/controller-document/#multihash).
        // Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
        // Multihash Identifier	Multihash Header	Description
        // sha2-256	            0x12	            SHA-2 with 256 bits (32 bytes) of output, as defined by [RFC6234].
        let multihash_header: &[u8] = &[
            0x12u8,             // hash algorithm (sha2-256) identifier
            digest.len() as u8, // hash size (in bytes)
        ];
        let multihash_digest = [multihash_header, digest.as_slice()].concat();
        // The 'static lifetime means the referred-to data needs to be guaranteed to
        // live for the rest of the program's execution.
        multihash_digest.leak() // <-- data will NEVER be freed, a mutable reference to this data is returned
    }

    /// Serialize the given data structure as a JCS UTF-8 string and calculate SHA2-256 multihash out of it.
    /// The multihash encoded in base58btc format is returned
    pub fn base58btc_encode_multihash(
        &mut self,
        json: &serde_json::Value,
    ) -> serde_json::Result<String> {
        let canonical = jcs_to_string(json)?;

        // WORKAROUND (":ff" -> ":") in case of numeric json properties (e.g. witnessThreshold)
        let multihash_sha256 = self.encode_multihash(canonical.replace(":ff", ":"));

        //
        // Since v0.3 (https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
        //            Change base32 encoding with base58btc, as it offers a better expansion rate.
        // More here: https://identity.foundation/trustdidweb/v0.3/#generate-scid
        //            To generate the required [[ref: SCID]] for a did:tdw DID, the DID Controller MUST execute the following function:
        //            base58btc(multihash(JCS(preliminary log entry with placeholders), <hash algorithm>))
        let encoded = base58_encode(multihash_sha256)
            .with_alphabet(Alphabet58::BITCOIN) // it is the default alphabet, but still (to ensure spec conformity)
            .into_string();
        Ok(encoded)
    }
}
