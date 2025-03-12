// SPDX-License-Identifier: MIT

use crate::errors::TrustDidWebError;
use bs58::{decode as base58_decode, encode as base58_encode, Alphabet as Alphabet58};
use std::cmp::PartialEq;

/// See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#appendix-D.1
pub const BASE58BTC_MULTIBASE_IDENTIFIER: &str = "z";

/// See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#appendix-D.1
#[derive(PartialEq, Debug)]
pub enum MultibaseAlgorithm {
    /// Base58 bitcoin
    Base58btc,
}

/// A helper capable of encoding/decoding data in Multibase format according to
/// https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html
pub struct MultibaseEncoderDecoder {
    algorithm: MultibaseAlgorithm,
    alphabet: &'static Alphabet58,
}

impl MultibaseEncoderDecoder {
    /// The default constructor featuring Base58btc algorithm.
    pub(crate) fn default() -> Self {
        MultibaseEncoderDecoder {
            algorithm: MultibaseAlgorithm::Base58btc,
            alphabet: Alphabet58::BITCOIN,
        }
    }

    /// Encode bytes into a new owned string using the alphabet supplied earlier.
    pub fn encode_base58btc(&self, data: &[u8]) -> String {
        // sanity guard
        if self.algorithm != MultibaseAlgorithm::Base58btc {
            panic!("Unsupported multibase algorithm {:?}", self.algorithm);
        }

        let encoded = base58_encode(data)
            .with_alphabet(self.alphabet)
            .into_string();
        // See https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html#name-base-58-bitcoin-encoding
        format!("{}{}", BASE58BTC_MULTIBASE_IDENTIFIER, encoded)
    }

    /// Decode into the given buffer.
    ///
    /// If the buffer is resizeable it will be extended and the new data will be written to the end
    /// of it.
    ///
    /// If the buffer is not resizeable bytes will be written from the beginning and bytes after
    /// the final encoded byte will not be touched.
    pub fn decode_base58_onto(
        &self,
        multibase: &str,
        result: &mut [u8],
    ) -> Result<(), TrustDidWebError> {
        // sanity guard
        if self.algorithm != MultibaseAlgorithm::Base58btc {
            panic!("Unsupported multibase algorithm {:?}", self.algorithm);
        }

        if !multibase.starts_with(BASE58BTC_MULTIBASE_IDENTIFIER) {
            return Err(TrustDidWebError::DeserializationFailed(format!(
                "Invalid multibase algorithm identifier '{:?}'",
                self.algorithm
            )));
        }

        let raw = multibase.chars().skip(1).collect::<String>(); // get rid of the multibase identifier

        // decode into the given buffer
        match base58_decode(raw).with_alphabet(self.alphabet).onto(result) {
            Ok(_) => Ok(()),
            Err(err) => Err(TrustDidWebError::DeserializationFailed(format!("{}", err))),
        }
    }
}
