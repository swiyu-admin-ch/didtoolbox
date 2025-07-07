// SPDX-License-Identifier: MIT

use crate::ed25519::*;
use crate::errors::TrustDidWebError;
use crate::jcs_sha256_hasher::JcsSha256Hasher;
use chrono::{serde::ts_seconds, DateTime, SecondsFormat, Utc};
use hex;
use serde::{Deserialize, Serialize};
use serde_json::{
    json, Value::Array as JsonArray, Value::Null as JsonNull, Value::String as JsonString,
};
use std::ops::Deref;

#[derive(Clone, Debug)]
pub enum CryptoSuiteType {
    Bbs2023,
    EcdsaRdfc2019,
    EcdsaJcs2019,
    EcdsaSd2019,
    EddsaRdfc2022,
    EddsaJcs2022,
}

impl std::fmt::Display for CryptoSuiteType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CryptoSuiteType::Bbs2023 => write!(f, "bbs-2023"),
            CryptoSuiteType::EcdsaRdfc2019 => write!(f, "ecdsa-rdfc-2019"),
            CryptoSuiteType::EcdsaJcs2019 => write!(f, "ecdsa-jcs-2019"),
            CryptoSuiteType::EcdsaSd2019 => write!(f, "ecdsa-sd-2019"),
            CryptoSuiteType::EddsaRdfc2022 => write!(f, "eddsa-rdfc-2022"),
            CryptoSuiteType::EddsaJcs2022 => write!(f, "eddsa-jcs-2022"),
        }
    }
}

/// As specified by https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
#[derive(Clone)]
pub struct CryptoSuiteProofOptions {
    pub proof_type: String,
    pub crypto_suite: CryptoSuiteType,
    pub created: DateTime<Utc>,
    pub verification_method: String,
    pub proof_purpose: String,
    pub context: Option<Vec<String>>,
    pub challenge: String,
}

impl CryptoSuiteProofOptions {
    /// The only (super-potent) non-empty constructor.
    ///
    /// As nearly all arguments are optional, see [`Self::default()`] constructor for default values.
    pub fn new(
        crypto_suite: Option<CryptoSuiteType>,
        created: Option<DateTime<Utc>>,
        verification_method: String,
        proof_purpose: Option<String>,
        context: Option<Vec<String>>,
        challenge: String,
    ) -> Self {
        let mut options = Self::default();
        if let Some(crypto_suite) = crypto_suite {
            options.crypto_suite = crypto_suite;
        }
        if let Some(created) = created {
            options.created = created; // otherwise take current time
        }

        options.verification_method = verification_method;
        if let Some(purpose) = proof_purpose {
            options.proof_purpose = purpose;
        }

        options.context = context;
        options.challenge = challenge;
        options
    }

    /// The default constructor aligned with https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022, hence:
    ///
    /// - proof_type: "DataIntegrityProof"
    /// - crypto_suite: "eddsa-jcs-2022"
    /// - created: \<current datetime\>
    /// - proof_purpose: "authentication"
    pub(crate) fn default() -> Self {
        CryptoSuiteProofOptions {
            proof_type: "DataIntegrityProof".to_string(),
            crypto_suite: CryptoSuiteType::EddsaJcs2022,
            created: Utc::now(), // fallback to current datetime
            verification_method: String::from(""),
            proof_purpose: "authentication".to_string(),
            context: None,
            challenge: String::from(""),
        }
    }
}

// See https://www.w3.org/TR/vc-data-integrity/#dataintegrityproof
// For EdDSA Cryptosuites v1.0 suites, see https://www.w3.org/TR/vc-di-eddsa/#dataintegrityproof
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(rename = "cryptosuite")]
    pub crypto_suite: String,
    #[serde(skip)]
    pub crypto_suite_type: Option<CryptoSuiteType>,
    #[serde(with = "ts_seconds")]
    // with = "ts_seconds" requires (in Cargo.toml):
    // chrono = { version = "0.4.39", features = ["serde"] }
    pub created: DateTime<Utc>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    pub context: Option<Vec<String>>,
    pub challenge: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}
impl DataIntegrityProof {
    /// The non-empty parsing constructor featuring validation in terms of supported type/proofPurpose/cryptosuite
    pub fn from(json: String) -> Result<Self, TrustDidWebError> {
        let value = match serde_json::from_str(&json) {
            Ok(JsonArray(entry)) => {
                if entry.len() > 1 {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "A single proof is currently supported.".to_string(),
                    ));
                }

                match entry.first() {
                    Some(first) => first.clone(),
                    None => {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(
                            "Empty proof array detected.".to_string(),
                        ))
                    }
                }
            }
            Err(err) => {
                return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                    "Malformed proof format, expected single-element JSON array: {err}"
                )))
            }
            _ => {
                return Err(TrustDidWebError::InvalidDataIntegrityProof(
                    "Malformed proof format, expected single-element JSON array".to_string(),
                ))
            }
        };
        Ok(DataIntegrityProof {
            proof_type: match value["type"] {
                JsonString(ref s) => {
                    if s != "DataIntegrityProof" {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(
                            "Unsupported proof's type. Expected 'DataIntegrityProof'".to_string(),
                        ));
                    }
                    s.to_string()
                }
                _ => {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "Missing proof's type".to_string(),
                    ))
                }
            },
            crypto_suite: match value["cryptosuite"] {
                JsonString(ref s) => {
                    if s != CryptoSuiteType::EddsaJcs2022.to_string().deref() {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                            "Unsupported proof's cryptosuite. Expected '{}'",
                            CryptoSuiteType::EddsaJcs2022
                        )));
                    }
                    s.to_string()
                }
                _ => {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "Missing proof's cryptosuite".to_string(),
                    ))
                }
            },
            crypto_suite_type: Some(CryptoSuiteType::EddsaJcs2022), // the only currently supported cryptosuite
            created: match value["created"] {
                JsonString(ref s) => match DateTime::parse_from_rfc3339(s) {
                    Ok(date) => date.to_utc(),
                    Err(err) => return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        format!("Invalid proof's creation datetime format: {err}"),
                    ))
                },
                _ =>  return Err(TrustDidWebError::InvalidDataIntegrityProof(
                    "Missing proof's creation datetime.".to_string(),
                )),
            },
            verification_method: match value["verificationMethod"] {
                JsonString(ref s) => {
                    if !s.starts_with("did:key:") {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(
                            "Unsupported proof's verificationMethod. Expected prefix 'did:key:'"
                                .to_string(),
                        ));
                    }
                    s.to_string()
                }
                _ => {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "Missing proof's verificationMethod".to_string(),
                    ))
                }
            },
            proof_purpose: match value["proofPurpose"] {
                JsonString(ref s) => {
                    if s != "authentication" && s != "assertionMethod" {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(
                            "Unsupported proof's proofPurpose. Expected 'authentication'"
                                .to_string(),
                        ));
                    }
                    s.to_string()
                }
                _ => {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "Missing proof's proofPurpose".to_string(),
                    ))
                }
            },
            context: match value["@context"].to_owned() {
                JsonArray(arr) => {
                    Some(
                        arr.into_iter()
                            .try_fold(Vec::new(), |mut acc, val| match val {
                                JsonString(s) => {
                                    acc.push(s);
                                    Ok(acc)
                                }
                                _ => Err(TrustDidWebError::InvalidDataIntegrityProof(
                                    "Invalid type of 'context' entry, expected a string."
                                        .to_string(),
                                )),
                            })?,
                    )
                }
                JsonNull => None,
                _ => return Err(TrustDidWebError::InvalidDataIntegrityProof(
                    "Invalid format of 'context' entry, expected array of strings.".to_string(),
                )),
            },
            challenge: match value["challenge"] {
                JsonString(ref s) => s.to_string(),
                JsonNull => return Err(TrustDidWebError::InvalidDataIntegrityProof(
                    "Missing proof's challenge parameter. Expected a challenge of type string.".to_string(),
                )),
                _ => return Err(TrustDidWebError::InvalidDataIntegrityProof(
                    "Wrong format of proof's challenge parameter. Expected a challenge of type string.".to_string(),
                ))
            },
            proof_value: match value["proofValue"] {
                JsonString(ref s) => s.to_string(),
                JsonNull => return Err(TrustDidWebError::InvalidDataIntegrityProof(
                    "Missing proofValue parameter. Expected a proofValue of type string.".to_string(),
                )),
                _ => return Err(TrustDidWebError::InvalidDataIntegrityProof(
                    "Wrong format of proofValue parameter. Expected a proofValue of type string.".to_string(),
                ))
            },
        })
    }

    /// Construct a serde_json::Value from this DataIntegrityProof
    pub fn json_value(&self) -> Result<serde_json::Value, TrustDidWebError> {
        let mut value = match serde_json::to_value(self) {
            Ok(v) => v,
            Err(err) => {
                return Err(TrustDidWebError::SerializationFailed(format!(
                    "Could not serialize proof: {err}"
                )))
            }
        };

        value["created"] = serde_json::Value::String(
            self.created
                .to_rfc3339_opts(SecondsFormat::Secs, true)
                .to_string(),
        );
        Ok(value)
    }

    /// Delivers first available update key
    pub fn extract_update_key(&self) -> Result<String, TrustDidWebError> {
        if self.verification_method.starts_with("did:key:") {
            let hash_separated = self.verification_method.to_owned().replace("did:key:", "");
            let update_key_split = hash_separated.split('#').collect::<Vec<&str>>();
            if update_key_split.is_empty() {
                return Err(TrustDidWebError::InvalidDataIntegrityProof(
                    "A proof's verificationMethod must be #-delimited".to_string(),
                ));
            }
            Ok(update_key_split[0].to_string())
        } else {
            Err(TrustDidWebError::InvalidDataIntegrityProof(
                format!("Unsupported proof's verificationMethod (only 'did:key' is currently supported): {}", self.verification_method)
            ))
        }
    }
}

/*
/// Output generated by the verifyProof algorithm as defined in the vc-data-integrity algorithm
/// https://www.w3.org/TR/vc-data-integrity/#dfn-verifyproof
/// For eddsa-rdfc-2022 suite relevant is  https://www.w3.org/TR/vc-di-eddsa/#dfn-verification-result
pub struct CryptoSuiteVerificationResult {
    pub verified: bool,
    // if verified is false, Null; otherwise, an unsecured data document (https://www.w3.org/TR/vc-data-integrity/#dfn-unsecured-data-document)
    pub verified_document: String,
    pub errors: Vec<String>,
}

// See https://www.w3.org/TR/vc-data-integrity/#cryptographic-suites
pub trait CryptoSuite {
    // See https://www.w3.org/TR/vc-data-integrity/#dfn-createproof
    fn create_proof(
        &self,
        unsecured_data_document: &serde_json::Value,
        proof_options: &CryptoSuiteOptions,
    ) -> String;
    // See https://www.w3.org/TR/vc-data-integrity/#dfn-verifyproof
    //fn create_verification(&self, secured_document: &str, presentation_header: String) -> CryptoSuiteVerificationResult;
}
 */

/// Is main entry point for proof generation and validation of a given verifiable credential
/// Function in this class are based on algorithm section in the vc-data-integrity spec
/// https://www.w3.org/TR/vc-data-integrity/#algorithms
pub trait VCDataIntegrity {
    // See https://www.w3.org/TR/vc-data-integrity/#add-proof
    fn add_proof(
        &self,
        unsecured_document: &serde_json::Value,
        options: &CryptoSuiteProofOptions,
    ) -> Result<serde_json::Value, TrustDidWebError>;
    // See https://www.w3.org/TR/vc-data-integrity/#verify-proof
    fn verify_proof(
        &self,
        proof: &DataIntegrityProof,
        doc_hash: &str,
    ) -> Result<(), TrustDidWebError>;
}

pub struct EddsaJcs2022Cryptosuite {
    pub verifying_key: Option<Ed25519VerifyingKey>,
    pub signing_key: Option<Ed25519SigningKey>,
}

// NOTE Only https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022 is currently supported
impl VCDataIntegrity for EddsaJcs2022Cryptosuite {
    // See https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022
    fn add_proof(
        &self,
        unsecured_document: &serde_json::Value,
        options: &CryptoSuiteProofOptions,
    ) -> Result<serde_json::Value, TrustDidWebError> {
        // According to https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022:
        // If proofConfig.type is not set to DataIntegrityProof or proofConfig.cryptosuite is not set to eddsa-jcs-2022,
        // an error MUST be raised that SHOULD convey an error type of PROOF_GENERATION_ERROR.
        if !matches!(options.crypto_suite, CryptoSuiteType::EddsaJcs2022) {
            return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                "Unsupported proof's cryptosuite. Only '{}' is supported",
                CryptoSuiteType::EddsaJcs2022
            )));
        }
        if options.proof_type != "DataIntegrityProof" {
            return Err(TrustDidWebError::InvalidDataIntegrityProof(
                "Unsupported proof's type. Only 'DataIntegrityProof' is supported".to_string(),
            ));
        }

        let created = options
            .created
            .to_rfc3339_opts(SecondsFormat::Secs, true)
            .to_string();

        // See https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
        let mut proof_without_proof_value = json!({
            "type": options.proof_type,
            "cryptosuite": options.crypto_suite.to_string(),
            "created": created,
            "verificationMethod": options.verification_method,
            "proofPurpose": options.proof_purpose,
            "challenge": options.challenge,
        });

        if let Some(ctx) = &options.context {
            proof_without_proof_value["@context"] = json!(ctx);
        }

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
        let proof_hash = match JcsSha256Hasher::default().encode_hex(&proof_without_proof_value) {
            Ok(proof_hash) => proof_hash,
            Err(err) => {
                return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                    "Could not serialize proof: {err}"
                )))
            }
        };
        let doc_hash = match JcsSha256Hasher::default().encode_hex(unsecured_document) {
            Ok(doc_hash) => doc_hash,
            Err(err) => {
                return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                    "Could not serialize document for hash generation: {err}"
                )))
            }
        };

        let hash_data = proof_hash + &doc_hash; // CAUTION is actually hex-encoded at this point
        let decoded_hex_data = match hex::decode(hash_data) {
            Ok(hex_data) => hex_data,
            Err(err) => {
                return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                    "Unable to decode created hash: {err}"
                )))
            }
        };

        let signature = match &self.signing_key {
            Some(signing_key) => signing_key.sign_bytes(decoded_hex_data.deref()),
            None => return Err(TrustDidWebError::InvalidDataIntegrityProof(
                "Invalid eddsa cryptosuite. Signing key is missing but required for proof creation"
                    .to_string(),
            )),
        };
        //let signature_hex = hex::encode(signature.signature.to_bytes()); // checkpoint

        let proof_value = signature.to_multibase();
        proof_without_proof_value["proofValue"] = JsonString(proof_value);
        let mut secured_document = unsecured_document.clone();
        secured_document["proof"] = json!([proof_without_proof_value]);
        Ok(secured_document)
    }

    // See https://www.w3.org/TR/vc-di-eddsa/#proof-verification-eddsa-jcs-2022
    // See https://www.w3.org/TR/vc-di-eddsa/#verify-proof-eddsa-jcs-2022

    fn verify_proof(
        &self,
        proof: &DataIntegrityProof,
        doc_hash: &str,
    ) -> Result<(), TrustDidWebError> {
        let proof_value = &proof.proof_value;

        let created = proof
            .created
            .to_rfc3339_opts(SecondsFormat::Secs, true)
            .to_string();

        // CAUTION Beware that only serde_json::json macro is able to serialize proof.created field properly (if used directly)!
        //         (thanks to #[serde(with = "ts_seconds")])
        let mut proof_without_proof_value = json!({
            "type": proof.proof_type,
            "cryptosuite": proof.crypto_suite,
            // The proof.created is not used directly here, due to more error-prone conversion that requires #[serde(with = "ts_seconds")] attribute
            "created": created,
            "verificationMethod": proof.verification_method,
            "proofPurpose": proof.proof_purpose,
            "challenge": proof.challenge, // EIDSYS-429
        });
        if let Some(ctx) = &proof.context {
            proof_without_proof_value["@context"] = json!(ctx);
        }

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
        let proof_hash = match JcsSha256Hasher::default().encode_hex(&proof_without_proof_value) {
            Ok(proof_hash) => proof_hash,
            Err(err) => {
                return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                    "Could not serialize proof: {err}"
                )))
            }
        };
        let hash_data = proof_hash + doc_hash;
        let signature = Ed25519Signature::from_multibase(proof_value.as_str())?;
        match self.verifying_key {
            Some(ref verifying_key) => {
                let hash_data_decoded: [u8; 64] = match hex::FromHex::from_hex(hash_data) {
                    Ok(decoded_hash) => decoded_hash,
                    Err(_) => return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "Cannot decode hash value from hex.".to_string()
                    ))
                };
                // Strictly verify a signature on a message with this keypair's public key.
                // It may respond with: "signature error: Verification equation was not satisfied"
                verifying_key.verifying_key.verify_strict(&hash_data_decoded, &signature.signature)
                    .map_err(|err| TrustDidWebError::InvalidDataIntegrityProof(format!("{err}")))
            }
            None => Err(TrustDidWebError::InvalidDataIntegrityProof(
                "Invalid eddsa cryptosuite. Verifying key is missing but required for proof verification".to_string()
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::errors::TrustDidWebErrorKind;
    use crate::test::assert_trust_did_web_error;
    use crate::vc_data_integrity::DataIntegrityProof;
    use rstest::rstest;

    #[rstest]
    // emtpy proof
    #[case("[]", "Empty proof array detected")]
    // two proofs
    #[case("[\"proof1\", \"proof2\"]", "A single proof is currently supported")]
    // invalid json
    #[case(
        "[{\"key:}]",
        "Malformed proof format, expected single-element JSON array"
    )]
    // invalid type
    #[case(
        "[{\"type\":\"invalidType\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]",
        "Unsupported proof's type"
    )]
    // unsupported cryptosuite
    #[case(
        "[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"unsupportedCrypto\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]",
        "Unsupported proof's cryptosuite"
    )]
    // invalid created date
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"invalidDate\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]",
        "Invalid proof's creation datetime format"
    )]
    // invalid verification method
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"invalidMethod\", \"proofPurpose\":\"authentication\"}]",
        "Unsupported proof's verificationMethod"
    )]
    // invalid proof purpose
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"invalidPurpose\"}]",
        "Unsupported proof's proofPurpose"
    )]
    // invalid @context
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"@context\":\"invalidContext\"}]",
        "Invalid format of 'context' entry"
    )]
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"@context\":[\"validContext\", true, 3]}]",
        "Invalid type of 'context' entry"
    )]
    // invalid proof challenge
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]",
        "Missing proof's challenge parameter."
    )]
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"challenge\":[false, 2]}]",
        "Wrong format of proof's challenge parameter"
    )]
    // invalid proof challenge
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"challenge\":\"1-hash\"}]",
        "Missing proofValue parameter"
    )]
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"challenge\":\"1-hash\", \"proofValue\":5}]",
        "Wrong format of proofValue parameter"
    )]
    fn test_invalid_proof_parsing(
        #[case] input_str: String,
        #[case] error_string: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_trust_did_web_error(
            DataIntegrityProof::from(input_str),
            TrustDidWebErrorKind::InvalidIntegrityProof,
            error_string,
        );

        Ok(())
    }
}