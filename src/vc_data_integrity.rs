// SPDX-License-Identifier: MIT

use crate::ed25519::*;
//use sha2::Digest;
use crate::jcs_sha256_hasher::JcsSha256Hasher;
use chrono::{serde::ts_seconds, DateTime, SecondsFormat, Utc};
use hex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value::String as JsonString};

#[derive(Clone)]
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
        let string_representation = match self {
            CryptoSuiteType::Bbs2023 => String::from("bbs-2023"),
            CryptoSuiteType::EcdsaRdfc2019 => String::from("ecdsa-rdfc-2019"),
            CryptoSuiteType::EcdsaJcs2019 => String::from("ecdsa-jcs-2019"),
            CryptoSuiteType::EcdsaSd2019 => String::from("ecdsa-sd-2019"),
            CryptoSuiteType::EddsaRdfc2022 => String::from("eddsa-rdfc-2022"),
            CryptoSuiteType::EddsaJcs2022 => String::from("eddsa-jcs-2022"),
        };
        write!(f, "{}", string_representation)
    }
}

#[derive(Clone)]
pub struct CryptoSuiteOptions {
    pub proof_type: String,
    pub crypto_suite: CryptoSuiteType,
    pub verification_method: String,
    pub proof_purpose: String,
    pub challenge: Option<String>,
}

impl CryptoSuiteOptions {
    pub fn new(
        crypto_suite: CryptoSuiteType,
        verification_method: String,
        challenge: String,
    ) -> CryptoSuiteOptions {
        CryptoSuiteOptions {
            proof_type: "DataIntegrityProof".to_string(),
            crypto_suite,
            verification_method,
            proof_purpose: "authentication".to_string(),
            challenge: Some(challenge),
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
    #[serde(with = "ts_seconds")]
    pub created: DateTime<Utc>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    pub challenge: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}
impl DataIntegrityProof {
    /// The non-empty parsing constructor featuring validation in terms of supported type/proofPurpose/cryptosuite
    pub fn from(json: String) -> Self {
        let value = match serde_json::from_str(&json) {
            Ok(serde_json::Value::Array(entry)) => {
                if entry.is_empty() {
                    panic!("Empty proof array detected")
                }
                entry.first().unwrap().clone()
            }
            Err(e) => {
                panic!("Malformed proof array detected: {}", e)
            }
            _ => panic!("Malformed proof format, expected array"),
        };
        DataIntegrityProof {
            proof_type: match value["type"] {
                JsonString(ref s) => {
                    if s != "DataIntegrityProof" {
                        panic!("Unsupported proof's type. Expected 'DataIntegrityProof'");
                    }
                    s.to_string()
                }
                _ => panic!("Missing proof's type"),
            },
            crypto_suite: match value["cryptosuite"] {
                JsonString(ref s) => {
                    if s != "eddsa-jcs-2022" {
                        panic!(
                            "Unsupported proof's cryptosuite. Expected '{}'",
                            CryptoSuiteType::EddsaJcs2022
                        );
                    }
                    s.to_string()
                }
                _ => panic!("Missing proof's cryptosuite"),
            },
            created: match value["created"] {
                JsonString(ref s) => DateTime::parse_from_rfc3339(s).unwrap().to_utc(),
                _ => Utc::now(),
            },
            verification_method: match value["verificationMethod"] {
                JsonString(ref s) => {
                    if !s.starts_with("did:key:") {
                        panic!(
                            "Unsupported proof's verificationMethod. Expected prefix 'did:key:'"
                        );
                    }
                    s.to_string()
                }
                _ => panic!("Missing proof's verificationMethod"),
            },
            proof_purpose: match value["proofPurpose"] {
                JsonString(ref s) => {
                    if s != "authentication" {
                        panic!("Unsupported proof's proofPurpose. Expected 'authentication'");
                    }
                    s.to_string()
                }
                _ => panic!("Missing proof's proofPurpose"),
            },
            challenge: match value["challenge"] {
                JsonString(ref s) => s.to_string(),
                _ => panic!("Missing proof's challenge"),
            },
            proof_value: match value["proofValue"] {
                JsonString(ref s) => s.to_string(),
                _ => String::from(""),
            },
        }
    }

    /// Construct a serde_json::Value from this DataIntegrityProof
    pub fn json_value(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self).unwrap();
        value["created"] = serde_json::Value::String(
            self.created
                .to_rfc3339_opts(SecondsFormat::Secs, true)
                .to_string(),
        );
        value
    }

    pub fn extract_update_key(&self) -> String {
        // Option<String> {
        if self.verification_method.starts_with("did:key:") {
            let update_key_split = self.verification_method.split('#').collect::<Vec<&str>>();
            if update_key_split.is_empty() {
                panic!("A proof's verificationMethod must be #-delimited")
            }
            //Some(update_key_split[1].to_string())
            update_key_split[1].to_string()
        } else {
            panic!("Unsupported proof's verificationMethod (only 'did:key' is currently supported): {}", self.verification_method)
            //None
        }
    }
}

/// Output generated by the verifyProof algorithm as defined in the vc-data-integrity algorithm
/// https://www.w3.org/TR/vc-data-integrity/#dfn-verifyproof
/// For eddsa-rdfc-2022 suite relevant is  https://www.w3.org/TR/vc-di-eddsa/#dfn-verification-result
pub struct CryptoSuiteVerificationResult {
    pub verified: bool,
    // if verified is false, Null; otherwise, an unsecured data document (https://www.w3.org/TR/vc-data-integrity/#dfn-unsecured-data-document)
    pub verified_document: String,
    pub errors: Vec<String>,
}

/*
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
    // TODO https://www.w3.org/TR/vc-data-integrity/#add-proof
    // See https://www.w3.org/TR/vc-data-integrity/#verify-proof
    fn verify_proof(&self, proof: &DataIntegrityProof, doc_hash: &str) -> bool;
}

pub struct EddsaCryptosuite {
    pub verifying_key: Option<Ed25519VerifyingKey>,
    pub signing_key: Option<Ed25519SigningKey>,
}

// NOTE Only https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022 is supported
impl VCDataIntegrity for EddsaCryptosuite {
    // See https://www.w3.org/TR/vc-di-eddsa/#verify-proof-eddsa-jcs-2022
    // See https://www.w3.org/TR/vc-di-eddsa/#proof-verification-eddsa-jcs-2022
    fn verify_proof(&self, proof: &DataIntegrityProof, doc_hash: &str) -> bool {
        let proof_value = &proof.proof_value;
        let proof_without_proof_value = json!({
            "type": proof.proof_type,
            "cryptosuite": proof.crypto_suite,
            "created": proof.created,
            "verificationMethod": proof.verification_method,
            "proofPurpose": proof.proof_purpose,
            "challenge": proof.challenge,
        });
        let proof_hash = JcsSha256Hasher::default()
            .encode_hex(&proof_without_proof_value)
            .unwrap(); // should never panic
        let hash_data = proof_hash + doc_hash;
        let signature = Ed25519Signature::from_multibase(proof_value.as_str());
        match self.verifying_key {
            Some(ref verifying_key) => {
                let hash_data_decoded: [u8; 64] = hex::FromHex::from_hex(hash_data).unwrap();
                verifying_key.verifying_key.verify_strict(&hash_data_decoded, &signature.signature).is_err()
            }
            None => panic!("Invalid eddsa cryptosuite. Verifying key is missing but required for proof verification"),
        }
    }
}
