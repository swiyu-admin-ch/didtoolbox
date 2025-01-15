// SPDX-License-Identifier: MIT

use crate::ed25519::*;
use crate::jcs_sha256_hasher::JcsSha256Hasher;
use chrono::{serde::ts_seconds, DateTime, SecondsFormat, Utc};
use hex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value::String as JsonString};
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
    pub created: Option<DateTime<Utc>>,
    pub verification_method: String,
    pub proof_purpose: String,
    pub context: Option<Vec<String>>,
    pub challenge: Option<String>,
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
        challenge: Option<String>,
    ) -> Self {
        let mut options = Self::default();
        if let Some(crypto_suite) = crypto_suite {
            options.crypto_suite = crypto_suite;
        }
        options.created = created; // fallback to current datetime
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
            created: None, // fallback to current datetime
            verification_method: String::from(""),
            proof_purpose: "authentication".to_string(),
            context: None,
            challenge: None,
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
                    if s != CryptoSuiteType::EddsaJcs2022.to_string().deref() {
                        panic!(
                            "Unsupported proof's cryptosuite. Expected '{}'",
                            CryptoSuiteType::EddsaJcs2022
                        );
                    }
                    s.to_string()
                }
                _ => panic!("Missing proof's cryptosuite"),
            },
            crypto_suite_type: Some(CryptoSuiteType::EddsaJcs2022), // the only currently supported cryptosuite
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
                    if s != "authentication" && s != "assertionMethod" {
                        panic!("Unsupported proof's proofPurpose. Expected 'authentication'");
                    }
                    s.to_string()
                }
                _ => panic!("Missing proof's proofPurpose"),
            },
            challenge: match value["challenge"] {
                JsonString(ref s) => s.to_string(),
                _ => String::from(""), // panic!("Missing proof's challenge"),
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
    ) -> serde_json::Value;
    // See https://www.w3.org/TR/vc-data-integrity/#verify-proof
    fn verify_proof(&self, proof: &DataIntegrityProof, doc_hash: &str) -> bool;
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
    ) -> serde_json::Value {
        if !matches!(options.crypto_suite, CryptoSuiteType::EddsaJcs2022) {
            panic!(
                "Unsupported proof's cryptosuite. Only '{}' is supported",
                CryptoSuiteType::EddsaJcs2022
            );
        }
        if options.proof_type != "DataIntegrityProof" {
            panic!("Unsupported proof's type. Only 'DataIntegrityProof' is supported");
        }

        let created = match options.created {
            None => Utc::now()
                .to_rfc3339_opts(SecondsFormat::Secs, true)
                .to_string(),
            Some(v) => v.to_rfc3339_opts(SecondsFormat::Secs, true).to_string(),
        };

        // See https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
        let mut proof_without_proof_value = json!({
            "type": options.proof_type,
            "cryptosuite": options.crypto_suite.to_string(),
            "created": created,
            "verificationMethod": options.verification_method,
            "proofPurpose": options.proof_purpose,
        });
        if let Some(ctx) = &options.context {
            proof_without_proof_value["@context"] = json!(ctx);
        }
        if let Some(challenge) = &options.challenge {
            proof_without_proof_value["challenge"] = json!(challenge);
        }

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
        let proof_hash = JcsSha256Hasher::default()
            .encode_hex(&proof_without_proof_value)
            .unwrap(); // should never panic
        let doc_hash = JcsSha256Hasher::default()
            .encode_hex(unsecured_document)
            .unwrap();
        let hash_data = proof_hash + &doc_hash; // CAUTION is actually hex-encoded at this point

        let signature = match &self.signing_key {
            Some(signing_key) => signing_key.sign_bytes(hex::decode(hash_data).unwrap().deref()),
            None => panic!(
                "Invalid eddsa cryptosuite. Signing key is missing but required for proof creation"
            ),
        };
        //let signature_hex = hex::encode(signature.signature.to_bytes()); // checkpoint

        proof_without_proof_value["proofValue"] = JsonString(signature.to_multibase()); // finally, it's got one!
        let mut secured_document = unsecured_document.clone();
        secured_document["proof"] = json!([proof_without_proof_value]);
        secured_document
    }

    // See https://www.w3.org/TR/vc-di-eddsa/#proof-verification-eddsa-jcs-2022
    // See https://www.w3.org/TR/vc-di-eddsa/#verify-proof-eddsa-jcs-2022

    fn verify_proof(&self, proof: &DataIntegrityProof, doc_hash: &str) -> bool {
        let proof_value = &proof.proof_value;
        // CAUTION Beware that only serde_json::json macro is able to serialize "created" field properly!
        //         (thanks to #[serde(with = "ts_seconds")])
        let proof_without_proof_value = json!({
            "type": proof.proof_type,
            "cryptosuite": proof.crypto_suite,
            "created": proof.created,
            "verificationMethod": proof.verification_method,
            "proofPurpose": proof.proof_purpose,
            "challenge": proof.challenge,
        });
        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
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
