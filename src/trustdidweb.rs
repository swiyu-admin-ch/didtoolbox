use core::panic;

use chrono::{DateTime, Utc};
use chrono::serde::ts_seconds;
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE , Engine as _};
use base32::{decode as base32_decode, encode as base32_encode, Alphabet};
use serde_jcs::{to_vec as jcs_from_str, to_string as jcs_to_string};
use serde_json::json;
use sha2::{Sha256, Digest};
use hex;
use hex::ToHex;
use regex;
use crate::utils;
use crate::ed25519::*;
use crate::vc_data_integrity::*;
/// Entry in an did log file as shown here
/// https://bcgov.github.io/trustdidweb/#term:did-log-entry
#[derive(Serialize, Deserialize, Debug)]
pub struct DidLogEntry {
    pub entry_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<usize>,
    #[serde(with = "ts_seconds")]
    pub version_time: DateTime<Utc>,
    pub parameters: DidMethodParameters,
    pub did_doc: serde_json::Value,
    pub proof: serde_json::Value,
}

impl DidLogEntry {
    /// Import of existing log entry
    pub fn new(entry_hash: String, version_id: usize, version_time: DateTime<Utc>, parameters: DidMethodParameters, did_doc: serde_json::Value, proof: serde_json::Value) -> Self {
        DidLogEntry {
            entry_hash,
            version_id: Some(version_id),
            version_time,
            parameters,
            did_doc,
            proof,
        }
    }

    /// Creation of new log entry (without known version_id)
    pub fn of(entry_hash: String, parameters: DidMethodParameters, did_doc: serde_json::Value, proof: serde_json::Value) -> Self {
        DidLogEntry {
            entry_hash,
            version_id: Option::None,
            version_time: Utc::now(),
            parameters,
            did_doc,
            proof
        }
    }

    pub fn to_log_entry_line(&self) -> serde_json::Value {
        serde_json::json!([
            self.entry_hash,
            self.version_id,
            self.version_time.to_owned().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            self.parameters,
            self.did_doc,
        ])
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DidMethodParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub scid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cryptosuite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub prerotation: Option<bool>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub moved: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub deactivated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ttl: Option<i64>,
}
impl DidMethodParameters {
    pub fn for_genesis_did_doc(scid: String) -> Self {
        DidMethodParameters {
            method: Option::Some(String::from("tid:tdw:1")),
            scid: Option::Some(scid),
            hash: Option::None,
            cryptosuite: Option::None,
            prerotation: Option::None,
            next_keys: Option::None,
            moved: Option::None,
            deactivated: Option::None,
            ttl: Option::None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DidDocumentState {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub did_log_entries: Vec<DidLogEntry>,
}

impl DidDocumentState {
    pub fn new() -> Self {
        DidDocumentState {
            did_log_entries: Vec::new(),
        }
    }
    pub fn from(did_log: String) -> Self {
        DidDocumentState {
            did_log_entries: did_log.split("\n").map(|line| {
                let entry: Vec<String> = serde_json::from_str(line).unwrap();
                DidLogEntry::new(
                    entry[0].to_string(),
                    entry[1].to_string().parse::<usize>().unwrap(),
                    DateTime::parse_from_str(entry[2].as_str(), "%Y-%m-%dT%H:%M:%S%.3fZ").unwrap().to_utc(),
                    serde_json::from_str(&entry[3]).unwrap(),
                    serde_json::from_str(&entry[4]).unwrap(),
                    serde_json::from_str(&entry[5]).unwrap()
                )
            }).collect::<Vec<DidLogEntry>>()
        }
    }

    pub fn update(&mut self, log_entry: DidLogEntry) {
        let mut index: usize = 1;
        if self.did_log_entries.len() != 0 {
            let last_entry = self.did_log_entries.last().unwrap();
            index = last_entry.version_id.unwrap() + 1;
        }
        let doc = DidLogEntry{
            version_id: Some(index),
            ..log_entry
        };
        self.did_log_entries.push(doc);
    }   
}

impl std::fmt::Display for DidDocumentState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut log = String::new();
        for entry in &self.did_log_entries {
            let serialized = json!([
                entry.entry_hash,
                entry.version_id,
                entry.version_time.to_owned().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                entry.parameters,
                {
                    "value": entry.did_doc
                },
                entry.proof
            ]);
            log.push_str(serde_json::to_string(&serialized).unwrap().as_str());
            log.push_str("\n");
        }
        write!(f, "{}", log)
    }
}

/// Basic user facing did method operations to handle a did
pub trait DidMethodOperation {
    fn create(&self, domain: String, key_pair: &Ed25519KeyPair) -> String;
    fn read(&self, did_tdw: String) -> String;
    fn update(&self, did_tdw: String, did_doc: String) -> String;
    fn deactivate(&self, did_tdw: String) -> String;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationMethod {
    pub id: String,
    pub controller: String,
    #[serde(rename = "type")]
    pub verification_type: String,
    pub public_key_multibase: String,
}

impl VerificationMethod {
    pub fn new(id: String, controller: String, public_key_multibase: String) -> Self {
        VerificationMethod {
            id: id,
            controller: controller,
            verification_type: String::from("Multikey"),
            public_key_multibase: public_key_multibase,
        }
    }
}
impl Clone for VerificationMethod {
    fn clone(&self) -> Self {
        VerificationMethod {
            id: self.id.clone(),
            controller: self.controller.clone(),
            verification_type: self.verification_type.clone(),
            public_key_multibase: self.public_key_multibase.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DidDoc {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<VerificationMethod>,
    #[serde(
        rename = "capabilityInvocation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_invocation: Vec<VerificationMethod>,
    #[serde(
        rename = "capabilityDelegation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_delegation: Vec<VerificationMethod>,
    #[serde(
        rename = "assertionMethod",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub assertion_method: Vec<VerificationMethod>,
}

pub struct EddsaCryptosuite {
    pub key_pair: Ed25519KeyPair,
}

impl VCDataIntegrity for EddsaCryptosuite {
    fn add_proof(&self, unsecured_document: &serde_json::Value, options: &CryptoSuiteOptions) -> serde_json::Value {
        if !matches!(options.crypto_suite, CryptoSuiteType::EddsaJcs2022) {
            panic!("Invalid crypto suite. Only eddsa-jcs-2022 is supported");
        }
        if options.proof_type != "DataIntegrityProof" {
            panic!("Invalid proof type. Only DataIntegrityProof is supported");
        }

        // 3.1.3 Transformation of doc and options
        let json_doc = unsecured_document.to_string();
        let jcs_doc = jcs_from_str(&json_doc).unwrap();
        let utf8_doc: String = String::from_utf8(jcs_doc).unwrap();

        let mut proof = json!({
            "type": options.proof_type,
            "cryptoSuite": options.crypto_suite.to_string(),
            "created": Utc::now().to_string(),
            "verificationMethod": options.verification_method,
            "proofPurpose": options.proof_purpose,
            "challenge": options.challenge.as_ref().unwrap(),
        });
        let json_proof = proof.to_string();
        let jcs_proof = jcs_from_str(&json_proof).unwrap();
        let utf8_proof: String = String::from_utf8(jcs_proof).unwrap();

        // 3.1.4 Hashing
        let mut doc_hasher = Sha256::new();
        doc_hasher.update(utf8_doc);
        let doc_hash: String = doc_hasher.finalize().encode_hex();
        let mut proof_hasher = Sha256::new();
        proof_hasher.update(utf8_proof);
        let proof_hash: String = proof_hasher.finalize().encode_hex();
        let hash_data = proof_hash + &doc_hash;

        // 3.1.6 Proof serialization
        let proof_signature = self.key_pair.sign(hash_data);
        let proof_signature_multibase = proof_signature.to_multibase();
        proof["proofValue"] = json!(proof_signature_multibase);
        todo!("Proof value is null when converting to string!!");

        // Create secured document
        match serde_json::from_str::<serde_json::Value>(&json_doc) {
            Ok(mut secured_document) => {
                secured_document["proofValue"] = proof;
                return secured_document;
            },
            Err(_) => panic!("Invalid json document"),
        }

    }

    fn verify_proof(&self, secured_document: &serde_json::Value, presentation_header: String, public_key: &Ed25519VerifyingKey) -> CryptoSuiteVerificationResult {
        todo!()
    }
}   
pub struct TrustDidWebProcessor {
}

impl DidMethodOperation for TrustDidWebProcessor {

    fn create(&self, domain: String, key_pair: &Ed25519KeyPair) -> String {
        // Create verification method for subject with placeholder
        let did_tdw = format!("did:tdw:{}:{}", domain, utils::SCID_PLACEHOLDER);
        let verification_method = self.create_verification_method_from_verifying_key(&did_tdw, &key_pair.verifying_key);

        // Create initial did doc with placeholder
        let did_doc = DidDoc {
            context: vec![utils::DID_CONTEXT.to_string(), utils::MKEY_CONTEXT.to_string()],
            id: did_tdw.clone(),
            verification_method: vec![verification_method.clone()],
            authentication: vec![verification_method.clone()],
            capability_invocation: vec![],
            capability_delegation: vec![],
            assertion_method: vec![],
        };

        // Generate SCID and replace placeholder in did doc
        let scid = self.generate_scid(&did_doc);
        let did_doc_serialize = serde_json::to_string(&did_doc).unwrap();
        let did_doc_with_scid = str::replace(&did_doc_serialize, utils::SCID_PLACEHOLDER, &scid);
        // let did_doc_with_scid = re.replace_all(&did_doc_serialize, &scid).to_string();
        let genesis_did_doc = serde_json::from_str(&did_doc_with_scid).unwrap();

        // Generate data integrity proof for new entry
        let suite_options = CryptoSuiteOptions::new(
            CryptoSuiteType::EddsaJcs2022,
            did_doc.id.clone(),
            scid.clone()
        );
        let eddsa_suite = EddsaCryptosuite {
            key_pair: Ed25519KeyPair::from(key_pair.get_signing_key().to_multibase().as_str()),
        };
        let unsecured_document = serde_json::from_str(&did_doc_serialize.as_str()).unwrap();
        let secured_document = eddsa_suite.add_proof(&unsecured_document, &suite_options);

        let log_entry = DidLogEntry::of(
            scid.to_owned(),
            DidMethodParameters::for_genesis_did_doc(scid.to_owned()),
            genesis_did_doc,
            secured_document["proof"].to_owned()
        );

        // Initialize did log with genesis did doc
        let mut did_log: DidDocumentState = DidDocumentState::new();
        did_log.update(log_entry);
        did_log.to_string()
    }

    fn read(&self, did_tdw: String) -> String {
        todo!("Read did string")
    }

    fn update(&self, did_tdw: String, did_doc: String) -> String {
        todo!("Update did string")
    }

    fn deactivate(&self, did_tdw: String) -> String {
        todo!("Deactivate did string")
    }
}

impl TrustDidWebProcessor {

    pub fn new() -> Self {
        TrustDidWebProcessor {}
    }

    /// Create verification method object from public key
    fn create_verification_method_from_verifying_key(&self, domain: &String, verifying_key: &Ed25519VerifyingKey) -> VerificationMethod {
        let key_definition = json!({
            "type":"Multikey",
            "publicKeyMultibase": verifying_key.to_multibase(),
        });
        // let jcs_public_key = String::from_utf8(jcs_from_str(&keydef).unwrap()).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(jcs_from_str(&key_definition).unwrap());
        let hash: String = hasher.finalize().encode_hex();
        let base64_public_key = URL_SAFE.encode(hash.as_bytes());

        let kid = format!("#{}", base64_public_key.trim_end_matches("="));
        VerificationMethod {
            id: format!("{}{}", domain, kid),
            controller: domain.to_string(),
            verification_type: String::from("Multikey"),
            public_key_multibase: verifying_key.to_multibase(),
        }
    }

    /// Generates an SCID (self certifying identifier) based on the initial DiDoC.
    /// This function is used as well in the initial generation as in the verification
    /// process of the DidDoc log file
    fn generate_scid(&self, did_doc: &DidDoc) -> String {
        if !did_doc.id.contains(utils::SCID_PLACEHOLDER) {
            panic!("Invalid did:tdw document. SCID placeholder not found");
        }
        let json = serde_json::to_string(did_doc).unwrap();
        match jcs_to_string(&json) {
            Ok(jcs) => {
                let mut hasher = Sha256::new();
                hasher.update(jcs.as_bytes());
                let hash: String = hasher.finalize().encode_hex();
                let b32_encoded = base32_encode(Alphabet::Rfc4648Lower { padding: true }, hash.as_bytes());
                if b32_encoded.len() < utils::SCID_MIN_LENGTH {
                    panic!("Invalid scid length. A minimum of {} is required", utils::SCID_MIN_LENGTH);
                }
                return b32_encoded;
            },
            Err(_) => panic!("Invalid json couldn't canonicalize"),
        }
    }
}