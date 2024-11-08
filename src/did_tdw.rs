// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use chrono::serde::ts_seconds;
use serde::{Deserialize, Serialize};
use base64::{Engine as _};
use serde_jcs::{to_vec as jcs_from_str};
use serde_json::json;
use serde_json::Value::{String as JsonString, Object as JsonObject, Array as JsonArray};
use sha2::{Sha256, Digest};
use ssi::dids::{DIDMethod as SSIDIDMethod,
                DIDBuf as SSIDIDBuf,
                resolution::{
                    Error as SSIResolutionError,
                    DIDMethodResolver as SSIDIDMethodResolver,
                    Options as SSIOptions,
                    Output as SSIOutput,
                },
};
use thiserror::Error;
use hex;
use hex::ToHex;
use regex;
use regex::Regex;
use url_escape;
use crate::utils;
use crate::ed25519::*;
use crate::vc_data_integrity::*;
use crate::didtoolbox::*;

/// Entry in a did log file as shown here
/// https://identity.foundation/trustdidweb/#term:did-log-entry
/// See https://github.com.mcas.ms/decentralized-identity/trustdidweb/blob/63e21b69d84f7d9344f4e6ef4809e7823975c965/spec/specification.md
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DidLogEntry {
    pub entry_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<usize>,
    #[serde(with = "ts_seconds")]
    pub version_time: DateTime<Utc>,
    pub parameters: DidMethodParameters,
    pub did_doc: DidDoc,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
}

impl DidLogEntry {
    /// Import of existing log entry
    pub fn new(entry_hash: String, version_id: usize, version_time: DateTime<Utc>, parameters: DidMethodParameters, did_doc: DidDoc, proof: DataIntegrityProof) -> Self {
        DidLogEntry {
            entry_hash,
            version_id: Some(version_id),
            version_time,
            parameters,
            did_doc,
            proof: Some(proof),
        }
    }

    /// Creation of new log entry (without integrity proof)
    pub fn of_with_proof(entry_hash: String, parameters: DidMethodParameters, did_doc: DidDoc, proof: DataIntegrityProof) -> Self {
        DidLogEntry {
            entry_hash,
            version_id: Option::None,
            version_time: Utc::now(),
            parameters,
            did_doc,
            proof: Some(proof),
        }
    }

    /// Creation of new log entry (without known version_id)
    pub fn of(entry_hash: String, parameters: DidMethodParameters, did_doc: DidDoc) -> Self {
        DidLogEntry {
            entry_hash,
            version_id: Option::None,
            version_time: Utc::now(),
            parameters,
            did_doc,
            proof: None,
        }
    }

    /// Check wether the entry_hash of this log entry is based on the previous entry_hash
    pub fn verify_entry_hash_integrity(&self, previous_entry_hash: &str) {
        let entry_without_proof = DidLogEntry {
            entry_hash: previous_entry_hash.to_string(),
            version_id: self.version_id,
            version_time: self.version_time,
            parameters: self.parameters.clone(),
            did_doc: self.did_doc.clone(),
            proof: None,
        };
        let entry_hash = entry_without_proof.get_hash();
        if entry_hash != self.entry_hash {
            panic!("Invalid did log. Genesis entry has invalid entry hash")
        }
    }

    /// Check wether the integrity proof matches the content of the did document of this log entry
    pub fn verify_data_integrity_proof(&self) {
        // Verify data integrity proof 
        let verifying_key = self.get_data_integrity_verifying_key(); // may panic

        // Check if verifying key is actually a controller and therefore allowed to update the doc => valid key to create the proof
        let controller_keys = self.get_controller_verifying_key();
        if !controller_keys.values().any(|(id, key)| key.to_multibase() == verifying_key.to_multibase()) {
            panic!("Invalid key pair. The provided key pair is not the one referenced in the did doc")
        }

        let eddsa_suite = EddsaCryptosuite {
            verifying_key: Some(verifying_key),
            signing_key: None,
        };
        let mut did_doc_value = serde_json::to_value(&self.did_doc).unwrap();
        did_doc_value["proof"] = self.proof.as_ref().unwrap().to_value();
        if !eddsa_suite.verify_proof(&did_doc_value) {
            panic!("Invalid did log. Entry of version {} has invalid data integrity proof", self.version_id.unwrap())
        }
    }

    fn get_hash(&self) -> String {
        let json = serde_json::to_string(&self.to_log_entry_line()).unwrap();
        utils::generate_jcs_hash(&json)
    }

    fn get_controller_verifying_key(&self) -> HashMap<String, (String, Ed25519VerifyingKey)> {
        self.did_doc.verification_method.iter()
            .filter(|entry|
                self.did_doc.controller.iter()
                    .any(|controller| entry.id.starts_with(controller) && entry.verification_type == utils::EDDSA_VERIFICATION_KEY_TYPE))
            .map(|entry| (
                entry.id.split("#").collect::<Vec<&str>>().first().unwrap().to_string(),
                (entry.id.clone(), Ed25519VerifyingKey::from_multibase(entry.public_key_multibase.as_ref().unwrap()))
            ))
            .collect::<HashMap<String, (String, Ed25519VerifyingKey)>>()
    }

    fn check_if_verification_method_match_public_key(&self, did_tdw: &str, verifying_key: &Ed25519VerifyingKey) {
        match self.get_controller_verifying_key().get(did_tdw) {
            Some(public_key) => {
                if public_key.1.to_multibase() != verifying_key.to_multibase() {
                    panic!("Invalid key pair. The provided key pair is not the one referenced in the did doc")
                }
            }
            None => panic!("Invalid did_tdw. The did_tdw is not a controller of the did doc")
        }
    }

    /// Get the verification method id (did_tdw#key-1) and verifying key with which the data integrity proof was created
    pub fn get_data_integrity_verifying_key(&self) -> Ed25519VerifyingKey {
        let proof_verification_method = self.proof.as_ref().unwrap().verification_method.clone();
        let verification_method = self.did_doc.verification_method.iter()
            .filter(|entry| entry.id == proof_verification_method)
            .collect::<Vec<&VerificationMethod>>().first().unwrap().to_owned();

        // Make sure the the verification method is part of the authentication section
        if !self.did_doc.authentication.iter().any(|authentication_method| authentication_method.id == verification_method.id) {
            panic!("Invalid integrity proof for log with id {}. The verification method used for the integrity proof is not part of the authentication section", self.version_id.unwrap())
        }

        if verification_method.verification_type != utils::EDDSA_VERIFICATION_KEY_TYPE {
            panic!("Invalid verification method. Only eddsa verification keys are supported")
        }

        Ed25519VerifyingKey::from_multibase(verification_method.public_key_multibase.as_ref().unwrap())
    }

    pub fn to_log_entry_line(&self) -> serde_json::Value {
        match &self.proof {
            Some(proof) => serde_json::json!([
                self.entry_hash,
                self.version_id,
                self.version_time.to_owned().format(utils::DATE_TIME_FORMAT).to_string(),
                self.parameters,
                {
                    "value": self.did_doc
                },
                proof.to_value()
            ]),
            None => serde_json::json!([
                self.entry_hash,
                self.version_id,
                self.version_time.to_owned().format(utils::DATE_TIME_FORMAT).to_string(),
                self.parameters,
                {
                    "value": self.did_doc
                },
            ])
        }
    }
}

// See https://identity.foundation/trustdidweb/#didtdw-did-method-parameters
#[derive(Serialize, Deserialize, Debug, Clone)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub portable: Option<bool>,
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
            portable: Option::Some(false),
        }
    }

    pub fn empty() -> Self {
        DidMethodParameters {
            method: Option::None,
            scid: Option::None,
            hash: Option::None,
            cryptosuite: Option::None,
            prerotation: Option::None,
            next_keys: Option::None,
            moved: Option::None,
            deactivated: Option::None,
            ttl: Option::None,
            portable: Option::None,
        }
    }

    pub fn deactivate() -> Self {
        DidMethodParameters {
            method: Option::None,
            scid: Option::None,
            hash: Option::None,
            cryptosuite: Option::None,
            prerotation: Option::None,
            next_keys: Option::None,
            moved: Option::None,
            deactivated: Option::Some(true),
            ttl: Option::None,
            portable: Option::None,
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
        let mut unescaped = did_log.clone();
        if unescaped.contains("\\\"") {
            unescaped = serde_json::from_str(&did_log).unwrap()
        }
        DidDocumentState {
            did_log_entries: unescaped.split("\n")
                .filter(|line| line.len() > 0)
                .map(|line| {
                    let entry: serde_json::Value = match serde_json::from_str(line) {
                        Ok(entry) => entry,
                        Err(e) => panic!("{}", e),
                    };
                    match entry {
                        JsonArray(ref entry) => {
                            if entry.len() < 5 {
                                panic!("Invalid did log entry. Expected at least 5 elements but got {}", entry.len())
                            }
                        }
                        _ => panic!("Invalid did log entry. Expected array")
                    }
                    // TODO replace this with toString call of log entry
                    DidLogEntry::new(
                        match entry[0] {
                            JsonString(ref entry_hash) => entry_hash.clone(),
                            _ => panic!("Invalid entry hash"),
                        },
                        entry[1].to_string().parse::<usize>().unwrap(),
                        DateTime::parse_from_str(entry[2].as_str().unwrap(), utils::DATE_TIME_FORMAT).unwrap().to_utc(),
                        serde_json::from_str(&entry[3].to_string()).unwrap(),
                        serde_json::from_str(&entry[4]["value"].to_string()).unwrap(),
                        DataIntegrityProof::from(entry[5].to_string()),
                    )
                    // TODO continue here with fixing the parsing process
                }).collect::<Vec<DidLogEntry>>()
        }
    }

    pub fn current(&self) -> &DidLogEntry {
        let last_entry = self.did_log_entries.last().unwrap();
        last_entry
    }

    /// Checks if all entries in the did log are valid (data integrity, versioning etc.)
    pub fn validate_with_scid(&self, scid_to_validate: Option<String>) -> Arc<DidDoc> {
        let mut previous_entry: Option<DidLogEntry> = None;
        for entry in &self.did_log_entries {
            match previous_entry {
                Some(ref prev) => {
                    // Check if version has incremented
                    if entry.version_id.unwrap() != prev.version_id.unwrap() + 1 {
                        panic!("Invalid did log for version {}. Version id has to be incremented", entry.version_id.unwrap())
                    }
                    // Verify data integrity proof
                    entry.verify_data_integrity_proof(); // may panic

                    // Verify the entryHash
                    entry.verify_entry_hash_integrity(&prev.entry_hash); // may panic
                    previous_entry = Some(entry.clone());
                }
                None => {
                    // First / genesis entry in did log
                    let genesis_entry = self.did_log_entries.first().unwrap();
                    if genesis_entry.version_id.unwrap() != 1 {
                        panic!("Invalid did log. First entry has to have version id 1")
                    }
                    // Verify data integrity proof
                    genesis_entry.verify_data_integrity_proof(); // may panic
                    // Verify the entryHash
                    genesis_entry.verify_entry_hash_integrity(genesis_entry.parameters.scid.as_ref().unwrap()); // may panic
                    // Verify that the SCID is correct
                    let doc_string = serde_json::to_string(&genesis_entry.did_doc).unwrap();
                    let scid = genesis_entry.parameters.scid.clone().unwrap();
                    if let Some(res) = &scid_to_validate {
                        if res.ne(scid.as_str()) {
                            panic!("The scid from the did doc {scid} doesnt match the requested one {res}")
                        }
                    }
                    let did_doc_with_palaceholder = str::replace(&doc_string, &scid, utils::SCID_PLACEHOLDER);
                    let did_doc: DidDoc = serde_json::from_str(&did_doc_with_palaceholder).unwrap();
                    let original_scid = generate_scid(&did_doc);
                    if original_scid != scid {
                        panic!("Invalid did log. Genesis entry has invalid SCID")
                    }
                    previous_entry = Some(genesis_entry.clone());
                }
            };
        }
        match previous_entry {
            Some(entry) => entry.did_doc.clone().into(),
            None => panic!("Invalid did log. No entries found")
        }
    }

    /// Checks if all entries in the did log are valid (data integrity, versioning etc.)
    pub fn validate(&self) -> Arc<DidDoc> {
        self.validate_with_scid(None) // may panic
    }

    /// Add a new entry to the did log file
    /// https://bcgov.github.io/trustdidweb/#create-register
    pub fn update(&mut self, log_entry: DidLogEntry, did_tdw: &str, key_pair: &Ed25519KeyPair) {

        // Identify version id
        let mut index: usize = 1;
        let mut previous_hash = log_entry.entry_hash.clone();
        let mut verification_method = String::new();

        // Make sure only activated did docs can be updated

        if self.did_log_entries.len() == 0 {
            // Genesis entry (Create)
            // Check if version hash is present
            if log_entry.entry_hash.len() == 0 {
                panic!("For the initial log entry the SCID/previous hash has to be provided")
            }
            log_entry.check_if_verification_method_match_public_key(did_tdw, key_pair.get_verifying_key().as_ref()); // may panic
            verification_method = log_entry.get_controller_verifying_key().get(did_tdw).unwrap().0.clone();
        } else {
            // Subsequent entry (Update)
            let previous_entry = self.did_log_entries.last().unwrap();

            // Make sure portability cant be set afterward to true
            if let Some(portable) = log_entry.parameters.portable {
                if portable {
                    panic!("Portability can only be set in genesis entry to true")
                }
            }

            // Make sure only activated did docs can be updated
            match previous_entry.did_doc.deactivated {
                Some(deactivated) => {
                    if deactivated {
                        panic!("Invalid did doc. The did doc is already deactivated. For simplicity reasons we don't allow updates of dids")
                    }
                }
                None => (),
            }

            // Get new version index
            index = previous_entry.version_id.unwrap() + 1;
            // Get last version hash
            previous_hash = previous_entry.entry_hash.clone();
            previous_entry.check_if_verification_method_match_public_key(did_tdw, key_pair.get_verifying_key().as_ref()); // may panic
            verification_method = log_entry.get_controller_verifying_key().get(did_tdw).unwrap().0.clone();
        }

        // Generate new hash and use it as entry_hash and integrity challenge
        let doc_without_entry_hash = DidLogEntry {
            version_id: Some(index),
            entry_hash: previous_hash,
            ..log_entry
        };
        let integrity_challenge = doc_without_entry_hash.get_hash();
        let doc_without_proof = DidLogEntry {
            entry_hash: integrity_challenge.clone(),
            ..doc_without_entry_hash
        };

        // Generate data integrity proof for new entry
        let suite_options = CryptoSuiteOptions::new(
            CryptoSuiteType::EddsaJcs2022,
            verification_method,
            integrity_challenge,
        );
        let signing_key = key_pair.get_signing_key().to_multibase();
        let eddsa_suite = EddsaCryptosuite {
            signing_key: Some(Ed25519SigningKey::from_multibase(&signing_key)),
            verifying_key: None,
        };
        let did_doc_ = match serde_json::to_string(&doc_without_proof.did_doc) {
            Ok(doc) => doc,
            Err(_) => panic!("Invalid did doc"),
        };
        let did_doc_value = serde_json::from_str(&did_doc_).unwrap();
        let secured_document = eddsa_suite.add_proof(&did_doc_value, &suite_options);
        let proof_value_string = secured_document["proof"].to_string();
        let doc = DidLogEntry {
            proof: Some(DataIntegrityProof::from(proof_value_string)),
            ..doc_without_proof
        };
        self.did_log_entries.push(doc);
    }
}

impl std::fmt::Display for DidDocumentState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut log = String::new();
        for entry in &self.did_log_entries {
            let serialized = entry.to_log_entry_line();
            log.push_str(serde_json::to_string(&serialized).unwrap().as_str());
            log.push_str("\n");
        }
        write!(f, "{}", log)
    }
}

/// Basic user facing did method operations to handle a did
pub trait DidMethodOperationWrapper {
    fn create(&self, url: String, key_pair: &Ed25519KeyPair) -> String;
    fn read(&self, did_tdw: String) -> String;
    fn update(&self, did_tdw: String, did_doc: String, key_pair: &Ed25519KeyPair) -> String;
    fn deactivate(&self, did_tdw: String, key_pair: &Ed25519KeyPair) -> String;
}

/// Basic user facing did method operations to handle a did
/// See https://identity.foundation/trustdidweb/#did-method-operations
/// CAUTION This trait assumes Ed25519 authorization key pair.
pub trait DidMethodOperation {
    /// See https://identity.foundation/trustdidweb/#create-register
    fn create(&self, url: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> String;
    /// See https://identity.foundation/trustdidweb/#read-resolve
    fn read(&self, did_tdw: String, allow_http: Option<bool>) -> String;
    /// See https://identity.foundation/trustdidweb/#update-rotate
    fn update(&self, did_tdw: String, did_doc: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> String;
    /// See https://identity.foundation/trustdidweb/#deactivate-revoke
    fn deactivate(&self, did_tdw: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> String;
}

/// Convert domain into did:tdw:{method specific identifier} method specific identifier
pub fn get_tdw_domain_from_url(url: &String, allow_http: Option<bool>) -> Result<String, TrustDidWebError> {
    let mut did = String::from("");
    if url.starts_with("https://") {
        did = url.replace("https://", "");
    } else if url.starts_with("http://localhost") || url.starts_with("http://127.0.0.1") || allow_http.unwrap_or(false) {
        did = url.replace("http://", "");
    } else {
        return Err(TrustDidWebError::InvalidMethodSpecificId(String::from("Invalid url. Only https is supported")));
    }

    if did.contains(".well-known") {
        return Err(TrustDidWebError::InvalidMethodSpecificId(String::from("Invalid url. Please remove .well-known from url")));
    }
    if did.contains("did.jsonl") {
        return Err(TrustDidWebError::InvalidMethodSpecificId(String::from("Invalid url. Please remove did.json from url")));
    }
    let url = did.replace(":", "%3A");
    Ok(url.replace("/", ":"))
}

/// Yet another UniFFI-compliant error.
///
/// Resembles ssi::dids::resolution::Error
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum TrustDidWebIdResolutionError {
    /// DID method is not supported by this resolver.
    #[error("DID method `{0}` not supported")]
    MethodNotSupported(String),
    /// Invalid method-specific identifier.
    #[error("invalid method specific identifier: {0}")]
    InvalidMethodSpecificId(String),
}

impl TrustDidWebIdResolutionError {
    /// Returns the error kind.
    pub fn kind(&self) -> TrustDidWebIdResolutionErrorKind {
        match self {
            Self::MethodNotSupported(_) => TrustDidWebIdResolutionErrorKind::MethodNotSupported,
            Self::InvalidMethodSpecificId(_) => TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId,
        }
    }
}

/// TrustDidWebIdResolutionError kind.
///
/// Each [`TrustDidWebIdResolutionError`] has a kind provided by the [`TrustDidWebIdResolutionErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrustDidWebIdResolutionErrorKind {
    MethodNotSupported,
    InvalidMethodSpecificId,
}

/// As specified at https://identity.foundation/trustdidweb/#method-specific-identifier:
///
/// "The did:tdw method-specific identifier contains both the self-certifying identifier (SCID) for the DID,
/// and a fully qualified domain name (with an optional path) that is secured by a TLS/SSL certificate."
pub struct TrustDidWebId {
    scid: String,
    url: String,
    // TODO path: Option<String>
}

static HAS_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([a-z]|[0-9])\/([a-z]|[0-9])").unwrap());
static HAS_PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\:[0-9]+").unwrap());

impl TrustDidWebId {
    /// Yet another UniFFI-compliant method.
    ///
    /// Otherwise, the idiomatic counterpart (try_from(value: (String, Option<bool>)) -> Result<Self, Self::Error>) may be used as well.
    pub fn parse_did_tdw(did_tdw: String, allow_http: Option<bool>) -> Result<Self, TrustDidWebIdResolutionError> {
        match Self::try_from((did_tdw, allow_http)) {
            Ok(parsed) => {
                Ok(parsed)
            }
            Err(e) => Err(e),
        }
    }

    pub fn get_scid(&self) -> String {
        self.scid.clone()
    }

    pub fn get_url(&self) -> String {
        self.url.clone()
    }
}

/// Implementation for a tuple denoting did_twd and allow_http.
impl TryFrom<(String, Option<bool>)> for TrustDidWebId {
    type Error = TrustDidWebIdResolutionError;

    fn try_from(value: (String, Option<bool>)) -> Result<Self, Self::Error> {
        let did_tdw = value.0;
        let allow_http = value.1;

        match SSIDIDBuf::try_from(did_tdw.to_owned()) {
            Ok(buf) => {
                if !buf.method_name().starts_with(TrustDidWeb::DID_METHOD_NAME) {
                    return Err(TrustDidWebIdResolutionError::MethodNotSupported(buf.method_name().to_owned()));
                };

                match buf.method_specific_id().split_once(":") {
                    Some((scid, did_tdw_reduced)) => {
                        let mut decoded_url = String::from("");
                        url_escape::decode_to_string(did_tdw_reduced.replace(":", "/"), &mut decoded_url);

                        let url = match String::from_utf8(decoded_url.into_bytes()) {
                            Ok(url) => {
                                if url.starts_with("localhost") || url.starts_with("127.0.0.1") || allow_http.unwrap_or(false) {
                                    format!("http://{}", url)
                                } else {
                                    format!("https://{}", url)
                                }
                            }
                            Err(_) => return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(did_tdw_reduced.to_string())),
                        };
                        if HAS_PATH_REGEX.captures(url.as_str()).is_some() || HAS_PORT_REGEX.captures(url.as_str()).is_some() {
                            Ok(Self { scid: scid.to_string(), url: format!("{}/did.jsonl", url) })
                        } else {
                            Ok(Self { scid: scid.to_string(), url: format!("{}/.well-known/did.jsonl", url) })
                        }
                    }
                    None => Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(buf.method_specific_id().to_owned())),
                }
            }
            Err(_) => Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(did_tdw)),
        }
    }
}

/// Yet another UniFFI-compliant error.
///
/// Resembles ssi::dids::resolution::Error
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum TrustDidWebError {
    /// DID method is not supported by this resolver
    #[error("DID method `{0}` not supported")]
    MethodNotSupported(String),
    /// Invalid method-specific identifier
    #[error("invalid method specific identifier: {0}")]
    InvalidMethodSpecificId(String),
    /// TODO Complete the docstring
    #[error("failed to serialize to JSON: {0}")]
    SerializationFailed(String),
    /// The supplied did doc is invalid or contains an argument which isn't part of the did specification/recommendation
    #[error("The supplied did doc is invalid or contains an argument which isn't part of the did specification/recommendation: {0}")]
    DeserializationFailed(String),
    /// Invalid (or not yet supported) operation against DID doc
    #[error("Invalid (or not yet supported) operation against DID doc: {0}")]
    InvalidOperation(String),
}

impl TrustDidWebError {
    /// Returns the error kind.
    pub fn kind(&self) -> TrustDidWebErrorKind {
        match self {
            Self::MethodNotSupported(_) => TrustDidWebErrorKind::MethodNotSupported,
            Self::InvalidMethodSpecificId(_) => TrustDidWebErrorKind::InvalidMethodSpecificId,
            Self::SerializationFailed(_) => TrustDidWebErrorKind::SerializationFailed,
            Self::DeserializationFailed(_) => TrustDidWebErrorKind::DeserializationFailed,
            Self::InvalidOperation(_) => TrustDidWebErrorKind::InvalidOperation,
        }
    }
}

/// TrustDidWebError kind.
///
/// Each [`TrustDidWebError`] has a kind provided by the [`TrustDidWebErrorKind::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrustDidWebErrorKind {
    MethodNotSupported,
    InvalidMethodSpecificId,
    SerializationFailed,
    DeserializationFailed,
    InvalidOperation,
}

/// TODO Doc comments missing
pub struct TrustDidWeb {
    did: String,
    did_log: String,
    did_doc: String,
}

impl TrustDidWeb {

    /// NOT UniFFI-compliant constructor.
    pub fn new(did: String,
               did_log: String,
               did_doc: String) -> Self {
        Self {
            did: did,
            did_log: did_log,
            did_doc: did_doc
        }
    }

    pub fn get_did(&self) -> String {
        self.did.clone()
    }

    pub fn get_did_log(&self) -> String {
        self.did_log.clone()
    }

    pub fn get_did_doc(&self) -> String {
        self.did_doc.clone()
    }

    pub fn create(url: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> Result<Self, TrustDidWebError> {
        // Check if domain is valid
        let domain = get_tdw_domain_from_url(&url, allow_http)?;

        // Create verification method suffix so that it can be used as part of verification method id property
        let did_tdw = format!("did:tdw:{}:{}", utils::SCID_PLACEHOLDER, domain);

        let key_def = json!({
            "type": utils::EDDSA_VERIFICATION_KEY_TYPE,
            "publicKeyMultibase": key_pair.verifying_key.to_multibase(),
        });
        let key_def_jcs = match jcs_from_str(&key_def.to_string()) {
            Ok(v) => v,
            Err(e) => return Err(TrustDidWebError::DeserializationFailed(e.to_string()))
        };
        let mut hasher = Sha256::new();
        hasher.update(key_def_jcs);
        let key_def_hash: String = hasher.finalize().encode_hex();
        let verification_method_suffix = URL_SAFE_NO_PAD.encode(key_def_hash.as_bytes());

        // Create verification method for subject with placeholder
        let verification_method = VerificationMethod {
            id: format!("{}#{}", &did_tdw, verification_method_suffix),
            controller: did_tdw.clone(),
            verification_type: String::from(utils::EDDSA_VERIFICATION_KEY_TYPE),
            public_key_multibase: Some(key_pair.verifying_key.to_multibase()),
            public_key_jwk: None,
        };
        // Create initial did doc with placeholder
        let did_doc = DidDoc {
            context: vec![utils::DID_CONTEXT.to_string(), utils::MKEY_CONTEXT.to_string()],
            id: did_tdw.clone(),
            verification_method: vec![verification_method.clone()],
            authentication: vec![verification_method.clone()],
            capability_invocation: vec![],
            capability_delegation: vec![],
            assertion_method: vec![],
            controller: vec![format!("did:tdw:{}:{}", utils::SCID_PLACEHOLDER, domain)],
            deactivated: None,
        };

        // Generate SCID and replace placeholder in did doc
        let scid = generate_scid(&did_doc);
        let did_doc_serialize: String = match serde_json::to_string(&did_doc) {
            Ok(v) => v,
            Err(e) => return Err(TrustDidWebError::SerializationFailed(e.to_string()))
        };
        let did_doc_with_scid = str::replace(&did_doc_serialize, utils::SCID_PLACEHOLDER, &scid);
        let genesis_did_doc: DidDoc = match serde_json::from_str(&did_doc_with_scid) {
            Ok(v) => v,
            Err(e) => return Err(TrustDidWebError::DeserializationFailed(e.to_string()))
        };

        let log_without_proof_and_signature = DidLogEntry::of(
            scid.to_owned(),
            DidMethodParameters::for_genesis_did_doc(scid.to_owned()),
            genesis_did_doc.clone(),
        );

        // Initialize did log with genesis did doc
        let mut did_log: DidDocumentState = DidDocumentState::new();
        let controller: &String = match genesis_did_doc.controller.first() {
            Some(v) => v,
            _ => return Err(TrustDidWebError::DeserializationFailed("genesis did doc controller is empty".to_string()))
        };
        did_log.update(log_without_proof_and_signature, &controller, key_pair); // may panic
        let genesis_str = match serde_json::to_string(&genesis_did_doc) {
            Ok(v) => v,
            Err(e) => return Err(TrustDidWebError::SerializationFailed(e.to_string()))
        };

        Ok(Self {
            did: genesis_did_doc.id,
            did_log: did_log.to_string(),
            did_doc: genesis_str,
        })
    }

    pub fn read(did_tdw: String, did_log: String, allow_http: Option<bool>) -> Result<Self, TrustDidWebError> {
        let did_doc_state = DidDocumentState::from(did_log); // may panic
        let scid = match TrustDidWebId::parse_did_tdw(did_tdw.to_owned(), allow_http) {
            Ok(tdw_id) => { tdw_id.get_scid() }
            Err(e) => return Err(TrustDidWebError::InvalidMethodSpecificId(e.to_string())),
        };
        let did_doc_arc = did_doc_state.validate_with_scid(Some(scid.to_owned())); // may panic
        let did_doc = did_doc_arc.as_ref().clone();
        let did_doc_str = match serde_json::to_string(&did_doc) {
            Ok(v) => v,
            Err(e) => return Err(TrustDidWebError::SerializationFailed(e.to_string()))
        };
        Ok(Self {
            did: did_doc.id,
            did_log: did_doc_state.to_string(),
            did_doc: did_doc_str,
        })
    }

    pub fn update(did_tdw: String, did_log: String, did_doc: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> Result<Self, TrustDidWebError> {
        let mut did_doc_state = DidDocumentState::from(did_log); // may panic
        let scid = match TrustDidWebId::parse_did_tdw(did_tdw.to_owned(), allow_http) {
            Ok(tdw_id) => { tdw_id.get_scid() }
            Err(e) => return Err(TrustDidWebError::InvalidMethodSpecificId(e.to_string())),
        };
        let current_did_doc = did_doc_state.validate_with_scid(Some(scid)); // may panic
        let update_did_doc: DidDoc = match serde_json::from_str(&did_doc) {
            Ok(doc) => doc,
            Err(e) => return Err(TrustDidWebError::DeserializationFailed(e.to_string()))
        };

        // TODO right now did can't be changed
        if current_did_doc.id != update_did_doc.id {
            return Err(TrustDidWebError::InvalidOperation("Invalid DID doc. The DID doc id has to match the did_tdw".to_string()));
        }

        let current_entry = did_doc_state.current();
        let update_entry = DidLogEntry::of(
            current_entry.entry_hash.clone(),
            // TODO make parameters configurable
            DidMethodParameters::empty(),
            update_did_doc.clone(),
        );
        did_doc_state.update(update_entry, &did_tdw, key_pair); // may panic
        let did_doc_str = match serde_json::to_string(&update_did_doc) {
            Ok(v) => v,
            Err(e) => return Err(TrustDidWebError::SerializationFailed(e.to_string()))
        };

        Ok(Self {
            did: update_did_doc.id,
            did_log: did_doc_state.to_string(),
            did_doc: did_doc_str,
        })
    }

    /// It  https://identity.foundation/trustdidweb/#deactivate-revoke
    pub fn deactivate(did_tdw: String, did_log: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> Result<Self, TrustDidWebError> {
        let mut did_doc_state = DidDocumentState::from(did_log); // may panic
        let scid = match TrustDidWebId::parse_did_tdw(did_tdw.to_owned(), allow_http) {
            Ok(tdw_id) => { tdw_id.get_scid() }
            Err(e) => return Err(TrustDidWebError::InvalidMethodSpecificId(e.to_string())),
        };
        let mut current_did_doc = did_doc_state.validate_with_scid(Some(scid)).as_ref().clone(); // may panic

        // Mark did doc as deactivated and set did log parameters accordingly
        current_did_doc.deactivated = Some(true);
        let current_entry = did_doc_state.current();
        let update_entry = DidLogEntry::of(
            current_entry.entry_hash.clone(),
            DidMethodParameters::deactivate(),
            current_did_doc.clone(),
        );
        did_doc_state.update(update_entry, &did_tdw, key_pair); // may panic
        let did_doc_str = match serde_json::to_string(&current_did_doc) {
            Ok(v) => v,
            Err(e) => return Err(TrustDidWebError::SerializationFailed(e.to_string()))
        };

        Ok(Self {
            did: current_did_doc.id,
            did_log: did_doc_state.to_string(),
            did_doc: did_doc_str,
        })
    }
}

impl SSIDIDMethod for TrustDidWeb {
    const DID_METHOD_NAME: &'static str = "tdw";
}

impl SSIDIDMethodResolver for TrustDidWeb {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: SSIOptions,
    ) -> Result<SSIOutput<Vec<u8>>, SSIResolutionError> {
        // TODO Implement DIDMethodResolver for TrustDidWeb
        todo!()
    }
}


/// Generates an SCID (self certifying identifier) based on the initial DiDoC.
/// This function is used as well in the initial generation as in the verification
/// process of the DidDoc log file
pub fn generate_scid(did_doc: &DidDoc) -> String {
    if !did_doc.id.contains(utils::SCID_PLACEHOLDER) {
        panic!("Invalid did:tdw document. SCID placeholder not found");
    }
    let json = serde_json::to_string(did_doc).unwrap();
    utils::generate_jcs_hash(&json)
}
