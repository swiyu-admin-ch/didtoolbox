use std::collections::HashMap;
use std::sync::Arc;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use chrono::serde::ts_seconds;
use serde::{Deserialize, Serialize};
use base64::{Engine as _};
use base32::{decode as base32_decode, encode as base32_encode, Alphabet};
use serde_jcs::{to_vec as jcs_from_str, to_string as jcs_to_string};
use serde_json::json;
use serde_json::Value::{String as JsonString, Object as JsonObject, Array as JsonArray};
use sha2::{Sha256, Digest};
use hex;
use hex::ToHex;
use rand::{thread_rng, Rng};
use regex;
use ureq;
use url_escape;
use crate::utils;
use crate::ed25519::*;
use crate::vc_data_integrity::*;
use crate::didtoolbox::*;
/// Entry in an did log file as shown here
/// https://bcgov.github.io/trustdidweb/#term:did-log-entry
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
            proof: Some(proof)
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
            proof: None
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
            proof: None
        };
        let entry_hash = entry_without_proof.get_hash();
        if entry_hash != self.entry_hash {
            panic!("Invalid did log. Genesis entry has invalid entry hash")
        }
    }

    /// Check wether the integrity proof matches the content of the did document of this log entry
    pub fn verify_data_integrity_proof(&self) {
        // Verify data integrity proof 
        let verifying_key = self.get_data_integrity_verifying_key();

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
        generate_jcs_hash(&json)
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
            },
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
                    },
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
                    DataIntegrityProof::from(entry[5].to_string())
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
    pub fn validate(&self) -> Arc<DidDoc> {
        let mut previous_entry: Option<DidLogEntry> = None;
        for entry in &self.did_log_entries {
            match previous_entry {
                Some(ref prev) => {
                    // Check if version has incremented
                    if entry.version_id.unwrap() != prev.version_id.unwrap()+1 {
                        panic!("Invalid did log for version {}. Version id has to be incremented", entry.version_id.unwrap())
                    }
                    // Verify data integrity proof 
                    entry.verify_data_integrity_proof();

                    // Verify the entryHash
                    entry.verify_entry_hash_integrity(&prev.entry_hash);
                    previous_entry = Some(entry.clone());
                },
                None => {
                    // First / genesis entry in did log
                    let genesis_entry = self.did_log_entries.first().unwrap();
                    if genesis_entry.version_id.unwrap() != 1 {
                        panic!("Invalid did log. First entry has to have version id 1")
                    }
                    // Verify data integrity proof 
                    genesis_entry.verify_data_integrity_proof();
                    // Verify the entryHash
                    genesis_entry.verify_entry_hash_integrity(genesis_entry.parameters.scid.as_ref().unwrap());
                    // Verify that the SCID is correct
                    let doc_string = serde_json::to_string(&genesis_entry.did_doc).unwrap();
                    let scid = genesis_entry.parameters.scid.clone().unwrap();
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
            log_entry.check_if_verification_method_match_public_key(did_tdw, key_pair.get_verifying_key().as_ref());
            verification_method = log_entry.get_controller_verifying_key().get(did_tdw).unwrap().0.clone();
        } else {
            // Subsequent entry (Update)
            let previous_entry = self.did_log_entries.last().unwrap();

            // Make sure only activated did docs can be updated
            match previous_entry.did_doc.deactivated{
                Some(deactivated) => {
                    if deactivated {
                        panic!("Invalid did doc. The did doc is already deactivated. For simplicity reasons we don't allow updates of dids")
                    }
                },
                None => (),
            }

            // Get new version index
            index = previous_entry.version_id.unwrap() + 1;
            // Get last version hash
            previous_hash = previous_entry.entry_hash.clone();
            previous_entry.check_if_verification_method_match_public_key(did_tdw, key_pair.get_verifying_key().as_ref());
            verification_method = log_entry.get_controller_verifying_key().get(did_tdw).unwrap().0.clone();
        }

        // Generate new hash and use it as entry_hash and integrity challenge
        let doc_without_entry_hash = DidLogEntry{
            version_id: Some(index),
            entry_hash: previous_hash,
            ..log_entry
        };
        let integrity_challenge = doc_without_entry_hash.get_hash();
        let doc_without_proof = DidLogEntry{
            entry_hash: integrity_challenge.clone(),
            ..doc_without_entry_hash
        };

        // Generate data integrity proof for new entry
        let suite_options = CryptoSuiteOptions::new(
            CryptoSuiteType::EddsaJcs2022,
            verification_method,
            integrity_challenge
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
pub trait DidMethodOperation {
    fn create(&self, url: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> String;
    fn read(&self, did_tdw: String, allow_http: Option<bool>) -> String;
    fn update(&self, did_tdw: String, did_doc: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> String;
    fn deactivate(&self, did_tdw: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> String;
}

pub trait UrlResolver: Send + Sync {
    fn read(&self, url: String) -> String;
    fn write(&self, url: String, content: String);
}
pub struct HttpClientResolver {
    pub api_key: Option<String>
}
impl UrlResolver for HttpClientResolver {
    fn read(&self, url: String) -> String {
        let mut request = ureq::get(&url);
        match &self.api_key {
            Some(api_key) => {
                request = request.set("X-API-KEY", api_key);
            },
            None => (),
        };
        match request.call() {
            Ok(response) => match response.into_string() {
                Ok(body) => body,
                Err(_) => panic!("Couldn't read from url"),
            },
            Err(_) => panic!("Couldn't read from url"),
        }
    }
    fn write(&self, url: String, content: String) {
        let mut request = ureq::post(&url);
        match &self.api_key {
            Some(api_key) => {
                request = request.set("X-API-KEY", api_key);
            },
            None => (),
        };
        match request.send_form(&[
            ("file", &content)
        ]) {
            Ok(_) => (),
            Err(e) => panic!("{}", e),
        }
    }
}


/// Convert did:tdw:{method specific identifier} method specific identifier into resolvable url
fn get_url_from_tdw(did_tdw: &String, allow_http: Option<bool>) -> String {
    if !did_tdw.starts_with("did:tdw:") {
        panic!("Invalid did:twd string. It has to start with did:tdw:")
    }
    let did_tdw = did_tdw.replace("did:tdw:","");

    let mut decoded_url = String::from("");
    url_escape::decode_to_string(did_tdw.replace(":", "/"), &mut decoded_url);
    let url = match String::from_utf8(decoded_url.into_bytes()) {
            Ok(url) => {
                if url.starts_with("localhost") || allow_http.unwrap_or(false) {
                    format!("http://{}", url)
                } else {
                    format!("https://{}", url)
                }
            },
            Err(_) => panic!("Couldn't convert did_tdw url to utf8 string"),
    };
    let has_path = regex::Regex::new(r"([a-z]|[0-9])\/([a-z]|[0-9])").unwrap();
    match has_path.captures(url.as_str()) {
        Some(_) => format!("{}/did.jsonl", url),
        None => format!("{}/.well-know/did.jsonl", url),
    }
}

/// Convert domain into did:tdw:{method specific identifier} method specific identifier
fn get_tdw_domain_from_url(url: &String, allow_http: Option<bool>) -> String {
    let mut did = String::from("");
    if url.starts_with("https://") {
        did = url.replace("https://", "");
    } else if url.starts_with("http://localhost") || allow_http.unwrap_or(false) {
        did = url.replace("http://", "");
    } else {
        panic!("Invalid url. Only https is supported")
    }

    if did.contains(".well-known") {
        panic!("Invalid url. Please remove .well-known from url")
    }
    if did.contains("did.jsonl") {
        panic!("Invalid url. Please remove did.json from url")
    }
    let url = did.replace(":", "%3A");
    url.replace("/", ":")
}



pub struct TrustDidWeb {
    did: String,
    did_log: String,
    did_doc: String,
}

impl TrustDidWeb {
    pub fn get_did(&self) -> String {
        self.did.clone()
    }

    pub fn get_did_log(&self) -> String {
        self.did_log.clone()
    }

    pub fn get_did_doc(&self) -> String {
        self.did_doc.clone()
    }

    pub fn create(url: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> Self {
        // Check if domain is valid
        let domain = get_tdw_domain_from_url(&url, allow_http);

        // Create verification method suffix so that it can be used as part of verification method id property
        let did_tdw = format!("did:tdw:{}:{}", domain, utils::SCID_PLACEHOLDER);
        let key_def = json!({
            "type": utils::EDDSA_VERIFICATION_KEY_TYPE,
            "publicKeyMultibase": key_pair.verifying_key.to_multibase(),
        });
        let key_def_jcs = jcs_from_str(&key_def.to_string()).unwrap();
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
            public_key_jwk: None
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
            controller: vec![format!("did:tdw:{}:{}", domain, utils::SCID_PLACEHOLDER)],
            deactivated: None,
        };

        // Generate SCID and replace placeholder in did doc
        let scid = generate_scid(&did_doc);
        let did_doc_serialize = serde_json::to_string(&did_doc).unwrap();
        let did_doc_with_scid = str::replace(&did_doc_serialize, utils::SCID_PLACEHOLDER, &scid);
        // let did_doc_with_scid = re.replace_all(&did_doc_serialize, &scid).to_string();
        let genesis_did_doc: DidDoc = serde_json::from_str(&did_doc_with_scid).unwrap();

        let log_without_proof_and_signature = DidLogEntry::of(
            scid.to_owned(),
            DidMethodParameters::for_genesis_did_doc(scid.to_owned()),
            genesis_did_doc.clone()
        );

        // Initialize did log with genesis did doc
        let mut did_log: DidDocumentState = DidDocumentState::new();
        let controller = genesis_did_doc.controller.first().unwrap();
        did_log.update(log_without_proof_and_signature,&controller , key_pair);
        let genesis_str = serde_json::to_string(&genesis_did_doc).unwrap();
        Self {
            did: genesis_did_doc.id,
            did_log: did_log.to_string(),
            did_doc: genesis_str
        }
    }

    pub fn read(did_tdw: String, allow_http: Option<bool>) -> Self {
        let url = get_url_from_tdw(&did_tdw, allow_http);
        let resolver = HttpClientResolver {
            api_key: Option::None,
        };
        let did_log_raw = resolver.read(url);
        let did_doc_state = DidDocumentState::from(did_log_raw);
        let did_doc_arc = did_doc_state.validate();
        let did_doc = did_doc_arc.as_ref().clone();
        let did_doc_str = serde_json::to_string(&did_doc).unwrap();
        Self {
            did: did_doc.id,
            did_log: did_doc_state.to_string(),
            did_doc: did_doc_str
        }
    }

    pub fn update(did_tdw: String, did_log: String, did_doc: String,  key_pair: &Ed25519KeyPair) -> Self {
        let mut did_doc_state = DidDocumentState::from(did_log);
        let current_did_doc = did_doc_state.validate();
        let update_did_doc: DidDoc = match serde_json::from_str(&did_doc) {
            Ok(doc) => doc,
            Err(_) => panic!("The did doc you provided is invalid or contains an argument which isn't part of the did specification/recommendation"),
        };

        // TODO right now did can't be changed
        if current_did_doc.id != update_did_doc.id {
            panic!("Invalid did doc. The did doc id has to match the did_tdw")
        }

        let current_entry = did_doc_state.current();
        let update_entry = DidLogEntry::of(
            current_entry.entry_hash.clone(),
            DidMethodParameters::empty(),
            update_did_doc.clone()
        );
        did_doc_state.update(update_entry, &did_tdw, key_pair);
        let did_doc_str = serde_json::to_string(&update_did_doc).unwrap();
        Self {
            did: update_did_doc.id,
            did_log: did_doc_state.to_string(),
            did_doc: did_doc_str
        }
    }

    pub fn deactivate(did_tdw: String, did_log: String, key_pair: &Ed25519KeyPair) -> Self {
        let mut did_doc_state = DidDocumentState::from(did_log);
        let mut current_did_doc = did_doc_state.validate().as_ref().clone();
        
        // Mark did doc as deactivated and set did log parameters accordingly
        current_did_doc.deactivated = Some(true);
        let current_entry = did_doc_state.current();
        let update_entry = DidLogEntry::of(
            current_entry.entry_hash.clone(),
            DidMethodParameters::deactivate(),
            current_did_doc.clone()
        );
        did_doc_state.update(update_entry, &did_tdw, key_pair);
        let did_doc_str = serde_json::to_string(&current_did_doc).unwrap();
        Self {
            did: current_did_doc.id,
            did_log: did_doc_state.to_string(),
            did_doc: did_doc_str
        }
    }
}

pub struct TrustDidWebProcessor {
    resolver: Box<dyn UrlResolver>,
}

impl DidMethodOperation for TrustDidWebProcessor {

    fn create(&self, url: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> String {
        let tdw = TrustDidWeb::create(url, key_pair, allow_http);
        self.resolver.write(get_url_from_tdw(&tdw.did, allow_http), tdw.did_log);
        tdw.did
    }

    fn read(&self, did_tdw: String, allow_http: Option<bool>) -> String {
        let url = get_url_from_tdw(&did_tdw, allow_http);
        let did_log_raw = self.resolver.read(url);
        let did_doc_state = DidDocumentState::from(did_log_raw);
        let did_doc = did_doc_state.validate();
        serde_json::to_string(&did_doc.as_ref()).unwrap()
    }

    fn update(&self, did_tdw: String, did_doc: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> String {
        let url = get_url_from_tdw(&did_tdw, allow_http);
        let did_log_raw = self.resolver.read(url);
        let tdw = TrustDidWeb::update(did_tdw.clone(),did_log_raw, did_doc, key_pair);
        self.resolver.write(get_url_from_tdw(&did_tdw, allow_http), tdw.did_log);
        tdw.did_doc
    }

    fn deactivate(&self, did_tdw: String, key_pair: &Ed25519KeyPair, allow_http: Option<bool>) -> String {
        let url = get_url_from_tdw(&did_tdw, allow_http);
        let did_log_raw = self.resolver.read(url);
        let tdw = TrustDidWeb::deactivate(did_tdw.clone(), did_log_raw, key_pair);
        self.resolver.write(get_url_from_tdw(&did_tdw, allow_http), tdw.did_log);
        tdw.did_doc
    }
}


fn generate_jcs_hash(json: &str) -> String {
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

/// Generates an SCID (self certifying identifier) based on the initial DiDoC.
/// This function is used as well in the initial generation as in the verification
/// process of the DidDoc log file
fn generate_scid(did_doc: &DidDoc) -> String {
    if !did_doc.id.contains(utils::SCID_PLACEHOLDER) {
        panic!("Invalid did:tdw document. SCID placeholder not found");
    }
    let json = serde_json::to_string(did_doc).unwrap();
    generate_jcs_hash(&json)
}

impl TrustDidWebProcessor {
    
    pub fn new_with_api_key(api_key: String) -> Self {
        TrustDidWebProcessor {
            resolver: Box::new(HttpClientResolver{api_key: Some(api_key)})
        }
    }

    pub fn new() -> Self {
        TrustDidWebProcessor {
            resolver: Box::new(HttpClientResolver{api_key: None})
        }
    }
}