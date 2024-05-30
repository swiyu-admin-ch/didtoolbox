use core::panic;

use chrono::{DateTime, Utc};
use chrono::serde::ts_seconds;
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE , Engine as _};
use base32::{decode as base32_decode, encode as base32_encode, Alphabet};
use serde_jcs::{to_vec as jcs_from_str, to_string as jcs_to_string};
use serde_json::json;
use serde_json::Value::{String as JsonString, Object as JsonObject, Array as JsonArray};
use sha2::{Sha256, Digest};
use hex;
use hex::ToHex;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use regex;
use ureq;
use url_escape;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<serde_json::Value>,
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
            proof: Some(proof),
        }
    }

    /// Creation of new log entry (without integrity proof)
    pub fn of_with_proof(entry_hash: String, parameters: DidMethodParameters, did_doc: serde_json::Value, proof: serde_json::Value) -> Self {
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
    pub fn of(entry_hash: String, parameters: DidMethodParameters, did_doc: serde_json::Value) -> Self {
        DidLogEntry {
            entry_hash,
            version_id: Option::None,
            version_time: Utc::now(),
            parameters,
            did_doc,
            proof: None
        }
    }

    fn get_hash(&self) -> String {
        let json = serde_json::to_string(&self.to_log_entry_line()).unwrap();
        generate_jcs_hash(&json)
    }

    pub fn to_log_entry_line(&self) -> serde_json::Value {
        match &self.proof {
            Some(proof) => serde_json::json!([
                self.entry_hash,
                self.version_id,
                self.version_time.to_owned().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                self.parameters,
                {
                    "value": self.did_doc
                },
                proof
            ]),
            None => serde_json::json!([
                self.entry_hash,
                self.version_id,
                self.version_time.to_owned().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
                self.parameters,
                {
                    "value": self.did_doc
                },
            ])
        }
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

#[derive(Deserialize, Debug)]
pub struct Entry(String, usize, DateTime<Utc>, DidMethodParameters, serde_json::Value, Option<serde_json::Value>);

impl DidDocumentState {
    pub fn new() -> Self {
        DidDocumentState {
            did_log_entries: Vec::new(),
        }
    }
    pub fn from(did_log: String) -> Self {
        DidDocumentState {
            did_log_entries: did_log.split("\n").map(|line| {
                println!("{}", line);
                let entry: serde_json::Value = match serde_json::from_str(line) {
                    Ok(entry) => entry,
                    Err(e) => panic!("{}", e),
                };
                // TODO replace this with toString call of log entry
                DidLogEntry::new(
                    entry[0].to_string(),
                    entry[1].to_string().parse::<usize>().unwrap(),
                    DateTime::parse_from_str(entry[2].as_str().unwrap(), "%Y-%m-%dT%H:%M:%S%.3fZ").unwrap().to_utc(),
                    serde_json::from_str(&entry[3].to_string()).unwrap(),
                    entry[4].clone(),
                    entry[5].clone()
                )
                // TODO continue here with fixing the parsing process
            }).collect::<Vec<DidLogEntry>>()
        }
    }

    /// Checks whether the did_tdw is an controller of the did doc and matches the provided key pair. Then its returns the 
    /// id of the entry in the the verification method array to be later used as challenge in the integrity proof
    /// https://bcgov.github.io/trustdidweb/#authorized-keys 
    fn get_verification_method_key(&self, log_entry: &DidLogEntry, authorization_key_id: &str, verifying_key: &Ed25519VerifyingKey) -> String {
        let authorization_key_is_controller = match log_entry.did_doc["controller"] {
            JsonArray(ref controller) => {
                let controller_value = JsonString(authorization_key_id.to_string());
                controller.contains(&controller_value)
            },
            _ => panic!("Invalid did doc controller"),
        };
        if !authorization_key_is_controller {
            panic!("Authorization key is not the controller of the did doc. Please provide a valid controller id")
        }

        let verification_method_reference: String = match log_entry.did_doc["authentication"] {
            JsonArray(ref auth) => {
                auth.iter()
                    .map(|entry| match entry {
                        JsonString(ref auth_method) => {
                            auth_method.to_string()
                        },
                        _ => panic!("Invalid did doc authentication"),
                    })
                    .filter(|entry| entry.starts_with(&authorization_key_id))
                    .collect::<Vec<String>>().first().unwrap().to_string()
            },
            _ => panic!("Invalid did doc authentication"),
        };

        let public_key_multibase = match log_entry.did_doc["verificationMethod"] {
            JsonArray(ref verification_methods) => {
                verification_methods.iter()
                .map(|method| {
                    match method {
                        JsonObject(ref verification_method) => {
                            verification_method
                        },
                        _ => panic!("Invalid did doc verificationMethod"),
                    }
                })
                .filter(|method| method["id"] == verification_method_reference)
                .map(|method| method.get("publicKeyMultibase").unwrap())
                .map(|value| match value {
                    JsonString(ref public_key) => public_key.to_string(),
                    _ => panic!("Invalid did doc verificationMethod"),
                })
                .collect::<Vec<String>>().first().unwrap().to_string()
            },
            _ => panic!("Invalid did doc verificationMethod"),
        };

        if public_key_multibase != verifying_key.to_multibase() {
            panic!("Invalid key pair. The provided key pair is not the one referenced in the did doc")
        }
        verification_method_reference
    }

    /// Add a new entry to the did log file
    /// https://bcgov.github.io/trustdidweb/#create-register
    pub fn update(&mut self, log_entry: DidLogEntry, did_tdw: &str, key_pair: &Ed25519KeyPair) {

        // Identify version id
        let mut index: usize = 1;
        let mut previous_hash = log_entry.entry_hash.clone();
        let mut verification_method = String::new();

        if self.did_log_entries.len() == 0 {
            // Genesis entry (Create)
            // Check if version hash is present
            if log_entry.entry_hash.len() == 0 {
                panic!("For the initial log entry the SCID/previous hash has to be provided")
            }
            verification_method = self.get_verification_method_key(&log_entry, did_tdw, key_pair.get_verifying_key());
        } else {
            // Subsequent entry (Update)
            let previous_entry = self.did_log_entries.last().unwrap();
            // Get new version index
            index = previous_entry.version_id.unwrap() + 1;
            // Get last version hash
            previous_hash = previous_entry.entry_hash.clone();
            verification_method = self.get_verification_method_key(&previous_entry, did_tdw, key_pair.get_verifying_key())
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
        let eddsa_suite = EddsaCryptosuite {
            key_pair: Ed25519KeyPair::from(key_pair.get_signing_key().to_multibase().as_str()),
        };
        let secured_document = eddsa_suite.add_proof(&doc_without_proof.did_doc, &suite_options);
        let doc = DidLogEntry {
            proof: Some(secured_document["proofValue"].to_owned()),
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
pub trait DidMethodOperation {
    fn create(&self, url: String, key_pair: &Ed25519KeyPair) -> String;
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
    #[serde(rename = "publicKeyMultibase")]
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
    pub authentication: Vec<String>,
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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub controller: Vec<String>,
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

        // 3.1.4 Hash didDoc and config
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

pub trait UrlResolver {
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
        match request.send_string(&content) {
            Ok(_) => (),
            Err(e) => panic!("{}", e),
        }
    }
}

pub struct MockResolver {
}
impl UrlResolver for MockResolver {
    fn read(&self, url: String) -> String {
        todo!()
    }
    fn write(&self, url: String, content: String) {
        todo!()
    }
}

/// Convert did:tdw:{method specific identifier} method specific identifier into resolvable url
fn get_url_from_tdw(did_tdw: &String) -> String {
    if !did_tdw.starts_with("did:tdw:") {
        panic!("Invalid did:twd string. It has to start with did:tdw:")
    }
    let did_tdw = did_tdw.replace("did:tdw:","");

    let mut decoded_url = String::from("");
    url_escape::decode_to_string(did_tdw.replace(":", "/"), &mut decoded_url);
    let url = match String::from_utf8(decoded_url.into_bytes()) {
            Ok(url) => {
                if url.starts_with("localhost") {
                    format!("http://{}", url)
                } else {
                    format!("https://{}", url)
                }
            },
            Err(_) => panic!("Couldn't convert did_tdw url to utf8 string"),
    };
    let has_path = regex::Regex::new(r"([a-z]|[0-9])\/([a-z]|[0-9])").unwrap();
    match has_path.captures(url.as_str()) {
        Some(_) => format!("{}/did.json", url),
        None => format!("{}/.well-know/did.json", url),
    }
}

/// Convert domain into did:tdw:{method specific identifier} method specific identifier
fn get_tdw_domain_from_url(url: &String) -> String {
    let mut did = String::from("");
    if url.starts_with("https://") {
        did = url.replace("https://", "");
    } else if url.starts_with("http://localhost") {
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


pub struct TrustDidWebProcessor {
    resolver: Box<dyn UrlResolver>,
}

impl DidMethodOperation for TrustDidWebProcessor {

    fn create(&self, url: String, key_pair: &Ed25519KeyPair) -> String {
        // Check if domain is valid
        let domain = get_tdw_domain_from_url(&url);

        // Create verification method for subject with placeholder
        let did_tdw = format!("did:tdw:{}:{}", domain, utils::SCID_PLACEHOLDER);
        let verification_method_suffix: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let verification_method = VerificationMethod {
            id: format!("{}#{}", &did_tdw, verification_method_suffix),
            controller: did_tdw.clone(),
            verification_type: String::from("Multikey"),
            public_key_multibase: key_pair.verifying_key.to_multibase(),
        };
        // Create initial did doc with placeholder
        let did_doc = DidDoc {
            context: vec![utils::DID_CONTEXT.to_string(), utils::MKEY_CONTEXT.to_string()],
            id: did_tdw.clone(),
            verification_method: vec![verification_method.clone()],
            authentication: vec![format!("did:tdw:{}:{}#{}", domain, utils::SCID_PLACEHOLDER, verification_method_suffix)],
            capability_invocation: vec![],
            capability_delegation: vec![],
            assertion_method: vec![],
            controller: vec![format!("did:tdw:{}:{}", domain, utils::SCID_PLACEHOLDER)]
        };

        // Generate SCID and replace placeholder in did doc
        let scid = self.generate_scid(&did_doc);
        let did_doc_serialize = serde_json::to_string(&did_doc).unwrap();
        let did_doc_with_scid = str::replace(&did_doc_serialize, utils::SCID_PLACEHOLDER, &scid);
        // let did_doc_with_scid = re.replace_all(&did_doc_serialize, &scid).to_string();
        let genesis_did_doc: serde_json::Value = serde_json::from_str(&did_doc_with_scid).unwrap();

        let log_without_proof_and_signature = DidLogEntry::of(
            scid.to_owned(),
            DidMethodParameters::for_genesis_did_doc(scid.to_owned()),
            genesis_did_doc.clone()
        );

        // Initialize did log with genesis did doc
        let mut did_log: DidDocumentState = DidDocumentState::new();
        let did_log_string = match genesis_did_doc["controller"] {
            JsonArray(ref controller) => {
                let controller = match controller.first() {
                    Some(JsonString(ref controller)) => controller.to_string(),
                    _ => panic!("Invalid did doc controller"),
                };
                did_log.update(log_without_proof_and_signature,&controller , key_pair);
                did_log.to_string()
            },
            _ => panic!("Invalid did doc controller"),
        };
        let did = match genesis_did_doc["id"] {
            JsonString(ref did_url) => did_url,
            _ => panic!("Invalid did doc id"),
        };
        self.resolver.write(get_url_from_tdw(&did), did_log_string.to_owned());
        did.to_string()
    }

    fn read(&self, did_tdw: String) -> String {
        let url = get_url_from_tdw(&did_tdw);
        let did_log_raw = self.resolver.read(url);
        let did_doc_state = DidDocumentState::from(did_log_raw);
        did_doc_state.to_string()
    }

    fn update(&self, did_tdw: String, did_doc: String) -> String {
        todo!("Update did string")
    }

    fn deactivate(&self, did_tdw: String) -> String {
        todo!("Deactivate did string")
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

    /// Create verification method object from public key
    fn create_verification_method_from_verifying_key(&self, domain: &String, id_suffix: &String, verifying_key: &Ed25519VerifyingKey) -> VerificationMethod {
        let kid = format!("#{}",id_suffix);
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
        generate_jcs_hash(&json)
    }
}