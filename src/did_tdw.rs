// SPDX-License-Identifier: MIT

use crate::didtoolbox::*;
use crate::ed25519::*;
use crate::utils;
use crate::vc_data_integrity::*;
use chrono::serde::ts_seconds;
use chrono::{DateTime, SecondsFormat, Utc};
use hex;
use regex;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value::{Array as JsonArray, Null, Object as JsonObject, String as JsonString};
use serde_json::{json, Value as JsonValue};
use sha2::Digest;
use ssi::dids::{
    resolution::{
        DIDMethodResolver as SSIDIDMethodResolver, Error as SSIResolutionError,
        Options as SSIOptions, Output as SSIOutput,
    },
    DIDBuf as SSIDIDBuf, DIDMethod as SSIDIDMethod,
};
use std::cmp::PartialEq;
use std::sync::{Arc, LazyLock};
use url_escape;

/// Entry in a did log file as shown here
/// https://identity.foundation/trustdidweb/#term:did-log-entry
/// See https://github.com.mcas.ms/decentralized-identity/trustdidweb/blob/63e21b69d84f7d9344f4e6ef4809e7823975c965/spec/specification.md
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DidLogEntry {
    /// Since v0.2 (see https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
    ///            The new versionId takes the form <version number>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
    pub version_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_index: Option<usize>,
    #[serde(with = "ts_seconds")]
    pub version_time: DateTime<Utc>,
    pub parameters: DidMethodParameters,
    pub did_doc: DidDoc,
    #[serde(skip)]
    pub did_doc_json: String,
    #[serde(skip)]
    pub did_doc_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Vec<DataIntegrityProof>>,
}

impl DidLogEntry {
    /// Import of existing log entry
    pub fn new(
        version_id: String,
        version_index: usize,
        version_time: DateTime<Utc>,
        parameters: DidMethodParameters,
        did_doc: DidDoc,
        did_doc_json: String,
        did_doc_hash: String,
        proof: DataIntegrityProof,
    ) -> Self {
        DidLogEntry {
            version_id,
            version_index: Some(version_index),
            version_time,
            parameters,
            did_doc,
            did_doc_json,
            did_doc_hash,
            proof: Some(vec![proof]),
        }
    }

    /*
    /// Creation of new log entry (with integrity proof)
    pub fn of_with_proof(
        version_id: String,
        parameters: DidMethodParameters,
        did_doc: DidDoc,
        proof: DataIntegrityProof,
    ) -> Self {
        let did_doc_json = serde_json::to_string(&did_doc.normalize()).unwrap();
        let did_doc_hash = utils::hash_canonical(&serde_json::to_value(&did_doc_json).unwrap());
        DidLogEntry {
            version_id,
            version_index: Option::None,
            version_time: Utc::now(),
            parameters,
            did_doc,
            did_doc_json,
            did_doc_hash,
            proof: Some(vec![proof]),
        }
    }

    /// Creation of new log entry (with known version_id and w/out proof)
    pub fn of(version_id: String, parameters: DidMethodParameters, did_doc: DidDoc) -> Self {
        let did_doc_json = serde_json::to_string(&did_doc.normalize()).unwrap();
        let did_doc_hash = utils::hash_canonical(&serde_json::to_value(&did_doc_json).unwrap());
        DidLogEntry {
            version_id,
            version_index: Option::None,
            version_time: Utc::now(),
            parameters,
            did_doc,
            did_doc_json,
            did_doc_hash,
            proof: None,
        }
    }
     */

    /// Check whether the versionId of this log entry is based on the previous versionId
    pub fn verify_version_id_integrity(&self, previous_version_id: &str) {
        let entry_without_proof = DidLogEntry {
            version_id: previous_version_id.to_string(),
            version_index: self.version_index,
            version_time: self.version_time,
            parameters: self.parameters.clone(),
            did_doc: self.did_doc.clone(),
            did_doc_json: self.did_doc_json.clone(),
            did_doc_hash: self.did_doc_hash.clone(),
            proof: None,
        };
        let version_id = entry_without_proof.build_version_id();
        if version_id != self.version_id {
            panic!(
                "Invalid did log. Genesis entry has invalid entry hash: {}. Expected: {}",
                self.version_id, version_id
            );
        }
    }

    /// Check whether the integrity proof matches the content of the did document of this log entry
    pub fn verify_data_integrity_proof(&self) {
        // Verify data integrity proof
        //let verifying_key = self.get_data_integrity_verifying_key(); // may panic

        let proof = match &self.proof {
            None => {
                panic!("Invalid did log. Proof is empty.");
            }
            Some(v) => {
                if v.is_empty() {
                    panic!("Invalid did log. Proof is empty.");
                }
                v.first().unwrap()
            }
        };

        let verifying_key = self.is_key_authorized_for_update(proof.extract_update_key()); // may panic

        /*
        // Check if verifying key is actually a controller and therefore allowed to update the doc => valid key to create the proof
        let controller_keys = self.get_controller_verifying_key();
        if !controller_keys
            .values()
            .any(|(_, key)| key.to_multibase() == verifying_key.to_multibase())
        {
            panic!(
                "Invalid key pair. The provided key pair is not the one referenced in the did doc"
            )
        }
         */

        let eddsa_suite = EddsaCryptosuite {
            verifying_key: Some(verifying_key),
            signing_key: None,
        };

        if eddsa_suite.verify_proof(&proof, &self.did_doc_hash) {
            panic!(
                "Invalid did log. Entry of version {} has invalid data integrity proof",
                self.version_index.unwrap()
            )
        }
    }

    /// The new versionId takes the form <version number>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
    fn build_version_id(&self) -> String {
        // Since v0.2 (see https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
        //            The new versionId takes the form <version number>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
        // Also see https://identity.foundation/trustdidweb/v0.3/#the-did-log-file:
        //            A Data Integrity Proof across the entry, signed by a DID authorized to update the DIDDoc, using the versionId as the challenge.
        format!(
            "{}-{}",
            self.version_index.unwrap(),
            utils::base58btc_encode_multihash(&self.to_log_entry_line())
        )
    }

    /*
    fn get_controller_verifying_key(&self) -> HashMap<String, (String, Ed25519VerifyingKey)> {
        self.did_doc
            .verification_method
            .iter()
            /*.filter(|entry| {
                self.did_doc.controller.iter().any(|controller| {
                    entry.id.starts_with(controller)
                        && entry.verification_type == VerificationType::Ed25519VerificationKey2020
                })
            })*/
            .map(|entry| {
                (
                    entry
                        .id
                        .split("#")
                        .collect::<Vec<&str>>()
                        .first()
                        .unwrap()
                        .to_string(),
                    (
                        entry.id.clone(),
                        Ed25519VerifyingKey::from_multibase(
                            entry.public_key_multibase.as_ref().unwrap(),
                        ),
                    ),
                )
            })
            .collect::<HashMap<String, (String, Ed25519VerifyingKey)>>()
    }
     */

    /*
    fn check_if_verification_method_match_public_key(
        &self,
        did_tdw: &str,
        verifying_key: &Ed25519VerifyingKey,
    ) {
        match self.get_controller_verifying_key().get(did_tdw) {
            Some(public_key) => {
                if public_key.1.to_multibase() != verifying_key.to_multibase() {
                    panic!("Invalid key pair. The provided key pair is not the one referenced in the did doc")
                }
            }
            None => panic!("Invalid did_tdw. The did_tdw is not a controller of the did doc"),
        }
    }
     */

    fn is_key_authorized_for_update(&self, update_key: String) -> Ed25519VerifyingKey {
        match &self.parameters.update_keys {
            Some(update_keys) => {
                if update_keys.is_empty() {
                    panic!("No update keys detected")
                }

                match update_keys
                    .iter()
                    .filter(|entry| *entry == &update_key)
                    .next()
                {
                    Some(_) => {}
                    _ => panic!(
                        "Key extracted from proof is not authorized for update: {}",
                        update_key
                    ),
                };

                Ed25519VerifyingKey::from_multibase(update_key.as_str())
            }
            //None => panic!("No update keys detected"),
            None => Ed25519VerifyingKey::from_multibase(update_key.as_str()),
        }
    }

    /*
    /// Get the verification method id (did_tdw#key-1) and verifying key with which the data integrity proof was created
    pub fn get_data_integrity_verifying_key(&self) -> Ed25519VerifyingKey {
        let proof_verification_method = self.proof.as_ref().unwrap().verification_method.clone();
        let verification_method = self
            .did_doc
            .verification_method
            .iter()
            .filter(|entry| entry.id == proof_verification_method)
            .collect::<Vec<&VerificationMethod>>()
            .first()
            .unwrap()
            .to_owned();

        // Make sure the verification method is part of the authentication section
        if !self
            .did_doc
            .authentication
            .iter()
            .any(|authentication_method| authentication_method.id == verification_method.id)
        {
            panic!("Invalid integrity proof for log with id {}. The verification method used for the integrity proof is not part of the authentication section", self.version_index.unwrap())
        }

        if verification_method.verification_type != VerificationType::Ed25519VerificationKey2020 {
            panic!("Invalid verification method. Only eddsa verification keys are supported")
        }

        Ed25519VerifyingKey::from_multibase(
            verification_method.public_key_multibase.as_ref().unwrap(),
        )
    }
     */

    fn to_log_entry_line(&self) -> JsonValue {
        let did_doc_json_value: JsonValue = serde_json::from_str(&self.did_doc_json).unwrap();
        let version_time = self
            .version_time
            .to_owned()
            .to_rfc3339_opts(SecondsFormat::Secs, true)
            .to_string();
        match &self.proof {
            Some(proof) => json!([
                self.version_id,
                version_time,
                self.parameters,
                {
                    "value": did_doc_json_value
                },
                vec![proof.first().unwrap().json_value()] // should never panic at this point
            ]),
            None => json!([
                self.version_id,
                version_time,
                self.parameters,
                {
                    "value": did_doc_json_value
                }
            ]),
        }
    }

    pub fn get_original_scid(&self, scid: &String) -> String {
        let entry_with_placeholder_without_proof = json!([
            utils::SCID_PLACEHOLDER,
            self.version_time,
            serde_json::from_str::<JsonValue>(&*str::replace(serde_json::to_string(&self.parameters).unwrap().as_str(), scid, utils::SCID_PLACEHOLDER)).unwrap(),
            { "value" : serde_json::from_str::<JsonValue>(&*str::replace(&self.did_doc_json, scid, utils::SCID_PLACEHOLDER)).unwrap()},
        ]);

        utils::base58btc_encode_multihash(&entry_with_placeholder_without_proof)
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
    // Since v0.3 (https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
    //            Removes the cryptosuite parameter, moving it to implied based on the method parameter.
    /*
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cryptosuite: Option<String>,
     */
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub prerotation: Option<bool>,
    #[serde(default)]
    #[serde(rename = "updateKeys", skip_serializing_if = "Option::is_none")]
    pub update_keys: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "nextKeyHashes", skip_serializing_if = "Option::is_none")]
    pub next_keys: Option<Vec<String>>,
    #[serde(default)]
    #[serde(rename = "witnesses", skip_serializing_if = "Option::is_none")]
    pub witnesses: Option<Vec<String>>,
    #[serde(
        rename = "witnessThreshold",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub witness_threshold: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub moved: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub deactivated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ttl: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub portable: Option<bool>,
}

impl DidMethodParameters {
    pub fn for_genesis_did_doc(scid: String, update_key: String) -> Self {
        DidMethodParameters {
            method: Option::Some(String::from(DID_METHOD_PARAMETER_VERSION)),
            scid: Option::Some(scid),
            hash: Option::None,
            // Since v0.3 (https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
            //            Removes the cryptosuite parameter, moving it to implied based on the method parameter.
            /*
            cryptosuite: Option::None,
             */
            prerotation: Option::None,
            //update_keys: Option::None,
            update_keys: Some(vec![update_key]),
            next_keys: Option::None,
            witnesses: Option::None,
            witness_threshold: Option::None,
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
            // Since v0.3 (https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
            //            Removes the cryptosuite parameter, moving it to implied based on the method parameter.
            /*
            cryptosuite: Option::None,
             */
            prerotation: Option::None,
            update_keys: Option::None,
            next_keys: Option::None,
            witnesses: Option::None,
            witness_threshold: Option::None,
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
            // Since v0.3 (https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
            //            Removes the cryptosuite parameter, moving it to implied based on the method parameter.
            /*
            cryptosuite: Option::None,
             */
            prerotation: Option::None,
            update_keys: Option::None,
            next_keys: Option::None,
            witnesses: Option::None,
            witness_threshold: Option::None,
            moved: Option::None,
            deactivated: Option::Some(true),
            ttl: Option::None,
            portable: Option::None,
        }
    }

    pub fn from_json(json_content: &str) -> Self {
        let did_method_parameters: DidMethodParameters = match serde_json::from_str(json_content) {
            Ok(did_method_parameters) => did_method_parameters,
            Err(e) => {
                panic!(
                    "Error parsing DID Document. Make sure the content is correct -> {}",
                    e
                );
            }
        };
        did_method_parameters
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DidDocumentState {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub did_log_entries: Vec<DidLogEntry>,
}

/// As defined by https://identity.foundation/trustdidweb/v0.3/#didtdw-did-method-parameters
const DID_METHOD_PARAMETER_VERSION: &str = "did:tdw:0.3";

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

        let mut current_params: Option<DidMethodParameters> = None;
        let mut current_did_doc: Option<DidDoc> = None;
        let mut did_doc_json: String = "".to_string();
        let mut did_doc_hash: String = "".to_string();
        let mut did_doc_value: JsonValue = Null;
        DidDocumentState {
            did_log_entries: unescaped.split("\n")
                .filter(|line| !line.is_empty())
                .map(|line| {
                    let entry: JsonValue = match serde_json::from_str(line) {
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

                    let version_id = match entry[0] {
                        JsonString(ref id) => id.clone(),
                        _ => panic!("Invalid entry hash"),
                    };
                    // Since v0.2 (see https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
                    //            The new versionId takes the form <version number>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
                    let version_index_as_str: &str;
                    //let entry_hash: &str;
                    match version_id.split_once("-") {
                        Some((index, hash)) => {
                            version_index_as_str = index;
                            //entry_hash = hash;
                        }
                        None => panic!("Invalid entry hash format. The valid format is <version number>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.")
                    }

                    current_params = match entry[2] {
                        JsonObject(ref obj) => {
                            let mut new_params: Option<DidMethodParameters> = None;
                            if !obj.is_empty() {
                                new_params = Some(DidMethodParameters::from_json(&entry[2].to_string()));
                            }
                            if current_params.is_none() && new_params.is_none() {
                                panic!("Missing DID Document parameters.")
                            } else if current_params.is_none() && new_params.is_some() {
                                match new_params.clone().unwrap().method {
                                    Some(method) => {
                                        if method != DID_METHOD_PARAMETER_VERSION {
                                            panic!("Invalid entry method parameter. Expected '{DID_METHOD_PARAMETER_VERSION}'")
                                        }
                                    }
                                    None => panic!("Missing entry 'method' parameter")
                                }
                                new_params // from the initial log entry
                            } else if current_params.is_some() && new_params.is_none() {
                                //current_params.to_owned()
                                Some(DidMethodParameters::empty())
                            } else { // i.e. current_params.is_some() && p.is_some()
                                //let params = current_params.clone().unwrap();
                                let new_params = new_params.unwrap();
                                Some(DidMethodParameters { // kind of merge
                                    method: None,
                                    scid: None,
                                    hash: None,
                                    prerotation: new_params.prerotation, // .or(params.prerotation),
                                    update_keys: new_params.update_keys, // .or(params.update_keys),
                                    next_keys: new_params.next_keys, // .or(params.next_keys),
                                    witnesses: new_params.witnesses, // .or(params.witnesses),
                                    witness_threshold: new_params.witness_threshold, // .or(params.witness_threshold),
                                    moved: new_params.moved,
                                    deactivated: new_params.deactivated, // .or(params.deactivated),
                                    ttl: new_params.ttl,
                                    portable: new_params.portable, // .or(params.portable),
                                })
                            }
                        }
                        _ => {
                            match &current_params {
                                Some(params) => Some(params.to_owned()),
                                None => panic!("Missing DID Document parameters."),
                            }
                        }
                    };

                    current_did_doc = match entry[3] {
                        JsonObject(ref obj) => {
                            did_doc_value = obj["value"].clone();
                            if !did_doc_value.is_null() {
                                did_doc_json = did_doc_value.to_string();
                                did_doc_hash = utils::hash_canonical(&did_doc_value);
                                match serde_json::from_str::<DidDoc>(&did_doc_json) {
                                    Ok(did_doc) => Some(did_doc),
                                    Err(_) => {
                                        match serde_json::from_str::<DidDocNormalized>(&did_doc_json) {
                                            Ok(did_doc_alt) => {
                                                Some(did_doc_alt.to_did_doc())
                                            }
                                            Err(e) => {
                                                panic!("Missing DID document.")
                                            }
                                        }
                                    }
                                }
                            } else {
                                // TODO Lookup for "patch"
                                match &current_did_doc {
                                    Some(did_doc) => Some(did_doc.to_owned()),
                                    None => panic!("Missing DID document."),
                                }
                            }
                        }
                        _ => {
                            match &current_did_doc {
                                Some(did_doc) => Some(did_doc.to_owned()),
                                None => panic!("Missing DID document."),
                            }
                        }
                    };

                    let proof = match entry[4] {
                        JsonArray(ref obj) => {
                            if obj.is_empty() {
                                panic!("Missing DID Document proof.")
                            }
                            DataIntegrityProof::from(entry[4].to_string()) // may panic
                        }
                        _ => panic!("Missing DID Document proof.")
                    };

                    // TODO replace this with toString call of log entry
                    DidLogEntry::new(
                        version_id.clone(),
                        version_index_as_str.parse::<usize>().unwrap(),
                        DateTime::parse_from_rfc3339(entry[1].as_str().unwrap()).unwrap().to_utc(),
                        current_params.clone().unwrap(),
                        current_did_doc.clone().unwrap(),
                        did_doc_json.clone(),
                        did_doc_hash.clone(),
                        proof,
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
                    if entry.version_index.unwrap() != prev.version_index.unwrap() + 1 {
                        panic!(
                            "Invalid did log for version {}. Version id has to be incremented",
                            entry.version_index.unwrap()
                        )
                    }
                    // Verify data integrity proof
                    entry.verify_data_integrity_proof(); // may panic

                    // Verify the entryHash
                    entry.verify_version_id_integrity(&prev.version_id); // may panic
                    previous_entry = Some(entry.clone());
                }
                None => {
                    // First / genesis entry in did log
                    let genesis_entry = self.did_log_entries.first().unwrap();
                    if genesis_entry.version_index.unwrap() != 1 {
                        panic!("Invalid did log. First entry has to have version id 1")
                    }

                    // Verify data integrity proof
                    genesis_entry.verify_data_integrity_proof(); // may panic

                    // Verify the entryHash
                    genesis_entry.verify_version_id_integrity(
                        genesis_entry.parameters.scid.as_ref().unwrap(),
                    ); // may panic

                    // Verify that the SCID is correct
                    let scid = genesis_entry.parameters.scid.clone().unwrap();
                    if let Some(res) = &scid_to_validate {
                        if res.ne(scid.as_str()) {
                            panic!("The scid from the did doc {scid} does not match the requested one {res}")
                        }
                    }

                    if genesis_entry.get_original_scid(&scid) != scid {
                        panic!("Invalid did log. Genesis entry has invalid SCID")
                    }
                    previous_entry = Some(genesis_entry.clone());
                }
            };
        }
        match previous_entry {
            Some(entry) => entry.did_doc.clone().into(),
            None => panic!("Invalid did log. No entries found"),
        }
    }

    /// Checks if all entries in the did log are valid (data integrity, versioning etc.)
    pub fn validate(&self) -> Arc<DidDoc> {
        self.validate_with_scid(None) // may panic
    }

    /*
    /// Add a new entry to the did log file
    /// https://bcgov.github.io/trustdidweb/#create-register
    pub fn update(&mut self, log_entry: DidLogEntry, did_tdw: &str, key_pair: &Ed25519KeyPair) {
        // Identify version id
        let mut index: usize = 1;
        let mut previous_version_id = log_entry.version_id.clone();
        let mut verification_method = String::new();

        // Make sure only activated did docs can be updated

        if self.did_log_entries.is_empty() {
            // Genesis entry (Create)
            // Check if version hash is present
            if log_entry.version_id.is_empty() {
                panic!("For the initial log entry the SCID/previous hash has to be provided")
            }
            log_entry.check_if_verification_method_match_public_key(
                did_tdw,
                key_pair.get_verifying_key().as_ref(),
            ); // may panic
            verification_method = log_entry
                .get_controller_verifying_key()
                .get(did_tdw)
                .unwrap()
                .0
                .clone();
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
            if let Some(true) = previous_entry.did_doc.deactivated {
                panic!("Invalid did doc. The did doc is already deactivated. For simplicity reasons we don't allow updates of dids")
            }

            // Get new version index
            index = previous_entry.version_index.unwrap() + 1;
            // Get last version hash
            previous_version_id = previous_entry.version_id.clone();
            previous_entry.check_if_verification_method_match_public_key(
                did_tdw,
                key_pair.get_verifying_key().as_ref(),
            ); // may panic
            verification_method = log_entry
                .get_controller_verifying_key()
                .get(did_tdw)
                .unwrap()
                .0
                .clone();
        }

        // Generate new hash and use it as versionId and integrity challenge
        let doc_without_version_id = DidLogEntry {
            version_index: Some(index),
            version_id: previous_version_id,
            did_doc_json: log_entry.did_doc_json.clone(),
            did_doc_hash: log_entry.did_doc_hash.clone(),
            ..log_entry
        };
        let integrity_challenge = doc_without_version_id.build_version_id();
        let doc_without_proof = DidLogEntry {
            version_id: integrity_challenge.clone(),
            ..doc_without_version_id
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
        let proof_value_string = json!([secured_document["proof"]]);
        let doc = DidLogEntry {
            proof: Some(vec![DataIntegrityProof::from(serde_json::to_string(&proof_value_string).unwrap())]),
            ..doc_without_proof
        };
        self.did_log_entries.push(doc);
    }
     */
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

/*
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
    fn update(
        &self,
        did_tdw: String,
        did_doc: String,
        key_pair: &Ed25519KeyPair,
        allow_http: Option<bool>,
    ) -> String;
    /// See https://identity.foundation/trustdidweb/#deactivate-revoke
    fn deactivate(
        &self,
        did_tdw: String,
        key_pair: &Ed25519KeyPair,
        allow_http: Option<bool>,
    ) -> String;
}
 */

/// Convert domain into did:tdw:{method specific identifier} method specific identifier
pub fn get_tdw_domain_from_url(
    url: &String,
    allow_http: Option<bool>,
) -> Result<String, TrustDidWebError> {
    let mut did = String::from("");
    if url.starts_with("https://") {
        did = url.replace("https://", "");
    } else if url.starts_with("http://localhost")
        || url.starts_with("http://127.0.0.1")
        || allow_http.unwrap_or(false)
    {
        did = url.replace("http://", "");
    } else {
        return Err(TrustDidWebError::InvalidMethodSpecificId(String::from(
            "Invalid url. Only https is supported",
        )));
    }

    if did.contains(".well-known") {
        return Err(TrustDidWebError::InvalidMethodSpecificId(String::from(
            "Invalid url. Please remove .well-known from url",
        )));
    }
    if did.contains("did.jsonl") {
        return Err(TrustDidWebError::InvalidMethodSpecificId(String::from(
            "Invalid url. Please remove did.json from url",
        )));
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
            Self::InvalidMethodSpecificId(_) => {
                TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId
            }
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

static HAS_PATH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([a-z]|[0-9])\/([a-z]|[0-9])").unwrap());
static HAS_PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\:[0-9]+").unwrap());

impl TrustDidWebId {
    /// Yet another UniFFI-compliant method.
    ///
    /// Otherwise, the idiomatic counterpart (try_from(value: (String, Option<bool>)) -> Result<Self, Self::Error>) may be used as well.
    pub fn parse_did_tdw(
        did_tdw: String,
        allow_http: Option<bool>,
    ) -> Result<Self, TrustDidWebIdResolutionError> {
        match Self::try_from((did_tdw, allow_http)) {
            Ok(parsed) => Ok(parsed),
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
                    return Err(TrustDidWebIdResolutionError::MethodNotSupported(
                        buf.method_name().to_owned(),
                    ));
                };

                match buf.method_specific_id().split_once(":") {
                    Some((scid, did_tdw_reduced)) => {
                        if !scid.starts_with("Q") {
                            panic!(
                                "Invalid multibase format for SCID. base58btc identifier expected"
                            );
                        }
                        let mut decoded_url = String::from("");
                        url_escape::decode_to_string(
                            did_tdw_reduced.replace(":", "/"),
                            &mut decoded_url,
                        );

                        let url = match String::from_utf8(decoded_url.into_bytes()) {
                            Ok(url) => {
                                if url.starts_with("localhost")
                                    || url.starts_with("127.0.0.1")
                                    || allow_http.unwrap_or(false)
                                {
                                    format!("http://{}", url)
                                } else {
                                    format!("https://{}", url)
                                }
                            }
                            Err(_) => {
                                return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                                    did_tdw_reduced.to_string(),
                                ))
                            }
                        };
                        if HAS_PATH_REGEX.captures(url.as_str()).is_some()
                            || HAS_PORT_REGEX.captures(url.as_str()).is_some()
                        {
                            Ok(Self {
                                scid: scid.to_string(),
                                url: format!("{}/did.jsonl", url),
                            })
                        } else {
                            Ok(Self {
                                scid: scid.to_string(),
                                url: format!("{}/.well-known/did.jsonl", url),
                            })
                        }
                    }
                    None => Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                        buf.method_specific_id().to_owned(),
                    )),
                }
            }
            Err(_) => Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                did_tdw,
            )),
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
    #[error("The supplied did doc is invalid or contains an argument which isn't part of the did specification/recommendation: {0}"
    )]
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
    pub fn new(did: String, did_log: String, did_doc: String) -> Self {
        Self {
            did,
            did_log,
            did_doc,
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

    pub fn read(
        did_tdw: String,
        did_log: String,
        allow_http: Option<bool>,
    ) -> Result<Self, TrustDidWebError> {
        let did_doc_state = DidDocumentState::from(did_log); // may panic
        let scid = match TrustDidWebId::parse_did_tdw(did_tdw.to_owned(), allow_http) {
            Ok(tdw_id) => tdw_id.get_scid(),
            Err(e) => return Err(TrustDidWebError::InvalidMethodSpecificId(e.to_string())),
        };
        let did_doc_arc = did_doc_state.validate_with_scid(Some(scid.to_owned())); // may panic
        let did_doc = did_doc_arc.as_ref().clone();
        let did_doc_str = match serde_json::to_string(&did_doc) {
            Ok(v) => v,
            Err(e) => return Err(TrustDidWebError::SerializationFailed(e.to_string())),
        };
        Ok(Self {
            did: did_doc.id,
            did_log: did_doc_state.to_string(), // DidDocumentState implements std::fmt::Display trait
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
