// SPDX-License-Identifier: MIT

use crate::didtoolbox::*;
use crate::ed25519::*;
use crate::errors::*;
use crate::jcs_sha256_hasher::JcsSha256Hasher;
use crate::vc_data_integrity::*;
use chrono::serde::ts_seconds;
use chrono::{DateTime, SecondsFormat, Utc};
use regex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value::{Array as JsonArray, Object as JsonObject, String as JsonString};
use serde_json::{
    from_str as json_from_str, json, to_string as json_to_string, Value as JsonValue,
};
use std::cmp::PartialEq;
use std::sync::{Arc, LazyLock};
use url_escape;

pub const SCID_PLACEHOLDER: &str = "{SCID}";

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
    #[serde(skip)]
    prev_entry: Option<Box<DidLogEntry>>, // Box-ed to prevent "recursive without indirection"
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
        prev_entry: Option<Box<DidLogEntry>>,
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
            prev_entry,
        }
    }

    /// Check whether the versionId of this log entry is based on the previous versionId
    pub fn verify_version_id_integrity(
        &self,
        previous_version_id: &str,
    ) -> Result<(), TrustDidWebError> {
        let entry_without_proof = DidLogEntry {
            version_id: previous_version_id.to_string(),
            version_index: self.version_index,
            version_time: self.version_time,
            parameters: self.parameters.clone(),
            did_doc: self.did_doc.clone(),
            did_doc_json: self.did_doc_json.clone(),
            did_doc_hash: self.did_doc_hash.clone(),
            proof: None,
            prev_entry: None,
        };
        let version_id = entry_without_proof.build_version_id().map_err(|err| {
            TrustDidWebError::InvalidDataIntegrityProof(format!(
                "Failed to build versionId: {}",
                err
            ))
        })?;
        if version_id != self.version_id {
            return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                "Invalid DID log. The DID log entry has invalid entry hash: {}. Expected: {}",
                self.version_id, version_id
            )));
        }
        Ok(())
    }

    /// Check whether the integrity proof matches the content of the did document of this log entry
    pub fn verify_data_integrity_proof(&self) -> Result<(), TrustDidWebError> {
        match &self.proof {
            None => {
                return Err(TrustDidWebError::InvalidDataIntegrityProof(
                    "Invalid did log. Proof is empty.".to_string(),
                ))
            }
            Some(v) => {
                if v.is_empty() {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "Invalid did log. Proof is empty.".to_string(),
                    ));
                }

                let prev = match self.prev_entry.as_ref() {
                    None => self,
                    //Some(_) => &prev_entry.clone().unwrap()
                    Some(e) => e,
                };
                for proof in v {
                    let verifying_key =
                        prev.is_key_authorized_for_update(proof.extract_update_key()?)?;

                    if !matches!(proof.crypto_suite_type, Some(CryptoSuiteType::EddsaJcs2022)) {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                            "Unsupported proof's cryptosuite {}",
                            proof.crypto_suite
                        )));
                    }

                    let cryptosuite = EddsaJcs2022Cryptosuite {
                        verifying_key: Some(verifying_key),
                        signing_key: None,
                    };

                    cryptosuite.verify_proof(proof, None, self.did_doc_hash.as_str())?
                }
            }
        };
        Ok(())
    }

    /// The new versionId takes the form \<version number\>-\<entryHash\>, where \<version number\> is the incrementing integer of version of the entry: 1, 2, 3, etc.
    fn build_version_id(&self) -> serde_json::Result<String> {
        // Since v0.2 (see https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
        //            The new versionId takes the form <version number>-<entry_hash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
        // Also see https://identity.foundation/trustdidweb/v0.3/#the-did-log-file:
        //            A Data Integrity Proof across the entry, signed by a DID authorized to update the DIDDoc, using the versionId as the challenge.
        let entry_hash =
            JcsSha256Hasher::default().base58btc_encode_multihash(&self.to_log_entry_line())?;
        Ok(format!("{}-{}", self.version_index.unwrap(), entry_hash))
    }

    fn is_key_authorized_for_update(
        &self,
        update_key: String,
    ) -> Result<Ed25519VerifyingKey, TrustDidWebError> {
        match &self.parameters.update_keys {
            Some(update_keys) => {
                if update_keys.is_empty() {
                    return Err(TrustDidWebError::InvalidDataIntegrityProof(
                        "No update keys detected".to_string(),
                    ));
                }

                match update_keys.iter().find(|entry| *entry == &update_key) {
                    Some(_) => {}
                    _ => {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                            "Key extracted from proof is not authorized for update: {}",
                            update_key
                        )))
                    }
                };

                Ok(Ed25519VerifyingKey::from_multibase(update_key.as_str())?)
            }
            None => {
                let prev_entry = match self.prev_entry.to_owned() {
                    Some(e) => e,
                    _ => {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(
                            "No update keys detected".to_string(),
                        ));
                    }
                };
                prev_entry.is_key_authorized_for_update(update_key) // recursive call
            }
        }
    }

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

    pub fn get_original_scid(&self, scid: &String) -> serde_json::Result<String> {
        let entry_with_placeholder_without_proof = json!([
            SCID_PLACEHOLDER,
            self.version_time,
            json_from_str::<JsonValue>(str::replace(json_to_string(&self.parameters).unwrap().as_str(), scid, SCID_PLACEHOLDER).as_str()).unwrap(),
            { "value" : json_from_str::<JsonValue>(str::replace(&self.did_doc_json, scid, SCID_PLACEHOLDER).as_str()).unwrap()},
        ]);

        let hash = JcsSha256Hasher::default()
            .base58btc_encode_multihash(&entry_with_placeholder_without_proof)?;
        Ok(hash)
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

    fn merge_from(&mut self, other: &DidMethodParameters) {
        let _other = other.to_owned();
        self.method = _other.method.or(self.method.to_owned());
        self.scid = _other.scid.or(self.scid.to_owned());
        self.hash = _other.hash.or(self.hash.to_owned());
        self.prerotation = _other.prerotation.or(self.prerotation.to_owned());
        self.update_keys = _other.update_keys.or(self.update_keys.to_owned());
        self.next_keys = _other.next_keys.or(self.next_keys.to_owned());
        self.witnesses = _other.witnesses.or(self.witnesses.to_owned());
        self.witness_threshold = _other.witness_threshold.or(self.witness_threshold.to_owned());
        self.moved = _other.moved.or(self.moved.to_owned());
        self.deactivated = _other.deactivated.or(self.deactivated.to_owned());
        self.ttl = _other.ttl.or(self.ttl.to_owned());
        self.portable = _other.portable.or(self.portable.to_owned());
    }

    /// As specified by https://identity.foundation/didwebvh/v0.3/#deactivate-revoke
    fn deactivate(&mut self) {
        self.update_keys = Some(vec![]);
        self.deactivated = Some(true);
    }

    pub fn from_json(json_content: &str) -> Result<Self, TrustDidWebError> {
        let did_method_parameters: DidMethodParameters = match serde_json::from_str(json_content) {
            Ok(did_method_parameters) => did_method_parameters,
            Err(err) => {
                return Err(TrustDidWebError::DeserializationFailed(format!(
                    "Error parsing DID method parameters: {}",
                    err
                )));
            }
        };
        Ok(did_method_parameters)
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
    /*
    pub(crate) fn default() -> Self {
        DidDocumentState {
            did_log_entries: Vec::new(),
        }
    }
     */

    pub fn from(did_log: String) -> Result<Self, TrustDidWebError> {
        let mut unescaped = did_log.clone();
        if unescaped.contains("\\\"") {
            unescaped = serde_json::from_str(&did_log).unwrap()
        }

        let mut current_params: Option<DidMethodParameters> = None;
        let mut prev_entry: Option<Box<DidLogEntry>> = None;
        let mut is_deactivated: bool = false;
        Ok(DidDocumentState {
            did_log_entries: unescaped.split("\n")
                .filter(|line| !line.is_empty())
                .map(|line| {
                    if is_deactivated {
                        return Err(TrustDidWebError::InvalidDidDocument(
                            "Already deactivated".to_string(),
                        ));
                    }

                    let entry: JsonValue = match serde_json::from_str(line) {
                        Ok(entry) => entry,
                        Err(err) => return Err(TrustDidWebError::DeserializationFailed(
                            format!("{}", err)
                        )),
                    };
                    match entry {
                        JsonArray(ref entry) => {
                            if entry.len() < 5 {
                                return Err(TrustDidWebError::DeserializationFailed(
                                    format!("Invalid did log entry. Expected at least 5 elements but got {}", entry.len()),
                                ));
                            }
                        }
                        _ => return Err(TrustDidWebError::DeserializationFailed(
                            "Invalid did log entry. Expected array".to_string(),
                        ))
                    }

                    let version_id = match entry[0] {
                        JsonString(ref id) => id.clone(),
                        _ => return Err(TrustDidWebError::DeserializationFailed(
                            "Invalid entry hash".to_string(),
                        ))
                    };
                    // Since v0.2 (see https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
                    //            The new versionId takes the form <version number>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
                    let (version_index_as_str, _) = match version_id.split_once("-") {
                        Some((index, hash)) => (index, hash),
                        None => return Err(TrustDidWebError::DeserializationFailed(
                            "Invalid entry hash format. The valid format is <version number>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.".to_string(),
                        ))
                    };

                    let mut new_params: Option<DidMethodParameters> = None;
                    current_params = match entry[2] {
                        JsonObject(ref obj) => {
                            if !obj.is_empty() {
                                new_params = Some(DidMethodParameters::from_json(&entry[2].to_string())?);
                            }
                            if current_params.is_none() && new_params.is_none() {
                                return Err(TrustDidWebError::DeserializationFailed(
                                    "Missing DID Document parameters.".to_string(),
                                ));
                            } else if current_params.is_none() && new_params.is_some() {
                                match new_params.clone().unwrap().method {
                                    Some(method) => {
                                        if method != DID_METHOD_PARAMETER_VERSION {
                                            return Err(TrustDidWebError::DeserializationFailed(
                                                "Invalid entry method parameter. Expected '{DID_METHOD_PARAMETER_VERSION}'".to_string(),
                                            ));
                                        }
                                    }
                                    None => return Err(TrustDidWebError::DeserializationFailed(
                                        "Missing entry 'method' parameter".to_string(),
                                    ))
                                }
                                new_params.to_owned() // from the initial log entry
                            } else if current_params.is_some() && new_params.is_none() {
                                Some(DidMethodParameters::empty())
                            } else { // i.e. current_params.is_some() && p.is_some()
                                let mut _current_params = current_params.to_owned().unwrap();
                                _current_params.merge_from(&new_params.to_owned().unwrap());
                                Some(_current_params)
                            }
                        }
                        _ => {
                            match &current_params {
                                Some(params) => Some(params.to_owned()),
                                None => return Err(TrustDidWebError::DeserializationFailed(
                                    "Missing DID Document parameters.".to_string(),
                                ))
                            }
                        }
                    };

                    is_deactivated = current_params.to_owned().is_some_and(|p| p.deactivated.is_some_and(|d| d));
                    if is_deactivated {
                        // https://identity.foundation/didwebvh/v0.3/#deactivate-revoke:
                        // To deactivate the DID, the DID Controller SHOULD add to the DID log entry parameters the item "deactivated": true.
                        // A DID MAY update the DIDDoc further to indicate the deactivation of the DID,
                        // such as including an empty updateKeys list ("updateKeys": []) in the parameters,
                        // preventing further versions of the DID.
                        if current_params.is_some() {
                            let mut _current_params = current_params.to_owned().unwrap();
                            _current_params.deactivate();
                            current_params = Some(_current_params);
                        }
                    }

                    let mut did_doc_hash: String = "".to_string();
                    let mut current_did_doc: Option<DidDoc> = None;
                    let mut did_doc_json: String = "".to_string();

                    current_did_doc = match entry[3] {
                        JsonObject(ref obj) => {
                            if obj.contains_key("value") {
                                let did_doc_value: JsonValue = obj["value"].to_owned();
                                if !did_doc_value.is_null() {
                                    did_doc_json = did_doc_value.to_string();
                                    did_doc_hash = JcsSha256Hasher::default().encode_hex(&did_doc_value).unwrap();
                                    match serde_json::from_str::<DidDoc>(&did_doc_json) {
                                        Ok(did_doc) => Some(did_doc),
                                        Err(_) => {
                                            match serde_json::from_str::<DidDocNormalized>(&did_doc_json) {
                                                Ok(did_doc_alt) => {
                                                    let doc = did_doc_alt.to_did_doc()?;
                                                    Some(doc)
                                                }
                                                Err(err) => return Err(TrustDidWebError::DeserializationFailed(
                                                    format!("Missing DID document: {}", err)
                                                ))
                                            }
                                        }
                                    }
                                } else {
                                    match &current_did_doc {
                                        Some(did_doc) => Some(did_doc.to_owned()),
                                        None => return Err(TrustDidWebError::DeserializationFailed(
                                            "Missing DID Document.".to_string(),
                                        ))
                                    }
                                }
                            } else if obj.contains_key("patch") {
                                return Err(TrustDidWebError::DeserializationFailed(
                                        "Missing DID Document. JSON 'patch' is not supported.".to_string(),
                                    ))
                            } else {
                                return Err(TrustDidWebError::DeserializationFailed(
                                    "Missing DID Document. No 'value' detected.".to_string(),
                                ))
                            }
                        }
                        _ => {
                            match &current_did_doc {
                                Some(did_doc) => Some(did_doc.to_owned()),
                                None => return Err(TrustDidWebError::DeserializationFailed(
                                    "Missing DID Document.".to_string(),
                                ))
                            }
                        }
                    };

                    let proof = match entry[4] {
                        JsonArray(ref obj) => {
                            if obj.is_empty() {
                                return Err(TrustDidWebError::DeserializationFailed(
                                    "Missing DID Document proof.".to_string(),
                                ));
                            }
                            DataIntegrityProof::from(entry[4].to_string())?
                        }
                        _ => return Err(TrustDidWebError::DeserializationFailed(
                            "Missing DID Document proof.".to_string(),
                        ))
                    };

                    let current_entry = DidLogEntry::new(
                        version_id.clone(),
                        version_index_as_str.parse::<usize>().unwrap(),
                        DateTime::parse_from_rfc3339(entry[1].as_str().unwrap()).unwrap().to_utc(),
                        new_params.unwrap(),
                        current_did_doc.clone().unwrap(),
                        did_doc_json.clone(),
                        did_doc_hash.clone(),
                        proof,
                        prev_entry.clone(),
                    );
                    prev_entry = Some(Box::from(current_entry.clone()));

                    Ok(current_entry)
                }).collect::<Result<Vec<DidLogEntry>, TrustDidWebError>>()?
        })
    }

    pub fn current(&self) -> &DidLogEntry {
        let last_entry = self.did_log_entries.last().unwrap();
        last_entry
    }

    /// Checks if all entries in the did log are valid (data integrity, versioning etc.)
    pub fn validate_with_scid(
        &self,
        scid_to_validate: Option<String>,
    ) -> Result<Arc<DidDoc>, TrustDidWebError> {
        let mut previous_entry: Option<DidLogEntry> = None;
        for entry in &self.did_log_entries {
            match previous_entry {
                Some(ref prev) => {
                    // Check if version has incremented
                    if entry.version_index.unwrap() != prev.version_index.unwrap() + 1 {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                            "Invalid did log for version {}. Version id has to be incremented",
                            entry.version_index.unwrap()
                        )));
                    }
                    // Verify data integrity proof
                    entry.verify_data_integrity_proof()?;

                    // Verify the entryHash
                    entry.verify_version_id_integrity(&prev.version_id)?;
                    previous_entry = Some(entry.clone());
                }
                None => {
                    // First / genesis entry in did log
                    let genesis_entry = self.did_log_entries.first().unwrap();
                    if genesis_entry.version_index.unwrap() != 1 {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(
                            "Invalid did log. First entry has to have version id 1".to_string(),
                        ));
                    }

                    // Verify data integrity proof
                    genesis_entry.verify_data_integrity_proof()?;

                    // Verify the entryHash
                    genesis_entry.verify_version_id_integrity(
                        genesis_entry.parameters.scid.as_ref().unwrap(),
                    )?;

                    // Verify that the SCID is correct
                    let scid = genesis_entry.parameters.scid.clone().unwrap();
                    if let Some(res) = &scid_to_validate {
                        if res.ne(scid.as_str()) {
                            return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                                "The scid from the did doc {} does not match the requested one {}",
                                scid, res
                            )));
                        }
                    }

                    let original_scid = genesis_entry.get_original_scid(&scid).map_err(|err| {
                        TrustDidWebError::InvalidDataIntegrityProof(format!(
                            "Failed to build original SCID: {}",
                            err
                        ))
                    })?;
                    if original_scid != scid {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(
                            "Invalid did log. Genesis entry has invalid SCID".to_string(),
                        ));
                    }
                    previous_entry = Some(genesis_entry.clone());
                }
            };
        }
        match previous_entry {
            Some(entry) => Ok(entry.did_doc.into()),
            None => Err(TrustDidWebError::InvalidDataIntegrityProof(
                "Invalid did log. No entries found".to_string(),
            )),
        }
    }

    /// Checks if all entries in the did log are valid (data integrity, versioning etc.)
    pub fn validate(&self) -> Result<Arc<DidDoc>, TrustDidWebError> {
        self.validate_with_scid(None)
    }
}

impl std::fmt::Display for DidDocumentState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut log = String::new();
        for entry in &self.did_log_entries {
            let serialized = entry.to_log_entry_line();
            log.push_str(serde_json::to_string(&serialized).unwrap().as_str());
            log.push('\n');
        }
        write!(f, "{}", log)
    }
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
    const DID_METHOD_NAME: &'static str = "tdw";

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

        let split: Vec<&str> = did_tdw.splitn(3, ":").collect();
        if split.len() < 3 || split[2].is_empty() {
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                did_tdw,
            ));
        };

        let method_name = format!("{}:{}", split[0], split[1]);
        if method_name != format!("did:{}", Self::DID_METHOD_NAME) {
            return Err(TrustDidWebIdResolutionError::MethodNotSupported(
                method_name,
            ));
        };
        let scid = split[2];
        /* TODO Ensure the SCID is encoded properly
        if !scid.starts_with("Q") {
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                String::from("Invalid multibase format for SCID. base58btc identifier expected"),
            ));
        }
         */
        let mut decoded_url = String::from("");
        match scid.split_once(":") {
            Some((scid, did_tdw_reduced)) => {
                url_escape::decode_to_string(did_tdw_reduced.replace(":", "/"), &mut decoded_url);
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
                did_tdw,
            )),
        }
    }
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
        let did_doc_state = DidDocumentState::from(did_log)?;
        let did = TrustDidWebId::parse_did_tdw(did_tdw.to_owned(), allow_http)
            .map_err(|err| TrustDidWebError::InvalidMethodSpecificId(format!("{}", err)))?;
        let scid = did.get_scid();
        let did_doc_arc = did_doc_state.validate_with_scid(Some(scid.to_owned()))?;
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
