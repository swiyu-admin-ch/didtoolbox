// SPDX-License-Identifier: MIT

use crate::did_tdw_parameters::*;
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
use url::Url;
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
    #[serde(skip)]
    pub version_index: usize,
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
    prev_entry: Option<Arc<DidLogEntry>>, // Arc-ed to prevent "recursive without indirection"
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
        prev_entry: Option<Arc<DidLogEntry>>,
    ) -> Self {
        DidLogEntry {
            version_id,
            version_index,
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
    pub fn verify_version_id_integrity(&self) -> Result<(), TrustDidWebError> {
        let version_id = self.build_version_id().map_err(|err| {
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

                    cryptosuite.verify_proof(proof, self.did_doc_hash.as_str())?
                }
            }
        };
        Ok(())
    }

    /// The new versionId takes the form \<version number\>-\<entryHash\>, where \<version number\> is the incrementing integer of version of the entry: 1, 2, 3, etc.
    pub fn build_version_id(&self) -> Result<String, TrustDidWebError> {
        // Since v0.2 (see https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
        //            The new versionId takes the form <version number>-<entry_hash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
        // Also see https://identity.foundation/trustdidweb/v0.3/#the-did-log-file:
        //            A Data Integrity Proof across the entry, signed by a DID authorized to update the DIDDoc, using the versionId as the challenge.
        let prev_version_id = match &self.prev_entry {
            Some(v) => v.version_id.clone(),
            None => match self.parameters.scid.clone() {
                Some(v) => v,
                None => {
                    return Err(TrustDidWebError::DeserializationFailed(
                        "Error extracting scid".to_string(),
                    ))
                }
            },
        };

        let entry_without_proof = DidLogEntry {
            version_id: prev_version_id,
            version_index: self.version_index,
            version_time: self.version_time,
            parameters: self.parameters.clone(),
            did_doc: self.did_doc.clone(),
            did_doc_json: self.did_doc_json.clone(),
            did_doc_hash: self.did_doc_hash.clone(),
            proof: None,
            prev_entry: None,
        };
        let entry_line = entry_without_proof.to_log_entry_line()?;
        let entry_hash = JcsSha256Hasher::default()
            .base58btc_encode_multihash(&entry_line)
            .map_err(|err| {
                TrustDidWebError::SerializationFailed(format!(
                    "Failed to encode multihash: {}",
                    err
                ))
            })?;

        Ok(format!("{}-{}", self.version_index, entry_hash))
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

    fn to_log_entry_line(&self) -> Result<JsonValue, TrustDidWebError> {
        let did_doc_json_value: JsonValue = match serde_json::from_str(&self.did_doc_json) {
            Ok(v) => v,
            Err(err) => return Err(TrustDidWebError::DeserializationFailed(format!("{}", err))),
        };

        let version_time = self
            .version_time
            .to_owned()
            .to_rfc3339_opts(SecondsFormat::Secs, true)
            .to_string();
        match &self.proof {
            Some(proof) => {
                let first_proof = match proof.first() {
                    Some(v) => v,
                    None => {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(
                            "Invalid did log. Proof is empty.".to_string(),
                        ))
                    }
                };

                Ok(json!([
                    self.version_id,
                    version_time,
                    self.parameters,
                    {
                        "value": did_doc_json_value
                    },
                    vec![first_proof.json_value()?]
                ]))
            }
            None => Ok(json!([
                self.version_id,
                version_time,
                self.parameters,
                {
                    "value": did_doc_json_value
                }
            ])),
        }
    }

    fn build_original_scid(&self, scid: &String) -> serde_json::Result<String> {
        let entry_with_placeholder_without_proof = json!([
            SCID_PLACEHOLDER,
            self.version_time,
            json_from_str::<JsonValue>(str::replace(json_to_string(&self.parameters)?.as_str(), scid, SCID_PLACEHOLDER).as_str())?,
            { "value" : json_from_str::<JsonValue>(str::replace(&self.did_doc_json, scid, SCID_PLACEHOLDER).as_str())?},
        ]);

        let hash = JcsSha256Hasher::default()
            .base58btc_encode_multihash(&entry_with_placeholder_without_proof)?;
        Ok(hash)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DidDocumentState {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub did_log_entries: Vec<DidLogEntry>,
}

impl DidDocumentState {
    /*
    pub(crate) fn default() -> Self {
        DidDocumentState {
            did_log_entries: Vec::new(),
        }
    }
     */

    pub fn from(did_log: String) -> Result<Self, TrustDidWebError> {
        let unescaped = did_log.clone();

        let mut current_params: Option<DidMethodParameters> = None;
        let mut prev_entry: Option<Arc<DidLogEntry>> = None;

        let mut is_deactivated: bool = false;

        Ok(DidDocumentState {
            did_log_entries: unescaped.split("\n")
                .filter(|line| !line.is_empty())
                .map(|line| {
                    if is_deactivated {
                        return Err(TrustDidWebError::InvalidDidDocument(
                            "This DID document is already deactivated. Therefore no additional DID logs are allowed.".to_string()
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
                    //            The new versionId takes the form <versionNumber>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.
                    let version_index: usize = match version_id.split_once("-") {
                        Some((index, _)) => {
                            match index.parse::<usize>() {
                                Ok(index) => index,
                                Err(_) => return Err(TrustDidWebError::DeserializationFailed(
                                    "The entry hash format (<versionNumber>-<entryHash>) is valid. However, the <versionNumber> is not an (unsigned) integer.".to_string(),
                                ))
                            }
                        }
                        None => return Err(TrustDidWebError::DeserializationFailed(
                            "Invalid entry hash format. The valid format is <versionNumber>-<entryHash>, where <version number> is the incrementing integer of version of the entry: 1, 2, 3, etc.".to_string(),
                        ))
                    };

                    // https://identity.foundation/didwebvh/v0.3/#the-did-log-file:
                    // The versionTime (as stated by the DID Controller) of the entry,
                    // in ISO8601 format (https://identity.foundation/didwebvh/v0.3/#term:iso8601).
                    let version_time = match entry[1] {
                        JsonString(ref dt) => {
                            match DateTime::parse_from_rfc3339(dt) {
                                Ok(x) => x.to_utc(),
                                Err(_) => return Err(TrustDidWebError::DeserializationFailed("Invalid versionTime. String representation of a datetime in ISO8601 format required.".to_string()))
                            }
                        }
                        _ => return Err(TrustDidWebError::DeserializationFailed("Invalid versionTime. String representation of a datetime in ISO8601 format required.".to_string()))
                    };

                    let mut new_params: Option<DidMethodParameters> = None;
                    current_params = match entry[2] {
                        JsonObject(ref obj) => {
                            if !obj.is_empty() {
                                new_params = Some(DidMethodParameters::from_json(&entry[2].to_string())?);
                            }

                            match (current_params.clone(), new_params.clone()) {
                                (None, None) => return Err(TrustDidWebError::DeserializationFailed(
                                    "Missing DID Document parameters.".to_string(),
                                )),
                                (None, Some(new_params)) => {
                                    // this is the first entry, therefore we check for the base configuration
                                    new_params.validate_initial()?;

                                    Some(new_params) // from the initial log entry
                                }
                                (Some(current_params), None) => {
                                    new_params = Some(DidMethodParameters::empty());
                                    Some(current_params.to_owned())
                                }
                                (Some(current_params), Some(new_params)) => {
                                    let mut _current_params = current_params.to_owned();
                                    _current_params.merge_from(&new_params)?;
                                    Some(_current_params)
                                }
                            }
                        }
                        _ => {
                            return Err(TrustDidWebError::DeserializationFailed(
                                "Missing DID Document parameters.".to_string(),
                            ))
                        }
                    };

                    is_deactivated = current_params.to_owned().is_some_and(|p| p.deactivated.is_some_and(|d| d));
                    if is_deactivated {
                        // https://identity.foundation/didwebvh/v0.3/#deactivate-revoke:
                        // To deactivate the DID, the DID Controller SHOULD add to the DID log entry parameters the item "deactivated": true.
                        // A DID MAY update the DIDDoc further to indicate the deactivation of the DID,
                        // such as including an empty updateKeys list ("updateKeys": []) in the parameters,
                        // preventing further versions of the DID.
                        if let Some(mut _current_params) = current_params.to_owned() {
                            _current_params.deactivate();
                            current_params = Some(_current_params);
                        }
                    }

                    let did_doc_hash: String;
                    let did_doc_json: String;

                    let current_did_doc: DidDoc = match entry[3] {
                        JsonObject(ref obj) => {
                            if obj.contains_key("value") {
                                let did_doc_value: JsonValue = obj["value"].to_owned();
                                if !did_doc_value.is_null() {
                                    did_doc_json = did_doc_value.to_string();
                                    did_doc_hash = match JcsSha256Hasher::default().encode_hex(&did_doc_value) {
                                        Ok(did_doc_hash_value) => did_doc_hash_value,
                                        Err(err) => return Err(TrustDidWebError::DeserializationFailed(
                                            format!("Deserialization of DID document failed: {}", err)
                                        ))
                                    };

                                    match serde_json::from_str::<DidDoc>(&did_doc_json) {
                                        Ok(did_doc) => did_doc,
                                        Err(_) => {
                                            match serde_json::from_str::<DidDocNormalized>(&did_doc_json) {
                                                Ok(did_doc_alt) => {
                                                    did_doc_alt.to_did_doc()?
                                                }
                                                Err(err) => return Err(TrustDidWebError::DeserializationFailed(
                                                    format!("Missing DID document: {}", err)
                                                ))
                                            }
                                        }
                                    }
                                } else {
                                    return Err(TrustDidWebError::DeserializationFailed(
                                        "Missing DID Document. JSON 'value' was empty.".to_string(),
                                    ));
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
                            return Err(TrustDidWebError::DeserializationFailed(
                                "Missing DID Document.".to_string(),
                            ))
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

                    let parameters = match new_params {
                        Some(new_params) => new_params,
                        None => return Err(TrustDidWebError::DeserializationFailed(
                            "Internal error: Missing parameter values.".to_string(),
                        ))
                    };

                    let current_entry = DidLogEntry::new(
                        version_id.clone(),
                        version_index,
                        version_time,
                        parameters,
                        current_did_doc.clone(),
                        did_doc_json.clone(),
                        did_doc_hash.clone(),
                        proof,
                        prev_entry.clone(),
                    );
                    prev_entry = Some(Arc::from(current_entry.clone()));

                    Ok(current_entry)
                }).collect::<Result<Vec<DidLogEntry>, TrustDidWebError>>()?
        })
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
                    if entry.version_index != prev.version_index + 1 {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                            "Invalid did log for version {}. Version id has to be incremented",
                            entry.version_index
                        )));
                    }
                    // Verify data integrity proof
                    entry.verify_data_integrity_proof()?;

                    // Verify the entryHash
                    entry.verify_version_id_integrity()?;
                    previous_entry = Some(entry.clone());
                }
                None => {
                    // First / genesis entry in did log
                    let genesis_entry = entry;
                    if genesis_entry.version_index != 1 {
                        return Err(TrustDidWebError::InvalidDataIntegrityProof(
                            "Invalid did log. First entry has to have version id 1".to_string(),
                        ));
                    }

                    // Verify data integrity proof
                    genesis_entry.verify_data_integrity_proof()?;

                    // Verify the entryHash
                    genesis_entry.verify_version_id_integrity()?;

                    // Verify that the SCID is correct
                    let scid = match genesis_entry.parameters.scid.clone() {
                        Some(scid_value) => scid_value,
                        None => {
                            return Err(TrustDidWebError::InvalidDataIntegrityProof(
                                "Missing SCID inside the DID document.".to_string(),
                            ))
                        }
                    };

                    if let Some(res) = &scid_to_validate {
                        if res.ne(scid.as_str()) {
                            return Err(TrustDidWebError::InvalidDataIntegrityProof(format!(
                                "The SCID '{}' supplied inside the DID document does not match the one supplied for validation: '{}'",
                                scid, res
                            )));
                        }
                    }

                    let original_scid =
                        genesis_entry.build_original_scid(&scid).map_err(|err| {
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
            let log_line = entry.to_log_entry_line().map_err(|_| std::fmt::Error)?;
            let serialized = serde_json::to_string(&log_line).map_err(|_| std::fmt::Error)?;
            log.push_str(serialized.as_str());
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
}

static HAS_PATH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([a-z]|[0-9])\/([a-z]|[0-9])").unwrap());
static HAS_PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\:[0-9]+").unwrap());

impl TrustDidWebId {
    pub const DID_METHOD_NAME: &'static str = "tdw";

    /// Yet another UniFFI-compliant method.
    ///
    /// Otherwise, the idiomatic counterpart (try_from(did_tdw: String) -> Result<Self, Self::Error>) may be used as well.
    pub fn parse_did_tdw(did_tdw: String) -> Result<Self, TrustDidWebIdResolutionError> {
        match Self::try_from(did_tdw) {
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

/// Implementation for a string denoting did_tdw
impl TryFrom<String> for TrustDidWebId {
    type Error = TrustDidWebIdResolutionError;

    /// It basically implements the 'The DID to HTTPS Transformation',
    /// as specified by https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation
    fn try_from(did_tdw: String) -> Result<Self, Self::Error> {
        let did_tdw_split: Vec<&str> = did_tdw.splitn(4, ":").collect();
        if did_tdw_split.len() < 4 {
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                did_tdw,
            ));
        };

        let method_name = format!("{}:{}", did_tdw_split[0], did_tdw_split[1]);
        if method_name != format!("did:{}", Self::DID_METHOD_NAME) {
            return Err(TrustDidWebIdResolutionError::MethodNotSupported(
                method_name,
            ));
        };

        let scid = did_tdw_split[2];
        if scid.is_empty() {
            // the SCID MUST be present in the DID string
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                String::from("Empty self-certifying identifier (SCID) detected. An object identifier derived from initial data is expected"),
            ));
        };

        if did_tdw_split[3].replace(":", "").is_empty() || did_tdw_split[3].starts_with(":") {
            return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                String::from("No fully qualified domain detected"),
            ));
        };

        // https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation:
        // 1. Remove the literal did:tdw: prefix from the DID, leaving the method specific identifier.
        // 2. Remove the SCID by removing the text up to and including the first colon (<scid>:) from the method-specific identifier and continue processing.
        // 3. Replace : with / in the method-specific identifier to obtain the fully qualified domain name and optional path.
        let domain_and_optional_path = did_tdw_split[3].replace(":", "/");

        // 5. If the domain contains a port, percent decode the colon.
        let decoded_url = domain_and_optional_path.replace("%3A", ":"); // Decode percent-encoded byte '%3A' (the percent-encoded semicolon (':') char/byte)

        // 6. Generate an HTTPS URL to the expected location of the DIDDoc by prepending https://.
        let url_string = format!("https://{}", decoded_url);

        let mut url = match Url::parse(&url_string) {
            Ok(url) => url,
            Err(err) => {
                return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                    format!("Not a valid URL: {}", err),
                ))
            }
        };

        let has_no_url_path = url.path().is_empty() || url.path() == "/";
        // get an object with methods to manipulate this URL’s path segments
        match url.path_segments_mut() {
            Ok(mut path_segments) => {
                if has_no_url_path {
                    // 4. If there is no optional path, append '/.well-known' to the URL.
                    path_segments.push(".well-known");
                }

                // 7. Append /did.jsonl to complete the URL.
                path_segments.push("did.jsonl");
            }
            Err(_) => {
                // path_segments_mut "Return Err(()) if this URL is cannot-be-a-base."
                return Err(TrustDidWebIdResolutionError::InvalidMethodSpecificId(
                    "This URL cannot-be-a-base".to_string(),
                ));
            }
        };

        Ok(Self {
            scid: scid.to_string(),
            url: url.to_string(),
        })
    }
}

/// Implementation for a tuple denoting did_tdw and allow_http.
#[diagnostic::do_not_recommend]
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
    pub fn get_did(&self) -> String {
        self.did.clone()
    }

    pub fn get_did_log(&self) -> String {
        self.did_log.clone()
    }

    pub fn get_did_doc(&self) -> String {
        self.did_doc.clone()
    }

    /// Yet another UniFFI-compliant method.
    pub fn get_did_doc_obj(&self) -> Result<Arc<DidDoc>, TrustDidWebError> {
        let did_doc_json = self.did_doc.clone();
        match json_from_str::<DidDoc>(&did_doc_json) {
            Ok(doc) => Ok(doc.into()),
            Err(e) => Err(TrustDidWebError::DeserializationFailed(e.to_string())),
        }
    }

    /// A UniFFI-compliant constructor.
    pub fn read(did_tdw: String, did_log: String) -> Result<Self, TrustDidWebError> {
        let did_doc_state = DidDocumentState::from(did_log)?;
        let did = TrustDidWebId::parse_did_tdw(did_tdw.to_owned())
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
