// SPDX-License-Identifier: MIT

use crate::errors::*;
use serde::{Deserialize, Serialize};

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
    #[deprecated(
        note = "kept for historical reasons only (backward compatibility in regard to unit testing) and should therefore not be used"
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

    /// Validation against all the criteria described in https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters
    ///
    /// Furthermore, the relevant Swiss profile checks are also taken into account here:
    /// https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#didtdwdidwebvh
    pub fn validate(
        &self,
        is_initial_did_log_entry: bool,
        is_already_prerotated: bool,
        is_already_portable: bool,
    ) -> Result<(), TrustDidWebError> {
        if is_initial_did_log_entry && (is_already_prerotated || is_already_portable) {
            panic!("An initial DID log entry assumes both 'portable' and 'prerotation' DID parameters are initialized to false.");
        }

        if let Some(method) = &self.method {
            // This item MAY appear in later DID log entries to indicate that the processing rules
            // for that and later entries have been changed to a different specification version.
            if method != DID_METHOD_PARAMETER_VERSION {
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Invalid 'method' DID parameter. Expected '{DID_METHOD_PARAMETER_VERSION}'"
                        .to_string(),
                ));
            }
        } else {
            // This item MUST appear in the first DID log entry.
            return Err(TrustDidWebError::InvalidDidParameter(
                "Missing 'method' DID parameter. This item MUST appear in the first DID log entry."
                    .to_string(),
            ));
        }

        if let Some(scid) = &self.scid {
            if is_initial_did_log_entry && scid.is_empty()
            //|| !is_initial_did_log_entry && scid.is_empty()
            {
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Invalid 'scid' DID parameter. This item MUST appear in the first DID log entry.".to_string(),
                ));
            }
        } else if is_initial_did_log_entry {
            return Err(TrustDidWebError::InvalidDidParameter(
                "Missing 'scid' DID parameter. This item MUST appear in the first DID log entry."
                    .to_string(),
            ));
        }

        if let Some(update_keys) = &self.update_keys {
            if is_initial_did_log_entry && update_keys.is_empty() {
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Empty 'updateKeys' DID parameter. This item MUST appear in the first DID log entry.".to_string(),
                ));
            }
        } else if is_initial_did_log_entry {
            return Err(TrustDidWebError::InvalidDidParameter(
                "Missing 'updateKeys' DID parameter. This item MUST appear in the first DID log entry.".to_string(),
            ));
        }

        if let Some(portable_new_value) = self.portable {
            if !is_initial_did_log_entry && !is_already_portable && portable_new_value {
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Invalid 'portable' DID parameter. Once the value has been set to false, it cannot be set back to true.".to_string(),
                ));
            }
            if !is_initial_did_log_entry && portable_new_value {
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Invalid 'portable' DID parameter. The value can ONLY be set to true in the first log entry, the initial version of the DID.".to_string(),
                ));
            }
        }

        if let Some(prerotation_new_value) = self.prerotation {
            if is_already_prerotated && !prerotation_new_value {
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Invalid 'prerotation' DID parameter. Once the value is set to true in a DID log entry it MUST NOT be set to false in a subsequent entry.".to_string(),
                ));
            }
        }

        if let Some(witnesses) = &self.witnesses {
            if !witnesses.is_empty() {
                // A witness item in the first DID log entry is used to define the witnesses and necessary threshold for that initial log entry.
                // In all other DID log entries, a witness item becomes active after the publication of its entry.
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Unsupported non-empty 'witnesses' DID parameter.".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn merge_from(&mut self, other: &DidMethodParameters) {
        let _other = other.to_owned();
        self.method = _other.method.or(self.method.to_owned());
        self.scid = _other.scid.or(self.scid.to_owned());
        self.hash = _other.hash.or(self.hash.to_owned());
        self.prerotation = _other.prerotation.or(self.prerotation.to_owned());
        self.update_keys = _other.update_keys.or(self.update_keys.to_owned());
        self.next_keys = _other.next_keys.or(self.next_keys.to_owned());
        self.witnesses = _other.witnesses.or(self.witnesses.to_owned());
        self.witness_threshold = _other
            .witness_threshold
            .or(self.witness_threshold.to_owned());
        self.moved = _other.moved.or(self.moved.to_owned());
        self.deactivated = _other.deactivated.or(self.deactivated.to_owned());
        self.ttl = _other.ttl.or(self.ttl.to_owned());
        self.portable = _other.portable.or(self.portable.to_owned());
    }

    /// As specified by https://identity.foundation/didwebvh/v0.3/#deactivate-revoke
    pub fn deactivate(&mut self) {
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

/// As defined by https://identity.foundation/trustdidweb/v0.3/#didtdw-did-method-parameters
const DID_METHOD_PARAMETER_VERSION: &str = "did:tdw:0.3";
