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
            prerotation: Option::None,
            //update_keys: Option::None,
            update_keys: Some(vec![update_key]),
            next_keys: Option::None,
            witnesses: Option::None,
            witness_threshold: Option::None,
            deactivated: Option::None,
            ttl: Option::None,
            portable: Option::Some(false),
        }
    }

    pub fn empty() -> Self {
        DidMethodParameters {
            method: Option::None,
            scid: Option::None,
            prerotation: Option::None,
            update_keys: Option::None,
            next_keys: Option::None,
            witnesses: Option::None,
            witness_threshold: Option::None,
            deactivated: Option::None,
            ttl: Option::None,
            portable: Option::None,
        }
    }

    /// Validation against all the criteria described in https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters
    ///
    /// Furthermore, the relevant Swiss profile checks are also taken into account here:
    /// https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#didtdwdidwebvh
    pub fn validate_initial(&self) -> Result<(), TrustDidWebError> {
        if let Some(method) = &self.method {
            // This item MAY appear in later DID log entries to indicate that the processing rules
            // for that and later entries have been changed to a different specification version.
            if method != DID_METHOD_PARAMETER_VERSION {
                return Err(TrustDidWebError::InvalidDidParameter(format!(
                    "Invalid 'method' DID parameter. Expected '{DID_METHOD_PARAMETER_VERSION}'"
                )));
            }
        } else {
            // This item MUST appear in the first DID log entry.
            return Err(TrustDidWebError::InvalidDidParameter(
                "Missing 'method' DID parameter. This item MUST appear in the first DID log entry."
                    .to_string(),
            ));
        }

        if let Some(scid) = &self.scid {
            if scid.is_empty() {
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Invalid 'scid' DID parameter. This item MUST appear in the first DID log entry.".to_string(),
                ));
            }
        } else {
            return Err(TrustDidWebError::InvalidDidParameter(
                "Missing 'scid' DID parameter. This item MUST appear in the first DID log entry."
                    .to_string(),
            ));
        }

        if let Some(update_keys) = &self.update_keys {
            if update_keys.is_empty() {
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Empty 'updateKeys' DID parameter. This item MUST appear in the first DID log entry.".to_string(),
                ));
            }
        } else {
            return Err(TrustDidWebError::InvalidDidParameter(
                "Missing 'updateKeys' DID parameter. This item MUST appear in the first DID log entry.".to_string(),
            ));
        }

        if let Some(portable) = self.portable {
            if portable {
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Unsupported 'portable' DID parameter. We currently don't support portable dids".to_string(),
                ));
            }
        }

        if let Some(prerotation) = self.prerotation {
            if prerotation {
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Unsupported 'prerotation' DID parameter. We currently don't support prerotation".to_string(),
                ));
            }
        }

        if let Some(next_keys) = &self.next_keys {
            if !next_keys.is_empty() {
                return Err(TrustDidWebError::InvalidDidParameter(
                    "Unsupported non-empty 'nextKeyHashes' DID parameter.".to_string(),
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

    pub fn merge_from(&mut self, other: &DidMethodParameters) -> Result<(), TrustDidWebError> {
        let new_params = other.to_owned();
        let current_params = self.clone();
        self.method = match new_params.method {
            Some(method) => {
                // This item MAY appear in later DID log entries to indicate that the processing rules
                // for that and later entries have been changed to a different specification version.
                if method != DID_METHOD_PARAMETER_VERSION {
                    return Err(TrustDidWebError::InvalidDidParameter(
                        format!("Invalid 'method' DID parameter. Expected '{DID_METHOD_PARAMETER_VERSION}'.")
                    ));
                }
                Some(method)
            }
            None => current_params.method,
        };

        self.scid = match new_params.scid {
            Some(scid) => {
                if current_params.scid.is_none_or(|x| x != scid) {
                    return Err(TrustDidWebError::InvalidDidParameter(
                        "Invalid 'scid' DID parameter. The 'scid' parameter is not allowed to change."
                        .to_string(),
                    ));
                };
                Some(scid)
            }
            None => self.scid.clone(),
        };

        self.update_keys = new_params.update_keys.or(current_params.update_keys);

        self.portable = match (current_params.portable, new_params.portable) {
            (Some(true), Some(true)) => return Err(TrustDidWebError::InvalidDidParameter(
                "Unsupported 'portable' DID parameter. We currently don't support portable dids".to_string(),
            )),
            (_, Some(true)) =>  return Err(TrustDidWebError::InvalidDidParameter(
                "Invalid 'portable' DID parameter. The value can ONLY be set to true in the first log entry, the initial version of the DID.".to_string(),
            )),
            (_, Some(false)) => Some(false),
            (_, None) => current_params.portable

        };

        self.prerotation = match (current_params.prerotation, new_params.prerotation) {
            (Some(true), Some(false)) => return Err(TrustDidWebError::InvalidDidParameter(
                "Invalid 'prerotation' DID parameter. Once the value is set to true in a DID log entry it MUST NOT be set to false in a subsequent entry.".to_string(),
            )),
            (_, Some(new_pre)) => Some(new_pre),
            (_, None) => current_params.prerotation
        };
        self.next_keys = new_params.next_keys.or(current_params.next_keys);

        self.witnesses = match new_params.witnesses {
            Some(witnesses) => {
                if !witnesses.is_empty() {
                    return Err(TrustDidWebError::InvalidDidParameter(
                        "Unsupported non-empty 'witnesses' DID parameter.".to_string(),
                    ));
                }
                Some(vec![])
            }
            None => current_params.witnesses,
        };

        self.deactivated = match (current_params.deactivated, new_params.deactivated) {
            (Some(true), _) => return Err(TrustDidWebError::InvalidDidDocument(
                "This DID document is already deactivated. Therefore no additional DID logs are allowed.".to_string()
            )),
            (_, Some(deactivate)) => Some(deactivate),
            (_, None) => current_params.deactivated,
        };

        self.ttl = new_params.ttl.or(self.ttl.to_owned());

        self.witness_threshold = new_params
            .witness_threshold
            .or(current_params.witness_threshold);

        Ok(())
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

#[cfg(test)]
mod test {
    use crate::did_tdw_parameters::DidMethodParameters;
    use crate::errors::TrustDidWebErrorKind;
    use crate::test::assert_trust_did_web_error;
    use rstest::rstest;

    #[rstest]
    fn test_did_tdw_parameters_validate_initial() {
        let params_for_genesis_did_doc =
            DidMethodParameters::for_genesis_did_doc("scid".to_string(), "update_key".to_string());
        assert!(params_for_genesis_did_doc.validate_initial().is_ok());

        let mut params = params_for_genesis_did_doc.clone();

        // Test "method" DID parameter
        params.method = Some("invalidVersion".to_string());
        assert_trust_did_web_error(
            params.validate_initial(),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Invalid 'method' DID parameter.",
        );
        params.method = None;
        assert_trust_did_web_error(
            params.validate_initial(),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Missing 'method' DID parameter.",
        );

        // Test "scid" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.scid = Some("".to_string());
        assert_trust_did_web_error(
            params.validate_initial(),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Invalid 'scid' DID parameter.",
        );
        params.scid = None;
        assert_trust_did_web_error(
            params.validate_initial(),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Missing 'scid' DID parameter.",
        );

        // Test "update_keys" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.update_keys = Some(vec![]);
        assert_trust_did_web_error(
            params.validate_initial(),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Empty 'updateKeys' DID parameter.",
        );
        params.update_keys = None;
        assert_trust_did_web_error(
            params.validate_initial(),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Missing 'updateKeys' DID parameter.",
        );

        // Test "portable" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.portable = Some(true);
        assert_trust_did_web_error(
            params.validate_initial(),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Unsupported 'portable' DID parameter",
        );
        params.portable = Some(false);
        assert!(params.validate_initial().is_ok());
        params.portable = None;
        assert!(params.validate_initial().is_ok());

        // Test "prerotation" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.prerotation = Some(true);
        assert_trust_did_web_error(
            params.validate_initial(),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Unsupported 'prerotation' DID parameter",
        );
        params.prerotation = Some(false);
        assert!(params.validate_initial().is_ok());
        params.prerotation = None;
        assert!(params.validate_initial().is_ok());

        // Test "next_keys" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.next_keys = Some(vec!["some_valid_key".to_string()]);
        assert_trust_did_web_error(
            params.validate_initial(),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Unsupported non-empty 'nextKeyHashes' DID parameter",
        );
        params.next_keys = Some(vec![]);
        assert!(params.validate_initial().is_ok());
        params.next_keys = None;
        assert!(params.validate_initial().is_ok());

        // Test "witnesses" DID parameter
        params = params_for_genesis_did_doc.clone();
        params.witnesses = Some(vec!["some_valid_witness".to_string()]);
        assert_trust_did_web_error(
            params.validate_initial(),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Unsupported non-empty 'witnesses' DID parameter.",
        );
        params.witnesses = Some(vec![]);
        assert!(params.validate_initial().is_ok());
        params.witnesses = None;
        assert!(params.validate_initial().is_ok());
    }

    #[rstest]
    fn test_did_tdw_parameters_validate_transition() {
        let base_params =
            DidMethodParameters::for_genesis_did_doc("scid".to_string(), "update_key".to_string());

        let mut old_params = base_params.clone();
        let mut new_params = base_params.clone();
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "method" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.method = Some("invalidVersion".to_string());
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Invalid 'method' DID parameter.",
        );
        new_params.method = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        // Test "scid" DID parameter
        old_params = old_params.clone();
        new_params = new_params.clone();
        new_params.scid = Some("otherSCID".to_string());
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Invalid 'scid' DID parameter.",
        );
        new_params.scid = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.scid = Some("scid".to_string()); // SAME scid value
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "update_keys" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.update_keys = Some(vec!["newUpdateKey".to_string()]);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.update_keys = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.update_keys = Some(vec![]);
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "portable" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();

        new_params.portable = Some(true);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Invalid 'portable' DID parameter.",
        );
        new_params.portable = Some(false);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.portable = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.portable = Some(true);
        old_params.portable = Some(true);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Unsupported 'portable' DID parameter.",
        );

        // Test "prerotation" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        old_params.prerotation = Some(true);
        new_params.prerotation = Some(false);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Invalid 'prerotation' DID parameter.",
        );
        old_params.prerotation = Some(true);
        new_params.prerotation = Some(true);
        assert!(old_params.merge_from(&new_params).is_ok());
        old_params.prerotation = Some(false);
        new_params.prerotation = Some(false);
        assert!(old_params.merge_from(&new_params).is_ok());
        old_params.prerotation = Some(false);
        new_params.prerotation = Some(true);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.prerotation = None;
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "next_keys" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.next_keys = Some(vec!["newUpdateKeyHash".to_string()]);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.next_keys = None;
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.next_keys = Some(vec![]);
        assert!(old_params.merge_from(&new_params).is_ok());

        // Test "witnesses" DID parameter
        old_params = base_params.clone();
        new_params = base_params.clone();
        new_params.witnesses = Some(vec!["some_valid_witness".to_string()]);
        assert_trust_did_web_error(
            old_params.merge_from(&new_params),
            TrustDidWebErrorKind::InvalidDidParameter,
            "Unsupported non-empty 'witnesses' DID parameter.",
        );
        new_params.witnesses = Some(vec![]);
        assert!(old_params.merge_from(&new_params).is_ok());
        new_params.witnesses = None;
        assert!(old_params.merge_from(&new_params).is_ok());
    }
}
