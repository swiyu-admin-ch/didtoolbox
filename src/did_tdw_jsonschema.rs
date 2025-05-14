// SPDX-License-Identifier: MIT

//use std::sync::Arc;
use thiserror::Error;

use crate::custom_jsonschema_keywords::*;
use jsonschema::draft202012::meta as jsch_meta;
use jsonschema::{options as jsch_opts, Draft, Validator as ValidatorBase};
use serde_json::from_str as json_from_str;

#[derive(Error, Debug, PartialEq)]
pub enum DidLogEntryValidatorError {
    #[error("the supplied JSON instance is not a valid DID log: {0}")]
    ValidationError(String),
    #[error("the supplied JSON instance cannot be deserialized: {0}")]
    DeserializationError(String),
}

impl DidLogEntryValidatorError {
    /// Returns the error kind.
    pub fn kind(&self) -> DidLogEntryValidatorErrorKind {
        match self {
            Self::ValidationError(_) => DidLogEntryValidatorErrorKind::ValidationError,
            Self::DeserializationError(_) => DidLogEntryValidatorErrorKind::DeserializationError,
        }
    }
}

/// [`DidLogEntryValidatorError`] kind.
///
/// Each [`DidLogEntryValidatorError`] variant has a kind provided by the [`DidLogEntryValidatorError::kind`] method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DidLogEntryValidatorErrorKind {
    ValidationError,
    DeserializationError,
}

/// A compiled JSON Schema validator.
///
/// This structure represents a JSON Schema that has been parsed and compiled into
/// an efficient internal representation for validation. It contains the root node
/// of the schema tree and the configuration options used during compilation.
//#[derive(Debug, Default, PartialEq)]
#[derive(Debug)]
pub struct DidLogEntryValidator {
    validator: ValidatorBase,
}

impl DidLogEntryValidator {
    /// As defined by https://identity.foundation/didwebvh/v0.3
    const DID_LOG_ENTRY_JSONSCHEMA_V_0_3: &'static str = r#"{
        "title": "DID log entry schema v0.3",
        "type": "array",
        "did-log-entry": true,
        "$comment": "As specified by https://identity.foundation/didwebvh/v0.3/#the-did-log-file",
        "allOf": [{
            "prefixItems": [
            {
                "type": "string",
                "patttern": "^[1-9][0-9]+-Q[1-9a-zA-NP-Z]{45,}$",
                "did-version-id": true,
                "$comment": "The entry versionId is a value that combines the version number (starting at 1 and incrementing by one per DID version), a literal dash -, and the entryHash, a hash calculated across the log entry content."
            },
            {
                "type": "string",
                "did-version-time": true,
                "$comment": "The versionTime (as stated by the DID Controller) of the entry, in ISO8601 format."
            },
            {
                "type": "object",
                "properties": {
                    "method": {
                        "const": "did:tdw:0.3",
                        "$comment": "Required only within first entry. This item MUST appear in the first DID log entry."
                    },
                    "scid": {
                        "type": "string",
                        "pattern": "^Q[1-9a-zA-NP-Z]{45,}$",
                        "$comment": "The self-certifying identifier or SCID is a required parameter in the first DID log entry and is the hash of the DID’s inception event."
                    },
                    "updateKeys": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "pattern": "^z[1-9a-zA-NP-Z]{47,}$"
                        },
                        "$comment": "A list of one or more multikey formatted public keys associated with the private keys that are authorized to sign the log entries that update the DID from one version to the next. This item MUST appear in the first DID log entry."
                    },
                    "portable": {
                        "type": "boolean",
                        "$comment": "A boolean flag indicating if the DID is portable and thus can be renamed to change the Web location of the DID. Must be unset or false in the first did log entry (REQUIREMENT)"
                    },
                    "prerotation": {
                        "type": "boolean",
                        "$comment": "A boolean value indicating that subsequent authentication keys added to the DIDDoc (after this version) MUST have their hash included in a nextKeyHashes parameter item. (warning) Is removed in future versions. Must be a boolean or unset (SPEC)"
                    },
                    "nextKeyHashes": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "pattern": "^z[1-9a-zA-NP-Z]{47,}$"
                        },
                        "$comment": "An array of strings that are hashes of multikey formatted public keys that MAY be added to the updateKeys list in the log entry of a future version of the DID."
                    },
                    "witnesses": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "$comment": "A list of one or more multikey formatted public keys associated with the private keys that are authorized to sign the log entries that update the DID from one version to the next. This item MUST appear in the first DID log entry. Must be unset or null (REQUIREMENT)"
                    },
                    "witnessThreshold": {
                        "type": "integer",
                        "const": 0
                    },
                    "deactivated": {
                        "type": "boolean",
                        "$comment": "A JSON boolean that SHOULD be set to true when the DID is to be deactivated. See the deactivate (revoke) section of this specification for more details."
                    },
                    "ttl": {
                        "type": "integer",
                        "$comment": "A number, the number of seconds that a cache entry for a resolved did:tdw DID SHOULD last, as recommended by the DID Controller."
                    }
                },
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string"
                            }
                        },
                        "required": [
                            "id"
                        ]
                    }
                },
                "required": [
                    "value"
                ]
            },
            {
                "type": "array",
                "items": {
                    "type": "object",
                    "$comment": "As specified by https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022",
                    "properties": {
                        "type": {
                            "const": "DataIntegrityProof"
                        },
                        "cryptosuite": {
                            "const": "eddsa-jcs-2022"
                        },
                        "verificationMethod": {
                            "type": "string",
                            "pattern": "^did:key:z[1-9a-zA-NP-Z]{47,}#z[1-9a-zA-NP-Z]{47,}$"
                        },
                        "created": {
                            "type": "string",
                            "did-version-time": true
                        },
                        "proofPurpose": {
                            "$comment": "As specified by https://www.w3.org/TR/vc-data-integrity/#proof-purposes",
                            "enum": ["authentication", "assertionMethod", "keyAgreement", "capabilityDelegation", "capabilityInvocation"]
                        },
                        "proofValue": {
                            "type": "string",
                            "pattern": "^z[1-9a-zA-NP-Z]{87,}$",
                            "$comment": "The proofValue property of the proof MUST be a detached EdDSA signature produced according to [RFC8032], encoded using the base-58-btc header and alphabet as described in the Multibase section of Controlled Identifiers v1.0 (https://www.w3.org/TR/cid-1.0)."
                        },
                        "challenge": {
                            "type": "string",
                            "did-version-id": true
                        }
                    },
                    "required": [
                        "type",
                        "cryptosuite",
                        "verificationMethod",
                        "created",
                        "proofPurpose",
                        "proofValue",
                        "challenge"
                    ]
                }
            }
        ]}],
        "additionalItems": false
    }"#;

    /// Validate `instance` against `schema` and return the first error if any.
    ///
    /// A UniFFI-compliant method.
    pub fn validate(&self, instance: String) -> Result<(), DidLogEntryValidatorError> {
        match json_from_str(&instance) {
            Ok(val) => match self.validator.validate(&val) {
                Ok(_) => Ok(()),
                Err(e) => Err(DidLogEntryValidatorError::ValidationError(e.to_string())),
            },
            Err(e) => Err(DidLogEntryValidatorError::DeserializationError(
                e.to_string(),
            )),
        }
    }
}

impl Default for DidLogEntryValidator {
    /// Create a new JSON Schema validator using `JSON Schema Draft 2020-12` specifications and default options.
    ///
    /// Relies heavily on custom `jsonschema::Keyword` trait implementation like:
    /// - [`DidVersionIdKeyword`] and
    /// - [`DidVersionTimeKeyword`].
    ///
    /// A UniFFI-compliant constructor.
    fn default() -> Self {
        match json_from_str(Self::DID_LOG_ENTRY_JSONSCHEMA_V_0_3) {
            Ok(sch) => {
                let _ = jsch_meta::validate(&sch).is_err_and(|e| panic!("{}", e.to_string()));
                match jsch_opts()
                    .with_draft(Draft::Draft202012)
                    .with_keyword(
                        DidLogEntryKeyword::KEYWORD_NAME,
                        DidLogEntryKeyword::factory,
                    )
                    .with_keyword(
                        DidVersionIdKeyword::KEYWORD_NAME,
                        DidVersionIdKeyword::factory,
                    )
                    .with_keyword(
                        DidVersionTimeKeyword::KEYWORD_NAME,
                        DidVersionTimeKeyword::factory,
                    )
                    .build(&sch)
                {
                    Ok(validator) => DidLogEntryValidator { validator },
                    Err(e) => panic!("{}", e.to_string()),
                }
            }
            Err(e) => panic!("{}", e.to_string()),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::did_tdw_jsonschema::DidLogEntryValidator;
    use rstest::rstest;
    use serde_json::{json, Value};

    #[rstest]
    #[case(json!([
        "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "2012-12-12T12:12:12Z", 
        {
            "method": "did:tdw:0.3",
            "scid": "QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH",
            "updateKeys": [
              "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
              "z6Mkwf4PgXLq8sRfucTggtZXmigKZP7gQhFamk3XHGV54QvF"
            ],
            "portable": false,
            "prerotation": false,
            "nextKeyHashes": [],
            "witnesses": [],
            "witnessThreshold": 0,
            "deactivated": false
        },
        {"value": {"id": "x"}},
        [{
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2012-12-12T12:12:12Z",
            "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
            "proofPurpose": "authentication",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR"
        }],]), true)]
    #[case(json!([
        "invalid-version-id", 
        "2012-12-12T12:12:12Z",
        {"method": "did:tdw:0.3"}, 
        {"value": {"id": "x"}},
        [{
            "created": "2012-12-12T12:12:12Z",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
        }],]), false)]
    #[case(json!([
        "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "invalid-version-time",
        {"method": "did:tdw:0.3"},
        {"value": {"id": "x"}},
        [{
            "created": "2012-12-12T12:12:12Z",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
        }],]), false)]
    #[case(json!(["1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR","2012-12-12T12:12:12Z",{"":""},{"value":{"id":"x"}},[{"":""}]]), false)]
    #[case(json!(["1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR","2012-12-12T12:12:12Z",{},{"value":{"id":"x"}},[{"":""}]]), false)] // params may be empty
    #[case(json!(["1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR","2012-12-12T12:12:12Z",{},{"value":{"id":"x"}},[{}]]), false)] // proof must not be empty
    #[case(json!(["","",{},{},[]]), false)] // all empty
    #[case(json!(["","",{},{},[{}]]), false)] // all empty
    #[case(json!(["","","","",""]), false)] // all JSON strings
                                            //#[case(json!([]), false)] // empty array
    fn test_validate_using_custom_schema(#[case] instance: Value, #[case] expected: bool) {
        //-> Result<(), Box<dyn std::error::Error>> {

        let validator = DidLogEntryValidator::default();

        let is_valid = validator.validate(instance.to_string());

        assert_eq!(expected, is_valid.is_ok());
        assert_eq!(!expected, is_valid.is_err());

        //Ok(())
    }
}
