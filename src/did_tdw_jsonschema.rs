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
        "allOf": [{
            "prefixItems": [
            {
                "type": "string",
                "did-version-id": true
            },
            {
                "type": "string",
                "did-version-time": true
            },
            {
                "type": "object",
                "properties": {
                    "method": {
                        "const": "did:tdw:0.3",
                        "$comment": "Required only within first entry"
                    }
                }
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
                    "properties": {
                        "created": {
                            "type": "string",
                            "did-version-time": true
                        },
                        "proofValue": {
                            "type": "string",
                            "minLength": 64
                        },
                        "challenge": {
                            "type": "string",
                            "did-version-id": true
                        }
                    },
                    "required": [
                        "created",
                        "challenge",
                        "proofValue"
                    ]
                }
            }
        ]}],
        "additionalItems": false
    }"#;

    /// Create a new JSON Schema validator using `JSON Schema Draft 2020-12` specifications and default options.
    ///
    /// Relies heavily on custom `jsonschema::Keyword` trait implementation like:
    /// - [`DidVersionIdKeyword`] and
    /// - [`DidVersionTimeKeyword`].
    ///
    /// A UniFFI-compliant constructor.
    pub fn default() -> Self {
        //pub fn new() -> Self {
        match json_from_str(Self::DID_LOG_ENTRY_JSONSCHEMA_V_0_3) {
            Ok(sch) => {
                let _ = jsch_meta::validate(&sch).is_err_and(|e| panic!("{}", e.to_string()));
                match jsch_opts()
                    .with_draft(Draft::Draft202012)
                    /*.with_keyword(
                        DidLogEntryKeyword::KEYWORD_NAME,
                        DidLogEntryKeyword::factory,
                    )*/
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

#[cfg(test)]
mod test {
    use crate::did_tdw_jsonschema::DidLogEntryValidator;
    use rstest::rstest;
    use serde_json::{json, Value};

    #[rstest]
    #[case(json!([
        "1-some_entry_hash", 
        "2012-12-12T12:12:12Z", 
        {"method": "did:tdw:0.3"}, 
        {"value": {"id": "x"}},
        [{
            "created": "2012-12-12T12:12:12Z",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
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
        "1-some_entry_hash",
        "invalid-version-time",
        {"method": "did:tdw:0.3"},
        {"value": {"id": "x"}},
        [{
            "created": "2012-12-12T12:12:12Z",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
        }],]), false)]
    #[case(json!(["1-some_entry_hash","2012-12-12T12:12:12Z",{"":""},{"value":{"id":"x"}},[{"":""}]]), false)]
    #[case(json!(["1-some_entry_hash","2012-12-12T12:12:12Z",{},{"value":{"id":"x"}},[{"":""}]]), false)] // params may be empty
    #[case(json!(["1-some_entry_hash","2012-12-12T12:12:12Z",{},{"value":{"id":"x"}},[{}]]), false)] // proof must not be empty
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
