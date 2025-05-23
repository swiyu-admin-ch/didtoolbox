// SPDX-License-Identifier: MIT

use std::str::from_utf8;
use thiserror::Error;

use crate::custom_jsonschema_keywords::*;
use jsonschema::draft202012::meta as jsch_meta;
use jsonschema::{options as jsch_opts, Draft, Validator as ValidatorBase};
use rust_embed::Embed;
use serde_json::from_str as json_from_str;

/// Represents any error condition that might occur in conjunction with [`DidLogEntryValidator`].
///
/// Yet another UniFFI-compliant error.
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

#[derive(Embed)]
#[folder = "src/embed/jsonschema"]
#[include = "*.json"]
struct DidLogJsonSchemaEmbedFolder;

/// W.r.t. corresponding specification version available at https://identity.foundation/didwebvh
///
/// # CAUTION The single currently supported version is: v0.3
#[derive(Debug, Clone, PartialEq)]
pub enum DidLogEntryJsonSchema {
    /// As defined by both https://identity.foundation/didwebvh/v0.3 and (eID-conformity) addendum:
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
    V03EidConform,
    /// As (strictly) specified by https://identity.foundation/didwebvh/v0.3
    V03,
    /*
    /// Yet to be implemented
    V1_0,
     */
}

impl DidLogEntryJsonSchema {
    /// As defined by https://identity.foundation/didwebvh/v0.3
    const DID_LOG_ENTRY_JSONSCHEMA_V_0_3_FILENAME: &'static str = "did_log_jsonschema_v_0_3.json";

    /// As defined by both https://identity.foundation/didwebvh/v0.3 and (eID-conformity) addendum:
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check
    /// - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
    const DID_LOG_ENTRY_JSONSCHEMA_V_0_3_EID_CONFORM_FILENAME: &'static str =
        "did_log_jsonschema_v_0_3_eid_conform.json";

    /// Converts this type into a corresponding JSON schema in UTF-8 format.
    fn as_schema(&self) -> String {
        match self {
            Self::V03 => {
                // CAUTION This (i.e. unwrap() call) will panic only if file denoted by DID_LOG_ENTRY_JSONSCHEMA_V_0_3_FILENAME does not exist
                let jsonschema_file =
                    DidLogJsonSchemaEmbedFolder::get(Self::DID_LOG_ENTRY_JSONSCHEMA_V_0_3_FILENAME)
                        .unwrap();
                // CAUTION This (i.e. unwrap() call) will panic only if file denoted by DID_LOG_ENTRY_JSONSCHEMA_V_0_3_FILENAME is not UTF-8
                from_utf8(jsonschema_file.data.as_ref())
                    .unwrap()
                    .to_string()
            }
            Self::V03EidConform => {
                // CAUTION This (i.e. unwrap() call) will panic only if file denoted by DID_LOG_ENTRY_JSONSCHEMA_V_0_3_BIT_CONFORM_FILENAME does not exist
                let jsonschema_file = DidLogJsonSchemaEmbedFolder::get(
                    Self::DID_LOG_ENTRY_JSONSCHEMA_V_0_3_EID_CONFORM_FILENAME,
                )
                .unwrap();
                // CAUTION This (i.e. unwrap() call) will panic only if file denoted by DID_LOG_ENTRY_JSONSCHEMA_V_0_3_BIT_CONFORM_FILENAME is not UTF-8
                from_utf8(jsonschema_file.data.as_ref())
                    .unwrap()
                    .to_string()
            }
        }
    }
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

impl From<DidLogEntryJsonSchema> for DidLogEntryValidator {
    fn from(ver: DidLogEntryJsonSchema) -> Self {
        Self::from(ver.as_schema().as_str())
    }
}

impl From<&str> for DidLogEntryValidator {
    fn from(s: &str) -> Self {
        match json_from_str(s) {
            Ok(sch) => {
                let _ = jsch_meta::validate(&sch).is_err_and(|e| panic!("{}", e.to_string()));
                match jsch_opts()
                    .with_draft(Draft::Draft202012)
                    .with_keyword(
                        DidLogEntryKeyword::KEYWORD_NAME,
                        DidLogEntryKeyword::factory,
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

impl Default for DidLogEntryValidator {
    /// Create a new JSON Schema validator using `JSON Schema Draft 2020-12` specifications and default options.
    ///
    /// Relies heavily on custom `jsonschema::Keyword` trait implementation like:
    /// - [`DidVersionIdKeyword`] and
    /// - [`DidVersionTimeKeyword`].
    ///
    /// A UniFFI-compliant constructor.
    fn default() -> Self {
        Self::from(DidLogEntryJsonSchema::V03)
    }
}

#[cfg(test)]
mod test {
    use crate::did_tdw_jsonschema::{
        DidLogEntryJsonSchema, DidLogEntryValidator, DidLogEntryValidatorErrorKind,
    };
    use rstest::rstest;
    use serde_json::{json, Value};

    #[rstest]
    // CAUTION V03-specific (happy path) case
    #[case(vec!(DidLogEntryJsonSchema::V03), json!([
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
        {"value": {
            "id": "did:tdw:QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH:example.com", 
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
            "controller": "did:tdw:QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH:example.com",
            "verificationMethod": [{
                "id": "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                "controller": "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
                "type": "JsonWebKey2020",
                "publicKeyJwk":{
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "N4hbTf7x1eWwjqHOQpAB469BwLYfFzIw7QbSa-vv8VM",
                    "y": "eebnhG9Fmmw2OwW4BPdKJMKm8wGgo18yp_Q2FpvU57U",
                    "kid": "auth-key-01"
                }
            }],
        }},
        [{
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2012-12-12T12:12:12Z",
            "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
            "proofPurpose": "authentication",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR"
        }],]), true, "")]
    // CAUTION V03EidConform-specific (happy path) case
    #[case(vec!(DidLogEntryJsonSchema::V03EidConform), json!([
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
            "deactivated": false
        },
        {"value": {
            "id": "did:tdw:QmZ5tnGo1fHNEzHDpG2Bx5dmT3eGNmBY9QATtm6DrFMzcH:example.com",
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
            "verificationMethod": [{
                "id": "did:tdw:QmT7BM5RsM9SoaqAQKkNKHBzSEzpS2NRzT2oKaaaPYPpGr:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
                "type": "JsonWebKey2020",
                "publicKeyJwk":{
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "N4hbTf7x1eWwjqHOQpAB469BwLYfFzIw7QbSa-vv8VM",
                    "y": "eebnhG9Fmmw2OwW4BPdKJMKm8wGgo18yp_Q2FpvU57U",
                    "kid": "auth-key-01"
                }
            }],
        }},
        [{
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2012-12-12T12:12:12Z",
            "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
            "proofPurpose": "authentication",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR"
        }],]), true, "")]
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!([
        "invalid-version-id", 
        "2012-12-12T12:12:12Z",
        {"method": "did:tdw:0.3"}, 
        {"value": {}},
        [{
            "created": "2012-12-12T12:12:12Z",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
        }],]), false, "\"invalid-version-id\" does not match \"^[1-9][0-9]*-Q[1-9a-zA-NP-Z]{45,}$\"")]
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!([
        "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
        "invalid-version-time",
        {"method": "did:tdw:0.3"},
        {"value": {}},
        [{
            "created": "2012-12-12T12:12:12Z",
            "challenge": "1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR",
            "proofValue": "z4a92V6EKmWvURx99HXVTEM6KJhbVZZ1s4qN8HJXTMesSoDJx1VpTNtuNUpae2eHpXXKwBGjtCYC2EQK7b6eczmnp",
        }],]), false, "Datetime not in ISO8601 format")]
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR","2012-12-12T12:12:12Z",{"":""},{"value":{}},[{"":""}]]), false, "Additional properties are not allowed ('' was unexpected)")]
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR","2012-12-12T12:12:12Z",{},{"value":{"id":""}},[{"":""}]]), false, "\"@context\" is a required property")] // params may be empty, but DID doc must be complete
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["1-QmcykRx2WnZz2L9s5ACN34E4ADEYGiCde4BJSzoxrhYoiR","2012-12-12T12:12:12Z",{},{"value":{}},[{}]]), false, "A DID log entry must include a JSON array of five items")] // proof must not be empty
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["","",{},{},[]]), false, "A DID log entry must include a JSON array of five items")] // all empty
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["","",{},{},[{}]]), false, "A DID log entry must include a JSON array of five items")] // all empty
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!(["","","","",""]), false, "A DID log entry must include a JSON array of five items")] // all JSON strings
    #[case(vec!(DidLogEntryJsonSchema::V03, DidLogEntryJsonSchema::V03EidConform), json!([]), false, "A DID log entry must include a JSON array of five items")] // empty array
    fn test_validate_using_schema(
        #[case] schemata: Vec<DidLogEntryJsonSchema>,
        #[case] instance: Value,
        #[case] expected: bool,
        #[case] err_contains_pattern: &str,
    ) {
        //-> Result<(), Box<dyn std::error::Error>> {

        schemata.iter().for_each(|schema| {
            let validator = DidLogEntryValidator::from(schema.to_owned());

            let is_valid = validator.validate(instance.to_string());

            assert_eq!(expected, is_valid.is_ok());
            assert_eq!(!expected, is_valid.is_err());
            if !expected {
                assert!(is_valid.is_err_and(|err| {
                    assert_eq!(err.kind(), DidLogEntryValidatorErrorKind::ValidationError);
                    assert!(
                        err.to_string().contains(err_contains_pattern),
                        "got: '{}', expected '{}'",
                        err.to_string(),
                        err_contains_pattern
                    );
                    true
                }));
            }
        });

        //Ok(())
    }
}
