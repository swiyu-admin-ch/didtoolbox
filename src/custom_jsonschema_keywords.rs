// SPDX-License-Identifier: MIT

use chrono::{DateTime, Local};
use jsonschema::{
    paths::{LazyLocation, Location},
    Keyword, ValidationError,
};
use serde_json::{Map, Value};
use std::cmp::Ordering;

/// Yet another custom [`Keyword`] trait implementation able to validate if a JSON array represents
/// a regular `didwebvh` DID log entry (as defined by https://identity.foundation/didwebvh/v0.3/#overview).
///
/// This [`Keyword`] trait implementation validates instances according to https://identity.foundation/didwebvh/v0.3/#overview
pub struct DidLogEntryKeyword;

impl DidLogEntryKeyword {
    /// The constant required to register this custom keyword validator using `jsonschema::ValidationOptions::with_keyword`.
    pub const KEYWORD_NAME: &'static str = "did-log-entry";

    /// The factory method required to register this custom keyword validator using `jsonschema::ValidationOptions::with_keyword`.
    pub fn factory<'a>(
        _parent: &'a Map<String, Value>,
        value: &'a Value,
        path: Location,
    ) -> Result<Box<dyn Keyword>, ValidationError<'a>> {
        // You can use the `value` parameter to configure your validator if needed
        if value
            .as_bool()
            .is_some_and(|_| path.to_string().ends_with(Self::KEYWORD_NAME))
        {
            Ok(Box::new(DidLogEntryKeyword))
        } else {
            Err(ValidationError::custom(
                Location::new(),
                path,
                value,
                "The 'did-log-entry' keyword must be set to true",
            ))
        }
    }
}

impl Keyword for DidLogEntryKeyword {
    /// Validate instance according to https://identity.foundation/didwebvh/v0.3/#overview - each DID log entry includes a JSON array of five items:
    ///
    /// 1. The `versionId` of the entry, a value that combines the version number (starting at 1 and incrementing by one per version), a literal dash -, and a hash of the entry. The entry hash calculation links each entry to its predecessor in a ledger-like chain.
    /// 2. The `versionTime` (as stated by the DID Controller) of the entry.
    /// 3. A set of `parameters` that impact the processing of the current and future log entries. Example parameters are the version of the `did:tdw` specification and hash algorithm being used as well as the SCID and update key(s).
    /// 4. The new version of the DIDDoc as either a `value` (the full document) or a `patch` derived using JSON Patch to update the new version from the previous entry.
    /// 5. A Data Integrity (DI) proof across the entry, signed by a DID authorized to update the DIDDoc, using the `versionId` as the challenge.
    fn validate<'i>(
        &self,
        instance: &'i Value,
        location: &LazyLocation,
    ) -> Result<(), ValidationError<'i>> {
        if let Value::Array(_) = instance {
            if self.is_valid(instance) {
                Ok(())
            } else {
                Err(ValidationError::custom(
                    Location::new(),
                    location.into(),
                    instance,
                    "A DID log entry must include a JSON array of five items of the following types: string, string, object, object and array",
                ))
            }
        } else {
            Err(ValidationError::custom(
                Location::new(),
                location.into(),
                instance,
                "Value must be an array",
            ))
        }
    }

    /// Validate instance and return a boolean result.
    ///
    /// Instance is validated according to https://identity.foundation/didwebvh/v0.3/#overview - each DID log entry includes a JSON array of five items:
    ///
    /// 1. The `versionId` of the entry, a value that combines the version number (starting at 1 and incrementing by one per version), a literal dash -, and a hash of the entry. The entry hash calculation links each entry to its predecessor in a ledger-like chain.
    /// 2. The `versionTime` (as stated by the DID Controller) of the entry.
    /// 3. A set of `parameters` that impact the processing of the current and future log entries. Example parameters are the version of the `did:tdw` specification and hash algorithm being used as well as the SCID and update key(s).
    /// 4. The new version of the DIDDoc as either a `value` (the full document) or a `patch` derived using JSON Patch to update the new version from the previous entry.
    /// 5. A Data Integrity (DI) proof across the entry, signed by a DID authorized to update the DIDDoc, using the `versionId` as the challenge.
    fn is_valid(&self, instance: &Value) -> bool {
        // "each DID log entry includes a JSON array of five items"
        instance.as_array().is_some_and(|inst| {
            inst.len() == 5
                && inst
                    .first()
                    .is_some_and(|v| v.is_string() && v.as_str().is_some_and(|s| !s.is_empty()))
                && inst
                    .get(1)
                    .is_some_and(|v| v.is_string() && v.as_str().is_some_and(|s| !s.is_empty()))
                && inst.get(2).is_some_and(|v| v.is_object())
                && inst
                    .get(3)
                    .is_some_and(|v| v.is_object() && v.as_object().is_some_and(|m| !m.is_empty()))
                && inst.get(4).is_some_and(|v| {
                    v.is_array()
                        && v.as_array().is_some_and(|vec| {
                            !vec.is_empty()
                                && vec.iter().all(|t| {
                                    t.is_object() && t.as_object().is_some_and(|m| !m.is_empty())
                                })
                        })
                })
        })
    }
}

/// Yet another custom [`Keyword`] trait implementation able to validate the rule in regard
/// to `versionTime` DID log entry item (as defined by https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check)
pub struct DidVersionTimeKeyword;

impl DidVersionTimeKeyword {
    /// Required to register this custom keyword validator using `jsonschema::ValidationOptions::with_keyword`.
    pub const KEYWORD_NAME: &'static str = "did-version-time";

    /// Required to register this custom keyword validator using `jsonschema::ValidationOptions::with_keyword`.
    pub fn factory<'a>(
        _parent: &'a Map<String, Value>,
        value: &'a Value,
        path: Location,
    ) -> Result<Box<dyn Keyword>, ValidationError<'a>> {
        // You can use the `value` parameter to configure your validator if needed
        if value
            .as_bool()
            .is_some_and(|_| path.to_string().ends_with(Self::KEYWORD_NAME))
        {
            Ok(Box::new(DidVersionTimeKeyword))
        } else {
            Err(ValidationError::custom(
                Location::new(),
                path,
                value,
                "The 'did-version-time' keyword must be set to true",
            ))
        }
    }
}

impl Keyword for DidVersionTimeKeyword {
    /// Validate instance according to a custom specification i.e. a `versionTime` string representation qualifies as "valid" if:
    /// 1. is valid datetime in `ISO8601` format
    /// 2. is (as datetime) before the current time
    fn validate<'i>(
        &self,
        instance: &'i Value,
        location: &LazyLocation,
    ) -> Result<(), ValidationError<'i>> {
        if let Value::String(dt) = instance {
            // versionTime:
            // 1. Valid datetime in ISO8601 format SPEC
            // 2. datetime is before the current time

            match DateTime::parse_from_rfc3339(dt) {
                Ok(dt) => match dt.cmp(&Local::now().fixed_offset()) {
                    Ordering::Less => Ok(()),
                    _ => Err(ValidationError::custom(
                        Location::new(),
                        location.into(),
                        instance,
                        "Datetime not before current time",
                    )),
                },
                Err(_) => Err(ValidationError::custom(
                    Location::new(),
                    location.into(),
                    instance,
                    "Datetime not in ISO8601 format",
                )),
            }
        } else {
            Err(ValidationError::custom(
                Location::new(),
                location.into(),
                instance,
                "Value must be a string representing some datetime in ISO8601 format",
            ))
        }
    }

    /// Validate instance and return a boolean result.
    ///
    /// A `versionTime` string representation qualifies as "valid" if:
    /// 1. is valid datetime in `ISO8601` format
    /// 2. is (as datetime) before the current time
    fn is_valid(&self, instance: &Value) -> bool {
        instance.as_str().is_some_and(|s| {
            DateTime::parse_from_rfc3339(s)
                .is_ok_and(|dt| dt.cmp(&Local::now().fixed_offset()) == Ordering::Less)
        })
    }
}

#[cfg(test)]
mod test {
    use crate::custom_jsonschema_keywords::*;
    use jsonschema::options as jsch_opts;
    use rstest::rstest;
    use serde_json::{json, Value};

    #[rstest]
    fn test_did_log_entry_keyword_wrong_keyword() {
        const WRONG_KEYWORD_NAME: &str = "anything-but-proper-keyword-name";
        let schema = json!({WRONG_KEYWORD_NAME: true, "type": "array"});

        let validator = jsch_opts()
            /*
            .with_keyword(WRONG_KEYWORD_NAME, |_, _, _| {
                Ok(Box::new(DidLogEntryKeyword))
            }) // using closure
             */
            .with_keyword(WRONG_KEYWORD_NAME, DidLogEntryKeyword::factory) // using factory
            .build(&schema);

        assert!(validator.is_err());
        assert!(validator.err().is_some_and(|t| {
            t.to_string()
                .contains("The 'did-log-entry' keyword must be set to true")
        }));
    }

    #[rstest]
    #[case(json!(["some-version-id","some-version-time",{"":""},{"":""},[{"":""}]]), true)]
    #[case(json!(["some-version-id","some-version-time",{},{"":""},[{"":""}]]), true)] // params may be empty
    #[case(json!(["some-version-id","some-version-time",{},{"":""},[{"":""},{}]]), false)] // proof must not be empty
    #[case(json!(["","",{},{},[]]), false)] // all empty
    #[case(json!(["","",{},{},[{}]]), false)] // all empty
    #[case(json!(["","","","",""]), false)] // all JSON strings
    #[case(json!([]), false)] // empty array
    fn test_did_log_entry_keyword_validate(
        #[case] instance: Value,
        #[case] expected: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let schema = json!({DidLogEntryKeyword::KEYWORD_NAME: true, "type": "array"});

        let validator = jsch_opts()
            .with_keyword(
                DidLogEntryKeyword::KEYWORD_NAME,
                DidLogEntryKeyword::factory,
            ) // using factory
            .build(&schema)?;

        let validate = validator.validate(&instance);

        assert_eq!(expected, validate.is_ok());

        let schema = json!({DidLogEntryKeyword::KEYWORD_NAME: true, "type": "integer"}); // CAUTION wrong "type"

        let validator = jsch_opts()
            .with_keyword(
                DidLogEntryKeyword::KEYWORD_NAME,
                DidLogEntryKeyword::factory,
            ) // using factory
            .build(&schema)?;

        let validate = validator.validate(&instance);

        // should always fail since "type" is wrong ("integer" instead of "array")
        assert!(validate.is_err());
        assert!(validate.err().is_some());

        Ok(())
    }

    #[rstest]
    fn test_did_version_time_keyword_wrong_keyword() {
        const WRONG_KEYWORD_NAME: &str = "anything-but-proper-keyword-name";
        let schema = json!({WRONG_KEYWORD_NAME: true, "type": "string"});

        let validator = jsch_opts()
            /*
            .with_keyword(WRONG_KEYWORD_NAME, |_, _, _| {
                Ok(Box::new(DidVersionTimeKeyword))
            }) // using closure
             */
            .with_keyword(WRONG_KEYWORD_NAME, DidVersionTimeKeyword::factory) // using factory
            .build(&schema);

        assert!(validator.is_err());
        assert!(validator.err().is_some_and(|t| {
            t.to_string()
                .contains("The 'did-version-time' keyword must be set to true")
        }));
    }

    #[rstest]
    #[case("2012-12-12T12:12:12Z", true)]
    #[case("9999-12-12T12:12:12Z", false)] // CAUTION far beyond today
    #[case("2012-12-12T12:12:12", false)]
    #[case("2012-12-12X12:12:12X", false)]
    #[case("9999-99-99T99:99:99Z", false)]
    #[case("2012-12-12", false)]
    #[case("12:12:12", false)]
    #[case("anything but datetime", false)]
    fn test_did_version_time_keyword_validate(
        #[case] instance: String,
        #[case] expected: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let schema = json!({DidVersionTimeKeyword::KEYWORD_NAME: true, "type": "string"});

        let validator = jsch_opts()
            .with_keyword(DidVersionTimeKeyword::KEYWORD_NAME, |_, _, _| {
                Ok(Box::new(DidVersionTimeKeyword))
            }) // using closure
            .build(&schema)?;

        let instance_value = json!(instance);
        let validate = validator.validate(&instance_value);

        assert_eq!(expected, validate.is_ok());

        let schema = json!({DidVersionTimeKeyword::KEYWORD_NAME: true, "type": "integer"}); // CAUTION wrong "type"

        let validator = jsch_opts()
            .with_keyword(DidVersionTimeKeyword::KEYWORD_NAME, |_, _, _| {
                Ok(Box::new(DidVersionTimeKeyword))
            }) // using closure
            .build(&schema)?;

        let instance_value = json!(instance);
        let validate = validator.validate(&instance_value);

        // should always fail since "type" is wrong ("integer" instead of "string")
        assert!(validate.is_err());
        assert!(validate.err().is_some());

        Ok(())
    }

    #[rstest]
    #[case("2012-12-12T12:12:12Z", true)]
    #[case("9999-12-12T12:12:12Z", false)] // CAUTION far beyond today
    #[case("2012-12-12T12:12:12", false)]
    #[case("2012-12-12X12:12:12X", false)]
    #[case("9999-99-99T99:99:99Z", false)]
    #[case("2012-12-12", false)]
    #[case("12:12:12", false)]
    #[case("anything but datetime", false)]
    fn test_did_version_time_keyword_is_valid(
        #[case] instance: String,
        #[case] expected: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let schema = json!({DidVersionTimeKeyword::KEYWORD_NAME: true, "type": "string"});

        let validator = jsch_opts()
            .with_keyword(DidVersionTimeKeyword::KEYWORD_NAME, |_, _, _| {
                Ok(Box::new(DidVersionTimeKeyword))
            }) // using closure
            .build(&schema)?;

        assert_eq!(expected, validator.is_valid(&json!(instance)));

        assert!(!validator.is_valid(&json!(1234)));

        let validator = jsch_opts()
            .with_keyword(
                DidVersionTimeKeyword::KEYWORD_NAME,
                DidVersionTimeKeyword::factory,
            ) // using factory
            .build(&schema)?;

        assert_eq!(expected, validator.is_valid(&json!(instance)));

        assert!(!validator.is_valid(&json!(1234)));

        let schema = json!({DidVersionTimeKeyword::KEYWORD_NAME: true, "type": "integer"}); // CAUTION wrong "type"

        let validator = jsch_opts()
            .with_keyword(
                DidVersionTimeKeyword::KEYWORD_NAME,
                DidVersionTimeKeyword::factory,
            ) // using factory
            .build(&schema)?;

        // should always fail since "type" is wrong ("integer" instead of "string")
        assert_eq!(false, validator.is_valid(&json!(instance)));

        Ok(())
    }
}
