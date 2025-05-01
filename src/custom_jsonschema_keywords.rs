// SPDX-License-Identifier: MIT

use chrono::{DateTime, Local};
use jsonschema::{
    paths::{LazyLocation, Location},
    Keyword, ValidationError,
};
use serde_json::{Map, Value};
use std::cmp::Ordering;

/// The custom `jsonschema::Keyword` trait implementation able to validate rules defined by https://confluence.bit.admin.ch/display/EIDTEAM/DID+Log+Conformity+Check
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
        if value.as_bool() == Some(true) {
            Ok(Box::new(DidVersionTimeKeyword))
        } else {
            Err(ValidationError::custom(
                Location::new(),
                path,
                value,
                "The 'version-time' keyword must be set to true",
            ))
        }
    }
}

impl Keyword for DidVersionTimeKeyword {
    /// A `versionTime` string representation qualifies as "valid" if:
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
                "Value must be a string",
            ))
        }
    }

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
    use crate::custom_jsonschema_keywords::DidVersionTimeKeyword;
    use jsonschema::options as jsch_opts;
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case("2012-12-12T12:12:12Z", true)]
    #[case("9999-12-12T12:12:12Z", false)] // CAUTION far beyond today
    #[case("2012-12-12T12:12:12", false)]
    #[case("2012-12-12X12:12:12X", false)]
    #[case("9999-99-99T99:99:99Z", false)]
    #[case("2012-12-12", false)]
    #[case("12:12:12", false)]
    #[case("anything but datetime", false)]
    fn test_validate(
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
    fn test_is_valid(
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
