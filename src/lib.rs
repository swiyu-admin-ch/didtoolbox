// SPDX-License-Identifier: MIT

//! This project implements the following things:
//!
//! - General util structs reused by other libraries of swiyu-admin-ch
//! - Trust did web according to the specification [trust-did-web](https://bcgov.github.io/trustdidweb/)
//!

extern crate core;

pub mod did_tdw;
pub mod did_tdw_parameters;
pub mod didtoolbox;
pub mod ed25519;
pub mod errors;
pub mod jcs_sha256_hasher;
pub mod multibase;
pub mod vc_data_integrity;

// CAUTION All structs required by UniFFI bindings generator (declared in UDL) MUST also be "used" here
use did_tdw::*;
use didtoolbox::*;
use ed25519::*;
use errors::*;

uniffi::include_scaffolding!("didtoolbox");

#[cfg(test)]
mod test {
    use super::did_tdw::*;
    use super::didtoolbox::*;
    use super::ed25519::*;
    use super::jcs_sha256_hasher::*;
    use super::multibase::*;
    use crate::did_tdw_parameters::*;
    use crate::errors::*;
    use crate::vc_data_integrity::*;
    use chrono::DateTime;
    use core::panic;
    use hex::encode as hex_encode;
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use rstest::{fixture, rstest};
    use serde_json::{json, Value as JsonValue};
    use std::path::Path;
    use std::{fs, vec};
    //
    // INFO: To run tests in this module, it is NO NEED to start the 'did_server'
    //       located in the folder with the same name anymore!!!
    //
    // However, if still interested in using it (as kind of playground), here is a short how-to manual.
    //
    // For instance on macOS, a Linux container may be started by running following commands:
    // - install podman:              brew update && brew install podman
    // - to start a container:        podman run -it --rm -v $(pwd):$(pwd):Z -w $(pwd) -p 8000:8000 rust
    // - to setup system packages:    apt-get update && apt-get install python3-fastapi jq lsof -y
    // - to generate bindings:        source python-build.sh
    // - to boot up the test-server:  python3 did_server/main.py &
    //                                ("lsof -i:8000" should produce some output)
    // - to (smoke) test bindings:    python3 did_server/playground.py | tail -2 | jq
    //                                Output:
    //                                INFO:     127.0.0.1:55058 - "POST /123456789/did.jsonl HTTP/1.1" 201 Created
    //                                INFO:     127.0.0.1:55068 - "GET /123456789/did.jsonl HTTP/1.1" 200 OK
    // - and the last, but not least: cargo test --color=always --profile test --package didtoolbox --lib test --no-fail-fast --config env.RUSTC_BOOTSTRAP=\"1\" -- --format=json -Z unstable-options --show-output
    // - press CTRL+D to exit container
    //

    #[fixture]
    fn unique_base_url() -> String {
        let random_thing: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        format!("https://localhost:8000/{random_thing}")
    }

    #[fixture]
    #[once]
    fn ed25519_key_pair() -> Ed25519KeyPair {
        Ed25519KeyPair::generate()
    }

    // The first four testcases come from: https://identity.foundation/didwebvh/v0.3/#example-7
    #[rstest]
    #[case(
        "did:tdw:{SCID}:example.com",
        "https://example.com/.well-known/did.jsonl"
    )]
    #[case(
        "did:tdw:{SCID}:issuer.example.com",
        "https://issuer.example.com/.well-known/did.jsonl"
    )]
    #[case(
        "did:tdw:{SCID}:example.com:dids:issuer",
        "https://example.com/dids/issuer/did.jsonl"
    )]
    #[case(
        "did:tdw:{SCID}:example.com%3A3000:dids:issuer",
        "https://example.com:3000/dids/issuer/did.jsonl"
    )]
    #[case(
        "did:tdw:QMySCID:localhost%3A8000:123:456",
        "https://localhost:8000/123/456/did.jsonl"
    )]
    #[case(
        "did:tdw:QMySCID:localhost%3A8000",
        "https://localhost:8000/.well-known/did.jsonl"
    )]
    #[case("did:tdw:QMySCID:localhost", "https://localhost/.well-known/did.jsonl")]
    #[case(
        "did:tdw:QMySCID:admin.ch%3A8000:123:456",
        "https://admin.ch:8000/123/456/did.jsonl"
    )]
    #[case(
        "did:tdw:QMySCID:admin.ch%3A8000",
        "https://admin.ch:8000/.well-known/did.jsonl"
    )]
    #[case("did:tdw:QMySCID:admin.ch", "https://admin.ch/.well-known/did.jsonl")]
    #[case(
        "did:tdw:QMySCID:sub.admin.ch",
        "https://sub.admin.ch/.well-known/did.jsonl"
    )]
    #[case(
        "did:tdw:QMySCID:sub.admin.ch:mypath:mytrala",
        "https://sub.admin.ch/mypath/mytrala/did.jsonl"
    )]
    #[case("did:tdw:QMySCID:localhost:%2A", "https://localhost/%2A/did.jsonl")]
    #[case(
        "did:tdw:QMySCID:localhost:.hidden",
        "https://localhost/.hidden/did.jsonl"
    )]
    fn test_tdw_to_url_conversion(#[case] tdw: String, #[case] url: String) {
        let tdw = TrustDidWebId::parse_did_tdw(tdw).unwrap();
        let resolved_url = tdw.get_url();
        assert_eq!(resolved_url, url)
    }

    #[rstest]
    #[case("did:xyz:QMySCID:localhost%3A8000:123:456")]
    #[case("url:tdw:QMySCID:localhost%3A8000:123:456")]
    fn test_tdw_to_url_conversion_error_kind_method_not_supported(#[case] tdw: String) {
        match TrustDidWebId::parse_did_tdw(tdw) {
            Err(e) => assert_eq!(
                e.kind(),
                TrustDidWebIdResolutionErrorKind::MethodNotSupported
            ),
            _ => panic!(
                "Expected error kind: {:?}",
                TrustDidWebIdResolutionErrorKind::MethodNotSupported
            ),
        }
    }

    #[rstest]
    #[case("did:tdw")] // method only
    #[case("did:tdw::")] // method only
    #[case("did:tdw:::")] // method only
    #[case("did:tdw::::")] // method only
    #[case("did:tdw:SCID")] // no fully qualified domain
    #[case("did:tdw:SCID:::")] // no fully qualified domain
    #[case("did:tdw:SCID::123:")] // no fully qualified domain
    #[case("did:tdw::localhost%3A8000:123:456")] // empty/missing SCID
    fn test_tdw_to_url_conversion_error_kind_invalid_method_specific_id(#[case] tdw: String) {
        match TrustDidWebId::parse_did_tdw(tdw) {
            Err(e) => assert_eq!(
                e.kind(),
                TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId
            ),
            _ => panic!(
                "Expected error kind: {:?}",
                TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId
            ),
        }
    }

    #[rstest]
    fn test_multibase_conversion() -> Result<(), Box<dyn std::error::Error>> {
        let multibase = MultibaseEncoderDecoder::default();
        let encoded = multibase.encode("helloworld".as_bytes()); // zfP1vxkpyLWnH9dD6BQA
                                                                 //let mut buff: [u8; 16] = [0; 16];
        let mut buff = vec![0; 16];
        multibase.decode_onto(encoded.as_str(), &mut buff)?;
        let decoded = String::from_utf8_lossy(&buff).to_string();
        assert!(decoded.starts_with("helloworld"));
        //assert_eq!(decoded, "helloworld");
        Ok(())
    }

    #[rstest]
    #[should_panic(expected = "Invalid multibase algorithm identifier 'Base58btc'")]
    fn test_multibase_conversion_invalid_multibase() {
        let multibase = MultibaseEncoderDecoder::default();
        let encoded = multibase.encode("helloworld".as_bytes()); // zfP1vxkpyLWnH9dD6BQA
        let encoded_without_multibase = encoded.chars().skip(1).collect::<String>(); // get rid of the multibase code (prefix char 'z')
                                                                                     //let mut buff: [u8; 16] = [0; 16];
        let mut buff = vec![0; 16];
        let _ = multibase.decode_onto(encoded_without_multibase.as_str(), &mut buff);
    }

    #[rstest]
    #[should_panic(expected = "buffer provided to decode base58 encoded string into was too small")]
    fn test_multibase_conversion_buffer_too_small() {
        let multibase = MultibaseEncoderDecoder::default();
        let encoded = multibase.encode("helloworld".as_bytes()); // zfP1vxkpyLWnH9dD6BQA
                                                                 //let mut buff: [u8; 16] = [0; 16];
        let mut buff = vec![0; 8]; // empirical size for "helloworld" (encoded)
        match multibase.decode_onto(encoded.as_str(), &mut buff) {
            Ok(_) => panic!("Error expected to be returned"),
            Err(err) => panic!("{}", err),
        }
    }

    #[rstest]
    #[case(
        // Example taken from https://multiformats.io/multihash/#sha2-256---256-bits-aka-sha256
        "Merkle–Damgård",
        "122041dd7b6443542e75701aa98a0c235951a28a0d851b11564d20022ab11d2589a8"
    )]
    fn test_encode_multihash_sha256(#[case] input: String, #[case] expected: String) {
        let hash = hex_encode(JcsSha256Hasher::default().encode_multihash(input));
        assert_eq!(hash, expected);
    }

    #[rstest]
    fn test_key_pair_multibase_conversion(
        ed25519_key_pair: &Ed25519KeyPair, // fixture
    ) -> Result<(), Box<dyn std::error::Error>> {
        let original_private = ed25519_key_pair.get_signing_key();
        let original_public = ed25519_key_pair.get_verifying_key();

        let new_private = Ed25519SigningKey::from_multibase(&original_private.to_multibase())?;
        let new_public = Ed25519VerifyingKey::from_multibase(&original_public.to_multibase())?;

        assert_eq!(original_private.to_multibase(), new_private.to_multibase());
        assert_eq!(original_public.to_multibase(), new_public.to_multibase());
        Ok(())
    }

    #[rstest]
    fn test_key_pair_creation_from_multibase(
        ed25519_key_pair: &Ed25519KeyPair, // fixture
    ) -> Result<(), Box<dyn std::error::Error>> {
        let new_ed25519_key_pair =
            Ed25519KeyPair::from(&ed25519_key_pair.get_signing_key().to_multibase())?;

        assert_eq!(ed25519_key_pair, &new_ed25519_key_pair);
        assert_eq!(
            ed25519_key_pair.get_signing_key().to_multibase(),
            new_ed25519_key_pair.signing_key.to_multibase()
        );
        assert_eq!(
            ed25519_key_pair.get_verifying_key().to_multibase(),
            new_ed25519_key_pair.verifying_key.to_multibase()
        );
        Ok(())
    }

    /// A rather trivial assertion helper around TrustDidWebError.
    fn assert_trust_did_web_error<T>(
        res: Result<T, TrustDidWebError>,
        expected_kind: TrustDidWebErrorKind,
        error_contains: &str,
    ) {
        assert!(res.is_err());
        let err = res.err();
        assert!(err.is_some());
        let err = err.unwrap();
        assert_eq!(err.kind(), expected_kind);

        let err_to_string = err.to_string();
        assert!(
            err_to_string.contains(error_contains),
            "expected '{}' is not mentioned in '{}'",
            error_contains,
            err_to_string
        );
    }

    /// A rather trivial unit testing helper.
    fn build_valid_params_json_string() -> String {
        json!(DidMethodParameters::for_genesis_did_doc(
            "123".to_string(),
            "123".to_string()
        ))
        .to_string()
    }

    #[rstest]
    // doc needs 5 entries
    #[case("[1,2,3]", "Invalid did log entry")]
    // invalid version id
    #[case("[\"1\",2,3,4,5]", "Invalid entry hash format")]
    #[case(
        "[\"invalidNumber-hash\",2,3,4,5]",
        "the <versionNumber> is not an (unsigned) integer."
    )]
    // invalid time
    #[case("[\"1-hash\",[1234],3,4,5]", "Invalid versionTime.")]
    #[case("[\"1-hash\",\"invalidTime\",3,4,5]", "Invalid versionTime.")]
    // missing params
    #[case(
        "[\"1-hash\",\"2012-12-12T12:12:12Z\",{},4,5]",
        "Missing DID Document parameters"
    )]
    // JSON 'patch' is not supported
    #[case(format!("[\"1-hash\",\"2012-12-12T12:12:12Z\",{},{{\"patch\":0}},5]", build_valid_params_json_string()), "JSON 'patch' is not supported")]
    // JSON 'value' needs to be a valid did doc
    #[case(format!("[\"1-hash\",\"2012-12-12T12:12:12Z\",{},{{\"value\":\"invalidDoc\"}},5]", build_valid_params_json_string()), "Missing DID document: invalid type")]
    fn test_invalid_did_log(
        #[case] input_str: String,
        #[case] error_string: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_trust_did_web_error(
            DidDocumentState::from(input_str),
            TrustDidWebErrorKind::DeserializationFailed,
            error_string,
        );
        Ok(())
    }

    #[rstest]
    // emtpy proof
    #[case("[]", "Empty proof array detected")]
    // two proofs
    #[case("[\"proof1\", \"proof2\"]", "A single proof is currently supported")]
    // invalid json
    #[case("[{\"key:}]", "Malformed proof format, expected single-element JSON array")]
    // invalid type
    #[case(
        "[{\"type\":\"invalidType\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]", 
        "Unsupported proof's type"
    )]
    // unsupported cryptosuite
    #[case(
        "[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"unsupportedCrypto\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]",
        "Unsupported proof's cryptosuite"
    )]
    // invalid created date
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"invalidDate\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]",
        "Invalid proof's creation datetime format"
    )]
    // invalid verification method
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"invalidMethod\", \"proofPurpose\":\"authentication\"}]",
        "Unsupported proof's verificationMethod"
    )]
    // invalid proof purpose
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"invalidPurpose\"}]",
        "Unsupported proof's proofPurpose"
    )]
    // invalid @context
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"@context\":\"invalidContext\"}]",
        "Invalid format of 'context' entry"
    )]
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"@context\":[\"validContext\", true, 3]}]",
        "Invalid type of 'context' entry"
    )]
    // invalid proof challenge
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\"}]",
        "Missing proof's challenge parameter."
    )]
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"challenge\":[false, 2]}]",
        "Wrong format of proof's challenge parameter"
    )]
    // invalid proof challenge
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"challenge\":\"1-hash\"}]",
        "Missing proofValue parameter"
    )]
    #[case("[{\"type\":\"DataIntegrityProof\", \"cryptosuite\":\"eddsa-jcs-2022\", \"created\":\"2012-12-12T12:12:12Z\", \"verificationMethod\": \"did:key:123\", \"proofPurpose\":\"authentication\", \"challenge\":\"1-hash\", \"proofValue\":5}]",
        "Wrong format of proofValue parameter"
    )]
    fn test_invalid_proof_parsing(
        #[case] input_str: String,
        #[case] error_string: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_trust_did_web_error(
            DataIntegrityProof::from(input_str),
            TrustDidWebErrorKind::InvalidIntegrityProof,
            error_string,
        );

        Ok(())
    }

    #[rstest]
    fn test_cryptosuite_add_and_verify_proof() -> Result<(), Box<dyn std::error::Error>> {
        // From https://www.w3.org/TR/vc-di-eddsa/#example-credential-without-proof-0
        let credential_without_proof = json!(
            {
                 "@context": [
                     "https://www.w3.org/ns/credentials/v2",
                     "https://www.w3.org/ns/credentials/examples/v2"
                 ],
                 "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
                 "type": ["VerifiableCredential", "AlumniCredential"],
                 "name": "Alumni Credential",
                 "description": "A minimum viable example of an Alumni Credential.",
                 "issuer": "https://vc.example/issuers/5678",
                 "validFrom": "2023-01-01T00:00:00Z",
                 "credentialSubject": {
                     "id": "did:example:abcdefgh",
                     "alumniOf": "The School of Examples"
                 }
            }
        );

        let scid = JcsSha256Hasher::default()
            .base58btc_encode_multihash(&credential_without_proof)
            .unwrap();

        // From https://www.w3.org/TR/vc-di-eddsa/#example-proof-options-document-1
        let options = CryptoSuiteProofOptions::new(
            None,
            Some(DateTime::parse_from_rfc3339("2023-02-24T23:36:38Z").unwrap().to_utc()),
            "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2".to_string(),
            Some("assertionMethod".to_string()),
            Some(vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://www.w3.org/ns/credentials/examples/v2".to_string(),
            ]),
            format!("1-{}", scid),
        );

        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
        let suite = EddsaJcs2022Cryptosuite {
            verifying_key: Some(Ed25519VerifyingKey::from_multibase(
                "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
            )?),
            signing_key: Some(Ed25519SigningKey::from_multibase(
                "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
            )?),
        };

        let secured_document = suite.add_proof(&credential_without_proof, &options)?;

        assert!(
            !secured_document.is_null(),
            "'add_proof' method returned Value::Null"
        );
        let proof = &secured_document["proof"];
        assert!(proof.is_array(), "'proof' must be a JSON array");
        let proof_value = &proof[0]["proofValue"];
        assert!(proof_value.is_string(), "'proofValue' must be a string");

        // https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-base58-btc-1
        // CAUTION The value suggested in the spec (z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX)
        //         is irrelevant here since the add_proof method also computes a proof's challenge (if not supplied already)
        assert!(proof_value.to_string().contains("z3swhrb2DFocc562PATcKiv8YtjUzxLdfr4dhb9DidvG2BNkJqAXe65bsEMiNJdGKDdnYxiBa7cKXXw4cSKCvMcfm"));

        let doc_hash = JcsSha256Hasher::default().encode_hex(&credential_without_proof)?;
        // From https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-credential-without-proof-hex-0
        assert_eq!(
            "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19",
            doc_hash
        );

        // sanity check
        let proof_as_string = serde_json::to_string(proof)?;
        let data_integrity_proof = DataIntegrityProof::from(proof_as_string)?;
        assert!(
            suite.verify_proof(&data_integrity_proof, &doc_hash).is_ok(),
            "Sanity check failed"
        );

        Ok(())
    }

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

    #[rstest]
    #[case("test_data/generated_by_didtoolbox_java/did_1.jsonl")]
    #[case("test_data/generated_by_didtoolbox_java/did_2.jsonl")]
    #[case("test_data/generated_by_didtoolbox_java/did_3.jsonl")]
    #[case("test_data/generated_by_tdw_js/unique_update_keys.jsonl")]
    fn test_generate_version_id(
        #[case] did_log_raw_filepath: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath))?;
        let did_document = DidDocumentState::from(did_log_raw)?;
        for did_log in did_document.did_log_entries {
            let generated_version_id = did_log.build_version_id()?;
            assert!(generated_version_id == did_log.version_id);
        }
        Ok(())
    }

    #[rstest]
    /*#[case(
        "test_data/example_did.jsonl",
        "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu:domain.example"
    )]*/
    #[case(
        "test_data/generated_by_tdw_js/single_update_key.jsonl",
        "did:tdw:QmXjp5qhSEvm8oXip43cDX62hZhHZdAMYv7Magy1tkffSz:example.com"
    )]
    #[case(
        "test_data/generated_by_tdw_js/unique_update_keys.jsonl",
        "did:tdw:QmXjp5qhSEvm8oXip43cDX62hZhHZdAMYv7Magy1tkffSz:example.com"
    )]
    #[case(
        "test_data/generated_by_tdw_js/alternate_update_keys.jsonl",
        "did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/did_1.jsonl",
        "did:tdw:QmPJ85fz4FMocjsm6qqHkN2DqJLYJLQwvXAcNDFemM1Jgg:127.0.0.1%3A54858"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/did_2.jsonl",
        "did:tdw:QmUSyQohHF4tcRhdkJYoamuMQAXQmYBoFLCot35xd7dPda:127.0.0.1%3A54858:123456789"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/did_3.jsonl",
        "did:tdw:QmcTh4ghpn5HHuubeGzt5JMS9PfAyxZLVPn3zTq3TYP69v:127.0.0.1%3A54858:123456789:123456789"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/empty_did_params.jsonl",
        "did:tdw:QmeLapUpgZeyyCmjG8vRKjXYwEAXaYJyAT4ohzR73jZf1A:127.0.0.1%3A54858"
    )]
    fn test_read_did_tdw(
        #[case] did_log_raw_filepath: String,
        #[case] did_url: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath))?;

        // Read the newly did doc
        let tdw_v1 = TrustDidWeb::read(did_url.clone(), did_log_raw)?;
        let did_doc_v1: JsonValue = serde_json::from_str(&tdw_v1.get_did_doc())?;
        let did_doc_obj_v1 = DidDoc::from_json(&tdw_v1.get_did_doc())?;

        assert!(!did_doc_v1["@context"].to_string().is_empty());
        match did_doc_v1["id"] {
            JsonValue::String(ref doc_v1) => {
                assert!(doc_v1.eq(did_url.as_str()))
            }
            _ => panic!("Invalid did doc"),
        }
        assert!(!did_doc_v1["verificationMethod"].to_string().is_empty());
        assert!(!did_doc_v1["authentication"].to_string().is_empty());
        assert!(!did_doc_v1["controller"].to_string().is_empty());

        assert_eq!(did_doc_obj_v1.id, tdw_v1.get_did());
        assert!(!did_doc_obj_v1.verification_method.is_empty());
        assert!(!did_doc_obj_v1.authentication.is_empty());
        //assert!(!did_doc_v1_obj.controller.is_empty());

        Ok(())
    }

    #[rstest]
    #[case(
        "test_data/generated_by_tdw_js/unhappy_path/not_authorized.jsonl",
        "did:tdw:QmXjp5qhSEvm8oXip43cDX62hZhHZdAMYv7Magy1tkffSz:example.com"
    )]
    fn test_read_did_tdw_unauthorized_key(
        #[case] did_log_raw_filepath: String,
        #[case] did_url: String,
    ) {
        //let did_log_raw_filepath = "test_data/generated_by_tdw_js/unhappy_path/not_authorized.jsonl";
        //let did_url: String = String::from("did:tdw:QmXjp5qhSEvm8oXip43cDX62hZhHZdAMYv7Magy1tkffSz:example.com");

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap();

        // CAUTION No ? operator required here as we want to inspect the expected error
        let tdw_v1 = TrustDidWeb::read(did_url.clone(), did_log_raw);

        assert!(tdw_v1.is_err());
        let err = tdw_v1.err();
        assert!(err.is_some());
        let err = err.unwrap();
        assert_eq!(err.kind(), TrustDidWebErrorKind::InvalidIntegrityProof);
        // e.g. "invalid DID log integration proof: Key extracted from proof is not authorized for update: z6Mkwf4PgXLq8sRfucTggtZXmigKZP7gQhFamk3XHGV54QvF"
        assert!(err
            .to_string()
            .contains("Key extracted from proof is not authorized for update"));
    }

    #[rstest]
    #[case(
        "test_data/generated_by_tdw_js/deactivated.jsonl",
        "did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com"
    )]
    fn test_read_did_tdw_deactivated(
        #[case] did_log_raw_filepath: String,
        #[case] did_url: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        //let did_log_raw_filepath = "test_data/generated_by_tdw_js/deactivated.jsonl";
        //let did_url: String = String::from("did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com");

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath))?;

        // Read the newly did doc
        let tdw_v1 = TrustDidWeb::read(did_url.clone(), did_log_raw)?;
        let did_doc_json_v1: JsonValue = serde_json::from_str(&tdw_v1.get_did_doc())?;
        let did_doc_obj_v1 = DidDoc::from_json(&tdw_v1.get_did_doc())?;

        assert!(!did_doc_json_v1["@context"].to_string().is_empty());
        match did_doc_json_v1["id"] {
            JsonValue::String(ref doc_v1) => {
                assert!(doc_v1.eq(did_url.as_str()), "DID mismatch")
            }
            _ => panic!("Invalid did doc"),
        }
        assert!(!did_doc_json_v1["verificationMethod"].to_string().is_empty());
        assert!(!did_doc_json_v1["authentication"].to_string().is_empty());
        assert!(!did_doc_json_v1["controller"].to_string().is_empty());

        assert_eq!(did_doc_obj_v1.id, tdw_v1.get_did());
        // CAUTION after deactivation these should be empty
        assert!(did_doc_obj_v1.verification_method.is_empty());
        assert!(did_doc_obj_v1.authentication.is_empty());
        //assert!(!did_doc_v1_obj.controller.is_empty());

        Ok(())
    }

    #[rstest]
    #[case(
        "test_data/generated_by_tdw_js/already_deactivated.jsonl",
        "did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com"
    )]
    fn test_read_did_tdw_already_deactivated(
        #[case] did_log_raw_filepath: String,
        #[case] did_url: String,
    ) {
        //let did_log_raw_filepath = "test_data/generated_by_tdw_js/already_deactivated.jsonl";
        //let did_url: String = String::from("did:tdw:QmdSU7F2rF8r4m6GZK7Evi2tthfDDxhw3NppU8pJMbd2hB:example.com");

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath)).unwrap();

        // CAUTION No ? operator required here as we want to inspect the expected error
        let tdw_v1 = TrustDidWeb::read(did_url.clone(), did_log_raw);

        assert!(tdw_v1.is_err());
        let err = tdw_v1.err();
        assert!(err.is_some());
        let err = err.unwrap();
        assert_eq!(err.kind(), TrustDidWebErrorKind::InvalidDidDocument);
        // e.g. "invalid DID log integration proof: Key extracted from proof is not authorized for update: z6Mkwf4PgXLq8sRfucTggtZXmigKZP7gQhFamk3XHGV54QvF"
        assert!(err
            .to_string()
            .contains("This DID document is already deactivated"));
    }
}
