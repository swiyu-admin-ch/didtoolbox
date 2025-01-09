// SPDX-License-Identifier: MIT

//! This project implements the following things:
//!
//! - General util structs reused by other libraries of e-id-admin
//! - Trust did web according to the specification [trust-did-web](https://bcgov.github.io/trustdidweb/)
//!

pub mod did_tdw;
pub mod didtoolbox;
pub mod ed25519;
pub mod utils;
pub mod vc_data_integrity;

use crate::did_tdw::*;
use crate::didtoolbox::*;
use crate::ed25519::*;

uniffi::include_scaffolding!("didtoolbox");

#[cfg(test)]
mod test {
    use super::did_tdw::*;
    use super::didtoolbox::*;
    use super::ed25519::*;
    use super::utils::*;
    use core::panic;
    use mockito::{Matcher, Server, ServerOpts};
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use rstest::{fixture, rstest};
    use serde_json::{json, Value};
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

    #[rstest]
    #[case(
        "did:tdw:QMySCID:localhost%3A8000:123:456",
        "http://localhost:8000/123/456/did.jsonl"
    )]
    #[case("did:tdw:QMySCID:localhost%3A8000", "http://localhost:8000/did.jsonl")]
    #[case("did:tdw:QMySCID:localhost", "http://localhost/.well-known/did.jsonl")]
    #[case(
        "did:tdw:QMySCID:admin.ch%3A8000:123:456",
        "http://admin.ch:8000/123/456/did.jsonl"
    )]
    #[case("did:tdw:QMySCID:admin.ch%3A8000", "http://admin.ch:8000/did.jsonl")]
    #[case("did:tdw:QMySCID:admin.ch", "http://admin.ch/.well-known/did.jsonl")]
    #[case(
        "did:tdw:QMySCID:sub.admin.ch",
        "http://sub.admin.ch/.well-known/did.jsonl"
    )]
    #[case(
        "did:tdw:QMySCID:sub.admin.ch:mypath:mytrala",
        "http://sub.admin.ch/mypath/mytrala/did.jsonl"
    )]
    fn test_tdw_to_url_conversion(#[case] tdw: String, #[case] url: String) {
        let tdw = TrustDidWebId::parse_did_tdw(tdw, Some(true)).unwrap();
        let resolved_url = tdw.get_url();
        assert_eq!(resolved_url, url)
    }

    #[rstest]
    #[case("did:xyz:QMySCID:localhost%3A8000:123:456")]
    fn test_tdw_to_url_conversion_error_kind_method_not_supported(#[case] tdw: String) {
        match TrustDidWebId::parse_did_tdw(tdw, Some(true)) {
            Err(e) => assert_eq!(
                e.kind(),
                TrustDidWebIdResolutionErrorKind::MethodNotSupported
            ),
            _ => (),
        }
    }

    #[rstest]
    #[case("did:tdw:MySCID:localhost%3A8000:123:456")]
    #[should_panic(expected = "Invalid multibase format for SCID. base58btc identifier expected")]
    fn test_tdw_to_url_conversion_error_invalid_scid_multibase(#[case] tdw: String) {
        TrustDidWebId::parse_did_tdw(tdw, Some(true)).unwrap();
    }

    #[rstest]
    #[case("did:tdw:")]
    fn test_tdw_to_url_conversion_error_kind_invalid_method_specific_id(#[case] tdw: String) {
        match TrustDidWebId::parse_did_tdw(tdw, Some(true)) {
            Err(e) => assert_eq!(
                e.kind(),
                TrustDidWebIdResolutionErrorKind::InvalidMethodSpecificId
            ),
            _ => (),
        }
    }

    #[rstest]
    #[case("http://localhost:8000/123/456", "localhost%3A8000:123:456")]
    #[case("http://localhost:8000", "localhost%3A8000")]
    #[case("http://localhost/123/456", "localhost:123:456")]
    #[case("http://sub.localhost/123/456", "sub.localhost:123:456")]
    #[case("http://sub.localhost", "sub.localhost")]
    fn test_url_to_tdw_domain(#[case] url: String, #[case] domain: String) {
        let resolved_domain = get_tdw_domain_from_url(&url, Some(true)).unwrap();
        assert_eq!(domain, resolved_domain)
    }

    #[rstest]
    #[case("not_really_an_http_url")]
    #[case("http://sub.localhost/did.jsonl")]
    fn test_url_to_tdw_domain_error(#[case] url: String) {
        match get_tdw_domain_from_url(&url, Some(true)) {
            Err(e) => assert_eq!(e.kind(), TrustDidWebErrorKind::InvalidMethodSpecificId),
            _ => (),
        }
    }

    #[rstest]
    fn test_did_doc_build_scid() {
        let did_doc = DidDoc {
            //context: vec![DID_CONTEXT.to_string(), MKEY_CONTEXT.to_string()],
            context: vec![],
            id: String::from(SCID_PLACEHOLDER),
            verification_method: vec![],
            authentication: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            //controller: vec![format!("did:tdw:{}:{}", SCID_PLACEHOLDER, "domain")],
            controller: vec![],
            deactivated: None,
        };

        let scid = did_doc.build_scid();
        assert_eq!(scid.len(), 46);
        assert_eq!(scid, "QmQnmvyVZQzkRTozocCrpbyJciVoEUu65u7rz8Cocp5Rmx")
    }

    #[rstest]
    #[should_panic(expected = "Invalid did:tdw document. SCID placeholder not found")]
    fn test_did_doc_build_scid_panic() {
        let did_doc = DidDoc {
            context: vec![DID_CONTEXT.to_string(), MKEY_CONTEXT.to_string()],
            id: String::from(""),
            verification_method: vec![],
            authentication: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            controller: vec![format!("did:tdw:{}:{}", SCID_PLACEHOLDER, "domain")],
            deactivated: None,
        };

        did_doc.build_scid();
    }

    #[rstest]
    fn test_multibase_base58btc_conversion() {
        let encoded = to_multibase_base58btc("helloworld".as_bytes()); // zfP1vxkpyLWnH9dD6BQA
        //let mut buff: [u8; 16] = [0; 16];
        let mut buff = vec![0; 16];
        from_multibase_base58btc(encoded.as_str(), &mut buff);
        let decoded = String::from_utf8_lossy(&buff).to_string();
        assert!(decoded.starts_with("helloworld"));
        //assert_eq!(decoded, "helloworld");
    }

    #[rstest]
    #[should_panic(expected = "Invalid multibase format for base58btc")]
    fn test_multibase_base58btc_conversion_invalid_multibase() {
        let encoded = to_multibase_base58btc("helloworld".as_bytes()); // zfP1vxkpyLWnH9dD6BQA
        let encoded_without_multibase = encoded.chars().skip(1).collect::<String>(); // get rid of the multibase code (prefix char 'z')
        //let mut buff: [u8; 16] = [0; 16];
        let mut buff = vec![0; 16];
        from_multibase_base58btc(encoded_without_multibase.as_str(), &mut buff);
    }

    #[rstest]
    #[should_panic(
        expected = "Entered base58btc content is invalid: buffer provided to decode base58 encoded string into was too small"
    )]
    fn test_multibase_base58btc_conversion_buffer_too_small() {
        let encoded = to_multibase_base58btc("helloworld".as_bytes()); // zfP1vxkpyLWnH9dD6BQA
        //let mut buff: [u8; 16] = [0; 16];
        let mut buff = vec![0; 8]; // empirical size for "helloworld" (encoded)
        from_multibase_base58btc(encoded.as_str(), &mut buff);
    }

    #[rstest]
    fn test_key_creation(ed25519_key_pair: &Ed25519KeyPair, // fixture
    ) {
        let original_private = ed25519_key_pair.get_signing_key();
        let original_public = ed25519_key_pair.get_verifying_key();

        let new_private = Ed25519SigningKey::from_multibase(&original_private.to_multibase());
        let new_public = Ed25519VerifyingKey::from_multibase(&original_public.to_multibase());

        assert_eq!(original_private.to_multibase(), new_private.to_multibase());
        assert_eq!(original_public.to_multibase(), new_public.to_multibase());
    }

    #[rstest]
    /*#[case(
        "test_data/example_did.jsonl",
        "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu:domain.example"
    )]*/
    #[case(
        "test_data/generated_by_didtoolbox_java/did_1.jsonl",
        "did:tdw:QmajG3izTnBaTsQUCZ3FMmf4H3K6pNzps4CtSPDvaEFaoc:127.0.0.1%3A54858"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/did_2.jsonl",
        "did:tdw:QmP4JfSDqTZp6zQzfQYxfTG31X1i7VujVyDPESgTchXTtJ:127.0.0.1%3A54858:123456789"
    )]
    #[case(
        "test_data/generated_by_didtoolbox_java/did_3.jsonl",
        "did:tdw:QmZxK1EAzSW6vT7Qx5xsRREqzenDCnznRGkrgDd1L9cqvE:127.0.0.1%3A54858:123456789:123456789"
    )]
    fn test_read_did_tdw(#[case] did_log_raw_filepath: String, #[case] did_url: String) {
        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath));
        assert!(did_log_raw.is_ok());
        let did_log_raw = did_log_raw.unwrap();

        // Read the newly did doc
        let did_doc_str_v1 = TrustDidWeb::read(did_url.clone(), did_log_raw, Some(false)).unwrap();
        let did_doc_v1: Value = serde_json::from_str(&did_doc_str_v1.get_did_doc()).unwrap();

        assert!(!did_doc_v1["@context"].to_string().is_empty());
        match did_doc_v1["id"] {
            Value::String(ref doc_v1) => {
                assert!(doc_v1.eq(did_url.as_str()))
            }
            _ => panic!("Invalid did doc"),
        }
        assert!(!did_doc_v1["verificationMethod"].to_string().is_empty());
        assert!(!did_doc_v1["authentication"].to_string().is_empty());
        assert!(!did_doc_v1["controller"].to_string().is_empty());
    }

    #[rstest]
    fn test_read_did_tdwX() {
        //let did_log_raw_filepath = "test_data/example_did.jsonl";
        //let did_url: String = String::from("did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu::domain.example");
        let did_log_raw_filepath = "test_data/generated_by_didtoolbox_java/did_1.jsonl";
        let did_url: String = String::from(
            "did:tdw:QmajG3izTnBaTsQUCZ3FMmf4H3K6pNzps4CtSPDvaEFaoc:127.0.0.1%3A54858",
        );

        let did_log_raw_filepath = "test_data/generated_by_didtoolbox_java/tdw-js.jsonl";
        let did_url: String =
            String::from("did:tdw:Qmb4sce9qf13cwcosaDfRt2NmWpUfqHAdpVfRUCN8gtB8G:example.com");

        let did_log_raw = fs::read_to_string(Path::new(&did_log_raw_filepath));
        assert!(did_log_raw.is_ok());
        let did_log_raw = did_log_raw.unwrap();

        // Read the newly did doc
        let tdw_v1 = TrustDidWeb::read(did_url.clone(), did_log_raw, Some(false)).unwrap();
        let did_doc_json_v1: Value = serde_json::from_str(&tdw_v1.get_did_doc()).unwrap();
        let did_doc_obj_v1 = DidDoc::from_json(&tdw_v1.get_did_doc()); // may panic

        assert!(!did_doc_json_v1["@context"].to_string().is_empty());
        match did_doc_json_v1["id"] {
            Value::String(ref doc_v1) => {
                assert!(doc_v1.eq(did_url.as_str()))
            }
            _ => panic!("Invalid did doc"),
        }
        assert!(!did_doc_json_v1["verificationMethod"].to_string().is_empty());
        assert!(!did_doc_json_v1["authentication"].to_string().is_empty());
        assert!(!did_doc_json_v1["controller"].to_string().is_empty());

        assert_eq!(did_doc_obj_v1.id, tdw_v1.get_did());
        assert!(!did_doc_obj_v1.verification_method.is_empty());
        assert!(!did_doc_obj_v1.authentication.is_empty());
        //assert!(!did_doc_v1_obj.controller.is_empty());
    }
}
