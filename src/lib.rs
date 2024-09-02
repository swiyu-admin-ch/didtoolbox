// SPDX-License-Identifier: MIT
pub mod didtoolbox;
pub mod utils;
pub mod vc_data_integrity;
pub mod ed25519;
pub mod did_tdw;

use crate::didtoolbox::*;
use crate::ed25519::*;
use crate::did_tdw::*;
use rand::{Rng}; // 0.8

uniffi::include_scaffolding!("didtoolbox");

#[cfg(test)]
mod test {
    use core::panic;
    use std::vec;
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use super::didtoolbox::*;
    use super::ed25519::*;
    use super::did_tdw::*;
    use rstest::{fixture, rstest};
    use serde_json::json;

    // INFO: To run the test you need to start the did_server located in the folder with the same name

    #[fixture]
    fn unique_base_url() -> String {
        let random_thing: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        format!("https://localhost:8000/{random_thing}")
    }

    #[rstest]
    #[case("did:tdw:myScid:localhost%3A8000:123:456", "http://localhost:8000/123/456/did.jsonl")]
    #[case("did:tdw:myScid:localhost%3A8000", "http://localhost:8000/did.jsonl")]
    #[case("did:tdw:myScid:localhost", "http://localhost/.well-known/did.jsonl")]
    #[case("did:tdw:myScid:admin.ch%3A8000:123:456", "http://admin.ch:8000/123/456/did.jsonl")]
    #[case("did:tdw:myScid:admin.ch%3A8000", "http://admin.ch:8000/did.jsonl")]
    #[case("did:tdw:myScid:admin.ch", "http://admin.ch/.well-known/did.jsonl")]
    #[case("did:tdw:myScid:sub.admin.ch", "http://sub.admin.ch/.well-known/did.jsonl")]
    #[case("did:tdw:myScid:sub.admin.ch:mypath:mytrala", "http://sub.admin.ch/mypath/mytrala/did.jsonl")]
    fn test_tdw_to_url_conversion(#[case] tdw: String, #[case] url: String) {
        let resolved_url = get_url_from_tdw(&tdw, Some(true));
        assert_eq!(resolved_url, url)
    }

    #[rstest]
    #[case("http://localhost:8000/123/456", "localhost%3A8000:123:456")]
    #[case("http://localhost:8000", "localhost%3A8000")]
    #[case("http://localhost/123/456", "localhost:123:456")]
    #[case("http://sub.localhost/123/456", "sub.localhost:123:456")]
    #[case("http://sub.localhost", "sub.localhost")]
    fn test_url_to_tdw_domain(#[case] url: String, #[case] domain: String) {
        let resolved_domain = get_tdw_domain_from_url(&url, Some(true));
        assert_eq!(domain, resolved_domain)
    }

    #[rstest]
    fn test_did_wrapping(unique_base_url: String) {
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::generate();
        let did = processor.create(unique_base_url, &key_pair, Some(false));
        let did_read = TrustDidWeb::read(did.clone(), Some(true));
        let did_doc = DidDoc::from_json(&did_read.get_did_doc());
        assert_eq!(did_doc.id, did);
    }
    
    #[rstest]
    fn test_key_creation() {
        let key_pair = Ed25519KeyPair::generate();
        let original_private = key_pair.get_signing_key();
        let original_public = key_pair.get_verifying_key();

        let new_private = Ed25519SigningKey::from_multibase(&original_private.to_multibase());
        let new_public = Ed25519VerifyingKey::from_multibase(&original_public.to_multibase());

        assert_eq!(original_private.to_multibase(), new_private.to_multibase());
        assert_eq!(original_public.to_multibase(), new_public.to_multibase());
    }

    #[rstest]
    fn test_create_did(unique_base_url: String) {
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::generate();
        print!("{}",key_pair.get_signing_key().to_multibase());
        let did = processor.create(unique_base_url, &key_pair, Some(false));
        print!("{}", did);
        assert!(did.len() > 0);
    }

    #[rstest]
    fn test_read_did_tdw() {
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::from("uQm7HM3hPG8ar7HqoXAC7RW_fy9Ah5TnLHwyIid-lh4I");
        println!("|> {} <|",key_pair.get_signing_key().to_multibase());
        let did = processor.create("https://localhost:8000/12345678".to_string(), &key_pair, Some(false));
        
        // Read original did document
        let did_doc_str_v1 = processor.read(String::from(&did), Some(false));
        let did_doc_v1: serde_json::Value = serde_json::from_str(&did_doc_str_v1).unwrap();
        match did_doc_v1["id"] {
            serde_json::Value::String(ref s) => {
                println!("{}", s);
                assert!(s.eq("did:tdw:ga3geodemrsggm3cmqydozlgguygcyrsgyydonlfgq2wgyrumzrdaylbgrsdcmbygnsten3gga2tonddgm3toyzqgmzdsyrxgvrdsoi=:localhost%3A8000:12345678"))
            },
            _ => panic!("Invalid did doc"),
        }
    }

    #[rstest]
    fn test_update_did_tdw(unique_base_url: String) {
        // Register did tdw
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::generate();
        let did = processor.create(unique_base_url, &key_pair, Some(false));
        
        // Read original did doc 
        let did_doc_str_v1 = processor.read(String::from(&did), Some(false));
        let did_doc_v1: serde_json::Value = serde_json::from_str(&did_doc_str_v1).unwrap();

        // Update did document by adding a new verification method
        let mut did_doc_v2: serde_json::Value = did_doc_v1.clone();
        let verification_method: VerificationMethod = VerificationMethod {
            id: String::from("did:jwk:123#type1"),
            controller: String::from("did:jwk:123"),
            verification_type: String::from("TestKey"),
            public_key_multibase: Some(String::from("SomeKey")),
            public_key_jwk: None
        };
        did_doc_v2["assertionMethod"] = json!(vec![serde_json::to_value(&verification_method).unwrap()]);
        let did_doc_v2 = did_doc_v2.to_string();
        processor.update(did.clone(), did_doc_v2, &key_pair, Some(false));

        // Read updated did doc with new property
        let did_doc_str_v3 = processor.read(String::from(&did), Some(false));
        let did_doc_v3: serde_json::Value = serde_json::from_str(&did_doc_str_v3).unwrap();
        match did_doc_v3["assertionMethod"][0]["id"] {
            serde_json::Value::String(ref s) => assert!(s.eq("did:jwk:123#type1")),
            _ => panic!("Invalid did doc"),
        };
    }

    #[rstest]
    #[should_panic(expected = "Invalid key pair. The provided key pair is not the one referenced in the did doc")]
    fn test_update_did_tdw_with_non_controller_did(unique_base_url: String) {
        // Register did tdw
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::generate();
        let did = processor.create(unique_base_url, &key_pair, Some(false));
        
        // Read original did doc 
        let did_doc_str_v1 = processor.read(String::from(&did), Some(false));
        let did_doc_v1: serde_json::Value = serde_json::from_str(&did_doc_str_v1).unwrap();

        // Update did document by adding a new verification method
        let mut did_doc_v2: serde_json::Value = did_doc_v1.clone();
        let verification_method: VerificationMethod = VerificationMethod {
            id: String::from("did:jwk:123#type1"),
            controller: String::from("did:jwk:123"),
            verification_type: String::from("TestKey"),
            public_key_multibase: Some(String::from("SomeKey")),
            public_key_jwk: None
        };
        did_doc_v2["assertionMethod"] = json!(vec![serde_json::to_value(&verification_method).unwrap()]);
        let did_doc_v2 = did_doc_v2.to_string();
        let unauthorized_key_pair = Ed25519KeyPair::generate();
        processor.update(did.clone(), did_doc_v2, &unauthorized_key_pair, Some(false));
    }

    #[rstest]
    #[should_panic(expected = "Invalid did doc. The did doc is already deactivated. For simplicity reasons we don't allow updates of dids")]
    fn test_deactivate_did_tdw(unique_base_url: String) {
        // Register did tdw
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::generate();
        let did = processor.create(unique_base_url, &key_pair, Some(false));

        // Deactivate did
        processor.deactivate(did.clone(), &key_pair, Some(false));

        // Read original did doc 
        let did_doc_str_v1 = processor.read(String::from(&did), Some(false));
        let did_doc_v1: serde_json::Value = serde_json::from_str(&did_doc_str_v1).unwrap();

        // Update did document after it has been deactivated
        let mut did_doc_v2: serde_json::Value = did_doc_v1.clone();
        let verification_method: VerificationMethod = VerificationMethod {
            id: String::from("did:jwk:123#type1"),
            controller: String::from("did:jwk:123"),
            verification_type: String::from("TestKey"),
            public_key_multibase: Some(String::from("SomeKey")),
            public_key_jwk: None
        };
        did_doc_v2["assertionMethod"] = json!(vec![serde_json::to_value(&verification_method).unwrap()]);

        let did_doc_v2 = did_doc_v2.to_string();
        processor.update(did.clone(), did_doc_v2, &key_pair, Some(false));
    }
}