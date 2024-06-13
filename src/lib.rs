pub mod didtoolbox;
pub mod utils;
pub mod vc_data_integrity;
pub mod ed25519;
pub mod did_tdw;

use crate::didtoolbox::*;
use crate::ed25519::*;
use crate::did_tdw::*;

uniffi::include_scaffolding!("didtoolbox");

#[cfg(test)]
mod test {
    use core::panic;
    use std::vec;

    use super::didtoolbox::*;
    use super::ed25519::*;
    use super::did_tdw::*;
    use rstest::rstest;
    use serde_json::json;

    /// TODO
    /// - Decoding of base 32 fails from time to time due to padding
    /// - Move doulbe decoding to HttpResolver

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
    fn test_create_did() {
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::generate();
        print!("{}",key_pair.get_signing_key().to_multibase());
        let did = processor.create("https://localhost:8000".to_string(), &key_pair);
        print!("{}", did);
        assert!(did.len() > 0);
    }

    #[rstest]
    fn test_read_did_tdw() {
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::from("uQm7HM3hPG8ar7HqoXAC7RW_fy9Ah5TnLHwyIid-lh4I");
        print!("|> {} <|",key_pair.get_signing_key().to_multibase());
        let did = processor.create("https://localhost:8000".to_string(), &key_pair);
        
        // Read original did document
        let did_doc_str_v1 = processor.read(String::from(&did));
        let did_doc_v1: serde_json::Value = serde_json::from_str(&did_doc_str_v1).unwrap();
        match did_doc_v1["id"] {
            serde_json::Value::String(ref s) => {
                println!("{}", s);
                assert!(s.eq("did:tdw:localhost%3A8000:gu4geodcmvsgmzbqge3wimrugeygeolcgzsgenlggbtdczdcge3dcnzwgi3tonzsg5sweyjwmrswintbguytimbsmm3tcmzsmiywimy="))
            },
            _ => panic!("Invalid did doc"),
        }
    }

    #[rstest]
    fn test_update_did_tdw() {
        // Register did tdw
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::generate();
        let did = processor.create("https://localhost:8000".to_string(), &key_pair);
        
        // Read original did doc 
        let did_doc_str_v1 = processor.read(String::from(&did));
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
        processor.update(did.clone(), did_doc_v2, &key_pair);

        // Read updated did doc with new property
        let did_doc_str_v3 = processor.read(String::from(&did));
        let did_doc_v3: serde_json::Value = serde_json::from_str(&did_doc_str_v3).unwrap();
        match did_doc_v3["assertionMethod"][0]["id"] {
            serde_json::Value::String(ref s) => assert!(s.eq("did:jwk:123#type1")),
            _ => panic!("Invalid did doc"),
        };
    }

    #[rstest]
    #[should_panic(expected = "Invalid key pair. The provided key pair is not the one referenced in the did doc")]
    fn test_update_did_tdw_with_non_controller_did() {
        // Register did tdw
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::generate();
        let did = processor.create("https://localhost:8000".to_string(), &key_pair);
        
        // Read original did doc 
        let did_doc_str_v1 = processor.read(String::from(&did));
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
        processor.update(did.clone(), did_doc_v2, &unauthorized_key_pair);
    }

    #[rstest]
    #[should_panic(expected = "Invalid did doc. The did doc is already deactivated. For simplicity reasons we don't allow updates of dids")]
    fn test_deactivate_did_tdw() {
        // Register did tdw
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::generate();
        let did = processor.create("https://localhost:8000".to_string(), &key_pair);

        // Deactivate did
        processor.deactivate(did.clone(), &key_pair);

        // Read original did doc 
        let did_doc_str_v1 = processor.read(String::from(&did));
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
        processor.update(did.clone(), did_doc_v2, &key_pair);
    }
}