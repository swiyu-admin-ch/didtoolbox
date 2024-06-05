pub mod trustdidweb;
pub mod utils;
pub mod vc_data_integrity;
pub mod ed25519;

uniffi::include_scaffolding!("trustdidweb");

#[cfg(test)]
mod test {
    use core::panic;
    use std::vec;

    use super::trustdidweb::*;
    use super::ed25519::*;
    use rstest::rstest;
    use serde_json::json;
    use chrono::{DateTime, Utc};
    use chrono::serde::ts_seconds;

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
        let key_pair = Ed25519KeyPair::from("Mw9qGFWOhK0pbPTAbdc815ZLwZfubmgceTWBOY8V1vr0=");
        let did = processor.create("https://localhost:8000".to_string(), &key_pair);
        
        // Read original did document
        let did_doc_str_v1 = processor.read(String::from(&did));
        let did_doc_v1: serde_json::Value = serde_json::from_str(&did_doc_str_v1).unwrap();
        match did_doc_v1["id"] {
            serde_json::Value::String(ref s) => assert!(s.eq("did:tdw:localhost%3A8000:mq4tenryme2tsojuge2tsndcguzdamdcgvrwcyrxg4ywczbqgqytsodfg5stqzddg4ywcm3cmnqtszjwmezgcmlgmm4wmyrqhezgiyi=")),
            _ => panic!("Invalid did doc"),
        }
    }

    #[rstest]
    fn test_update_did_tdw() {
        // Register did tdw
        let processor = TrustDidWebProcessor::new_with_api_key(String::from("secret"));
        let key_pair = Ed25519KeyPair::from("Mw9qGFWOhK0pbPTAbdc815ZLwZfubmgceTWBOY8V1vr0=");
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
            public_key_multibase: String::from("SomeKey")
        };
        did_doc_v2["assertionMethod"] = json!(vec![serde_json::to_value(&verification_method).unwrap()]);
        match did_doc_v2["assertionMethod"] {
            serde_json::Value::Array(ref s) => assert!(s.len() == 1),
            _ => panic!("Invalid did doc"),
        }
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
}