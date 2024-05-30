pub mod trustdidweb;
pub mod utils;
pub mod vc_data_integrity;
pub mod ed25519;

uniffi::include_scaffolding!("trustdidweb");

#[cfg(test)]
mod test {
    use super::trustdidweb::*;
    use super::ed25519::*;
    use rstest::rstest;
    use serde_json::json;

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
        let processor = TrustDidWebProcessor::new();
        let key_pair = Ed25519KeyPair::generate();
        let did_lines = processor.create("example.com".to_string(), &key_pair);
        print!("{}", did_lines);
        let value = serde_json::from_str(&did_lines).unwrap();
        match value {
            serde_json::Value::Array(did_line) => {
                assert!(did_line.len() == 6)
            },
            _ => assert!(false)
        }
    }

}