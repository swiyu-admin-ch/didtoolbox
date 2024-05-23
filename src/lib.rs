pub mod trustdidweb;
pub mod utils;

uniffi::include_scaffolding!("trustdidweb");

#[cfg(test)]
mod test {
    use crate::trustdidweb::Base64MultiBaseConverter;

    use super::trustdidweb::{Ed25519KeyPair, Ed25519SigningKey, Ed25519VerifyingKey};
    use rstest::{rstest};
    
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
}