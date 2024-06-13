use std::sync::Arc;

use ed25519_dalek::{SigningKey, Signature, Signer, Verifier, VerifyingKey, SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use rand::rngs::OsRng;
use crate::utils;
pub trait Base64MultiBaseConverter {
    fn to_multibase(&self) -> String;
    fn from_multibase(multibase: &str) -> Self;
}
#[derive(Clone)]
pub struct Ed25519Signature {
    pub signature: Signature,
}
impl Base64MultiBaseConverter for Ed25519Signature {
    fn to_multibase(&self) -> String {
        let signature_bytes = self.signature.to_bytes();
        utils::convert_to_multibase_base64(&signature_bytes)
    }

    fn from_multibase(multibase: &str) -> Self {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0; SIGNATURE_LENGTH];
        utils::convert_from_multibase_base64(multibase, &mut signature_bytes);
        Ed25519Signature {
            signature: Signature::from_bytes(&signature_bytes),
        }
    }
}

pub struct Ed25519SigningKey {
    signing_key: SigningKey,
}

impl Base64MultiBaseConverter for Ed25519SigningKey {
    fn to_multibase(&self) -> String {
        let public_key_bytes = self.signing_key.to_bytes();
        utils::convert_to_multibase_base64(&public_key_bytes)
    }

    fn from_multibase(multibase: &str) -> Self {
        let mut public_key_bytes: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
        utils::convert_from_multibase_base64(multibase, &mut public_key_bytes);
        Ed25519SigningKey {
            signing_key: SigningKey::from_bytes(&mut public_key_bytes),
        }
    }
}
impl Ed25519SigningKey {
    pub fn new (signing_key: SigningKey) -> Self {
        Ed25519SigningKey {
            signing_key,
        }
    }

    pub fn sign(&self, message: String) -> Arc<Ed25519Signature> {
        let signature = self.signing_key.sign(message.as_bytes());
        Ed25519Signature {
            signature,
        }.into()
    }
}

pub struct Ed25519VerifyingKey {
    pub verifying_key: VerifyingKey,
}
impl Base64MultiBaseConverter for Ed25519VerifyingKey {
    fn to_multibase(&self) -> String {
        let public_key_bytes = self.verifying_key.to_bytes();
        utils::convert_to_multibase_base64(&public_key_bytes)
    }

    fn from_multibase(multibase: &str) -> Self {
        let mut public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
        utils::convert_from_multibase_base64(multibase, &mut public_key_bytes);
        match VerifyingKey::from_bytes(&mut public_key_bytes) {
            Ok(verifying_key) => Ed25519VerifyingKey {
                verifying_key: verifying_key,
            },
            Err(_) => panic!("Invalid ed25519 public key"),
        }
    }
}
impl Ed25519VerifyingKey {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Ed25519VerifyingKey {
            verifying_key,
        }
    }
}

pub struct Ed25519KeyPair {
    pub verifying_key: Ed25519VerifyingKey,
    pub signing_key: Ed25519SigningKey,
}

impl Ed25519KeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        Ed25519KeyPair {
            verifying_key: Ed25519VerifyingKey::new(signing_key.verifying_key()),
            signing_key: Ed25519SigningKey::new(signing_key),
        }
    }

    pub fn from(signing_key_multibase: &str) -> Self {
        let mut signing_key_bytes: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
        utils::convert_from_multibase_base64(signing_key_multibase, &mut signing_key_bytes);
        let signing_key = SigningKey::from_bytes(&mut signing_key_bytes);
        Ed25519KeyPair {
            verifying_key: Ed25519VerifyingKey::new(signing_key.verifying_key()),
            signing_key: Ed25519SigningKey::new(signing_key)
        }
    }

    pub fn get_signing_key(&self) -> &Ed25519SigningKey {
        &self.signing_key
    }

    pub fn get_verifying_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }

    pub fn sign(&self, message: String) -> Arc<Ed25519Signature> {
        self.signing_key.sign(message)
    }

}