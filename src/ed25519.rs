// SPDX-License-Identifier: MIT
use std::sync::Arc;

use crate::utils;
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;

pub trait MultiBaseConverter {
    fn to_multibase(&self) -> String;
    fn from_multibase(multibase: &str) -> Self;
}

#[derive(Clone)]
pub struct Ed25519Signature {
    pub signature: Signature,
}
impl MultiBaseConverter for Ed25519Signature {
    fn to_multibase(&self) -> String {
        let signature_bytes = self.signature.to_bytes();
        utils::convert_to_multibase_base58btc(&signature_bytes)
    }

    fn from_multibase(multibase: &str) -> Self {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0; SIGNATURE_LENGTH];
        utils::convert_from_multibase_base58btc(multibase, &mut signature_bytes); // may panic
        Ed25519Signature {
            signature: Signature::from_bytes(&signature_bytes),
        }
    }
}

#[derive(Clone)]
pub struct Ed25519SigningKey {
    signing_key: SigningKey,
}

impl MultiBaseConverter for Ed25519SigningKey {
    fn to_multibase(&self) -> String {
        let public_key_bytes = self.signing_key.to_bytes();
        utils::convert_to_multibase_base58btc(&public_key_bytes)
    }

    fn from_multibase(multibase: &str) -> Self {
        let mut public_key_bytes: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];
        utils::convert_from_multibase_base58btc(multibase, &mut public_key_bytes); // may panic
        Ed25519SigningKey {
            signing_key: SigningKey::from_bytes(&public_key_bytes),
        }
    }
}
impl Ed25519SigningKey {
    pub fn new(signing_key: SigningKey) -> Self {
        Ed25519SigningKey { signing_key }
    }

    pub fn sign(&self, message: String) -> Arc<Ed25519Signature> {
        let signature = self.signing_key.sign(message.as_bytes());
        Ed25519Signature { signature }.into()
    }
}

#[derive(Clone)]
pub struct Ed25519VerifyingKey {
    pub verifying_key: VerifyingKey,
}
impl MultiBaseConverter for Ed25519VerifyingKey {
    fn to_multibase(&self) -> String {
        let public_key_without_prefix = self.verifying_key.to_bytes();
        let mut public_key_with_prefix: [u8; PUBLIC_KEY_LENGTH + 2] = [0; PUBLIC_KEY_LENGTH + 2];
        public_key_with_prefix[0] = 0xed;
        public_key_with_prefix[1] = 0x01;
        public_key_with_prefix[2..].copy_from_slice(&public_key_without_prefix);
        utils::convert_to_multibase_base58btc(&public_key_with_prefix)
    }

    fn from_multibase(multibase: &str) -> Self {
        // According to https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020
        // the public key has a **two** byte prefix of 0xed01, which is not part of the public key instance itself
        // therefore "+2" is added to the length of the multibase public key
        let mut public_key_with_prefix: [u8; PUBLIC_KEY_LENGTH + 2] = [0; PUBLIC_KEY_LENGTH + 2];
        utils::convert_from_multibase_base58btc(multibase, &mut public_key_with_prefix);

        let mut public_key: [u8; PUBLIC_KEY_LENGTH] = [0; PUBLIC_KEY_LENGTH];
        public_key.copy_from_slice(&public_key_with_prefix[2..]);

        match VerifyingKey::from_bytes(&public_key) {
            Ok(verifying_key) => Ed25519VerifyingKey { verifying_key },
            Err(_) => panic!("{} is an invalid ed25519 public key", multibase),
        }
    }
}
impl Ed25519VerifyingKey {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Ed25519VerifyingKey { verifying_key }
    }
}

#[derive(Clone)]
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
        utils::convert_from_multibase_base58btc(signing_key_multibase, &mut signing_key_bytes); // may panic
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        Ed25519KeyPair {
            verifying_key: Ed25519VerifyingKey::new(signing_key.verifying_key()),
            signing_key: Ed25519SigningKey::new(signing_key),
        }
    }

    pub fn get_signing_key(&self) -> Arc<Ed25519SigningKey> {
        self.signing_key.clone().into()
    }

    pub fn get_verifying_key(&self) -> Arc<Ed25519VerifyingKey> {
        self.verifying_key.clone().into()
    }

    pub fn sign(&self, message: String) -> Arc<Ed25519Signature> {
        self.signing_key.sign(message)
    }
}
