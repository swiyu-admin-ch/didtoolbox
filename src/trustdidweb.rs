use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use ed25519_dalek::{SigningKey, Signature, Signer, Verifier, VerifyingKey, SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_jcs::{to_vec as jcs_from_str, to_string as jcs_to_string};
use serde_json::json;
use crate::utils;

/// Entry in an did log file as shown here
/// https://bcgov.github.io/trustdidweb/#term:did-log-entry
pub struct DidLogEntry {
    pub entry_hash: String,
    pub version_id: String,
    pub version_time: DateTime<Utc>,
    pub parameters: serde_json::Value,
    pub did_doc: serde_json::Value,
}

impl DidLogEntry {
    pub fn new(entry_hash: String, version_id: String, version_time: DateTime<Utc>, parameters: serde_json::Value, did_doc: serde_json::Value) -> Self {
        DidLogEntry {
            entry_hash,
            version_id,
            version_time,
            parameters,
            did_doc,
        }
    }

    pub fn to_log_entry_line(&self) -> serde_json::Value {
        serde_json::json!([
            self.entry_hash,
            self.version_id,
            self.version_time.to_owned().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            self.parameters,
            self.did_doc,
        ])
    }
}

/// Basic user facing did method operations to handle a did
pub trait DidMethodOperation {
    fn create(domain: String, key_pair: Ed25519KeyPair) -> String;
    fn read(did_tdw: String) -> String;
    fn update(did_tdw: String, did_doc: String) -> String;
    fn deactivate(did_tdw: String) -> String;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationMethod {
    pub id: String,
    pub controller: String,
    #[serde(rename = "type")]
    pub verification_type: String,
    pub public_key_multibase: String,
}

impl VerificationMethod {
    pub fn new(id: String, controller: String, public_key_multibase: String) -> Self {
        VerificationMethod {
            id: id,
            controller: controller,
            verification_type: String::from("Multikey"),
            public_key_multibase: public_key_multibase,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DidDoc {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<VerificationMethod>,
    #[serde(
        rename = "capabilityInvocation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_invocation: Vec<VerificationMethod>,
    #[serde(
        rename = "capabilityDelegation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_delegation: Vec<VerificationMethod>,
    #[serde(
        rename = "assertionMethod",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub assertion_method: Vec<VerificationMethod>,
}

pub trait Base64MultiBaseConverter {
    fn to_multibase(&self) -> String;
    fn from_multibase(multibase: &str) -> Self;
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
}

pub struct Ed25519VerifyingKey {
    verifying_key: VerifyingKey,
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
}

pub struct TrustDidWebProcessor {
}

impl DidMethodOperation for TrustDidWebProcessor {

    fn create(domain: String, key_pair: Ed25519KeyPair) -> String {
        let did_tdw = format!("did:tdw:{}:{}", domain, "{SCID}");
        todo!("Create did string")
    }

    fn read(did_tdw: String) -> String {
        todo!("Read did string")
    }

    fn update(did_tdw: String, did_doc: String) -> String {
        todo!("Update did string")
    }

    fn deactivate(did_tdw: String) -> String {
        todo!("Deactivate did string")
    }
}

impl TrustDidWebProcessor {
    pub fn create_verification_method_from_verifying_key(domain: &String, verifying_key: &Ed25519VerifyingKey) -> VerificationMethod {
        let keydef = json!({
            "type":"Multikey",
            "publicKeyMultibase": verifying_key.to_multibase(),
        });
        todo!("Create verification method from verifying key")
    }
}