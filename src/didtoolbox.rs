use serde::{Deserialize, Serialize};
/// Entry in an did log file as shown here
/// https://bcgov.github.io/trustdidweb/#term:did-log-entry

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationMethod {
    pub id: String,
    pub controller: String,
    #[serde(rename = "type")]
    pub verification_type: String,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Jwk>,
}

impl VerificationMethod {
    pub fn new(id: String, controller: String, public_key_multibase: String) -> Self {
        VerificationMethod {
            id: id,
            controller: controller,
            verification_type: String::from("Multikey"),
            public_key_multibase: Some(public_key_multibase),
            public_key_jwk: None,
        }
    }
}
impl Clone for VerificationMethod {
    fn clone(&self) -> Self {
        VerificationMethod {
            id: self.id.clone(),
            controller: self.controller.clone(),
            verification_type: self.verification_type.clone(),
            public_key_multibase: self.public_key_multibase.clone(),
            public_key_jwk: self.public_key_jwk.clone()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub controller: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
}

impl DidDoc {
    pub fn from_json(json_content: String) -> Self {
        let did_doc: DidDoc = match serde_json::from_str(&json_content) {
            Ok(did_doc) => did_doc,
            Err(e) => {
                panic!("Error parsing DID Document. Make sure the content is correct -> {}", e);
            }
        };
        did_doc
    }
}

pub fn create_did_doc_from_json(json_content: String) -> DidDoc {
    DidDoc::from_json(json_content)
}