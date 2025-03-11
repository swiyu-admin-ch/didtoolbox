// SPDX-License-Identifier: MIT

use crate::errors::TrustDidWebError;
use serde::{Deserialize, Serialize};

/// Entry in an did log file as shown here
/// https://bcgov.github.io/trustdidweb/#term:did-log-entry

// Implement basic properties related to EC algorithm
// https://www.rfc-editor.org/rfc/rfc7517#section-4
// https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Jwk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

// See https://www.w3.org/TR/did-core/#verification-methods
#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationMethod {
    pub id: String,
    pub controller: String,
    #[serde(rename = "type")]
    pub verification_type: VerificationType,
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<Jwk>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum VerificationType {
    Multikey,
    // https://w3c-ccg.github.io/lds-jws2020/#json-web-key-2020
    JsonWebKey2020,
    // https://www.w3.org/TR/vc-di-eddsa/#ed25519verificationkey2020
    Ed25519VerificationKey2020,
}

impl std::fmt::Display for VerificationType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let string_representation = match self {
            VerificationType::Multikey => String::from("Multikey"),
            VerificationType::JsonWebKey2020 => String::from("JsonWebKey2020"),
            VerificationType::Ed25519VerificationKey2020 => {
                String::from("Ed25519VerificationKey2020")
            }
        };
        write!(f, "{}", string_representation)
    }
}

impl VerificationMethod {
    pub fn new(
        id: String,
        controller: String,
        public_key_multibase: String,
        verification_type: VerificationType,
    ) -> Self {
        VerificationMethod {
            id,
            controller,
            verification_type,
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
            public_key_jwk: self.public_key_jwk.clone(),
        }
    }
}

// See      https://www.w3.org/TR/did-core/#dfn-did-documents
// Examples https://www.w3.org/TR/did-core/#did-documents
// According to https://www.w3.org/TR/did-core/#did-document-properties
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
    #[serde(
        rename = "keyAgreement",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub key_agreement: Vec<VerificationMethod>,
    //#[serde(skip_serializing_if = "Vec::is_empty", default)]
    #[serde(skip)]
    pub controller: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
}

// See      https://www.w3.org/TR/did-core/#dfn-did-documents
// Examples https://www.w3.org/TR/did-core/#did-documents
// According to https://www.w3.org/TR/did-core/#did-document-properties
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DidDocNormalized {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(
        rename = "verificationMethod",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<String>,
    #[serde(
        rename = "capabilityInvocation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_invocation: Vec<String>,
    #[serde(
        rename = "capabilityDelegation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_delegation: Vec<String>,
    #[serde(
        rename = "assertionMethod",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub assertion_method: Vec<String>,
    #[serde(
        rename = "keyAgreement",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub key_agreement: Vec<String>,
    //#[serde(skip_serializing_if = "Vec::is_empty", default)]
    //pub controller: Vec<String>,
    //#[serde(skip_serializing_if = "String::is_empty", default)]
    #[serde(skip)]
    pub controller: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
}

impl DidDocNormalized {
    pub fn to_did_doc(&self) -> Result<DidDoc, TrustDidWebError> {
        let controller = match self.controller.clone() {
            None => vec![],
            Some(c) => vec![c],
        };

        let mut did_doc = DidDoc {
            context: self.context.clone(), // vec![],
            id: self.id.clone(),
            verification_method: self.verification_method.clone(),
            authentication: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            //controller: self.controller.clone(),
            controller,
            deactivated: self.deactivated,
        };
        if !self.authentication.is_empty() {
            did_doc.authentication = vec![];
            self.authentication.iter().try_for_each(|id| -> Result<(), TrustDidWebError> {
                match self.verification_method.iter().find(|m| m.id == *id) {
                    Some(obj) => {
                        did_doc.authentication.push(obj.clone());
                        Ok(())
                    }
                    None => Err(TrustDidWebError::InvalidDidDocument(format!("Authentication (reference) key refers to non-existing verification method: {}", id)))
                }
            })?;
        }
        if !self.capability_invocation.is_empty() {
            did_doc.capability_invocation = vec![];
            self.capability_invocation.iter().try_for_each(|id| -> Result<(), TrustDidWebError> {
                match self.verification_method.iter().find(|m| m.id == *id) {
                    Some(obj) => {
                        did_doc.capability_invocation.push(obj.clone());
                        Ok(())
                    }
                    None => Err(TrustDidWebError::InvalidDidDocument(format!("Capability invocation (reference) key refers to non-existing verification method: {}", id)))
                }
            })?;
        }
        if !self.capability_delegation.is_empty() {
            did_doc.capability_delegation = vec![];
            self.capability_delegation.iter().try_for_each(|id| -> Result<(), TrustDidWebError> {
                match self.verification_method.iter().find(|m| m.id == *id) {
                    Some(obj) => {
                        did_doc.capability_delegation.push(obj.clone());
                        Ok(())
                    }
                    None => Err(TrustDidWebError::InvalidDidDocument(format!("Capability delegation (reference) key refers to non-existing verification method: {}", id)))
                }
            })?;
        }
        if !self.assertion_method.is_empty() {
            did_doc.assertion_method = vec![];
            self.assertion_method.iter().try_for_each(|id| -> Result<(), TrustDidWebError> {
                match self.verification_method.iter().find(|m| m.id == *id)
                {
                    Some(obj) => {
                        did_doc.assertion_method.push(obj.clone());
                        Ok(())
                    }
                    None => Err(TrustDidWebError::InvalidDidDocument(format!("Assertion method (reference) key refers to non-existing verification method: {}", id)))
                }
            })?;
        }
        if !self.key_agreement.is_empty() {
            did_doc.key_agreement = vec![];
            self.key_agreement.iter().try_for_each(|id| -> Result<(), TrustDidWebError> {
                match self.verification_method.iter().find(|m| m.id == *id) {
                    Some(obj) => {
                        did_doc.key_agreement.push(obj.clone());
                        Ok(())
                    }
                    None => Err(TrustDidWebError::InvalidDidDocument(format!("Key agreement (reference) key refers to non-existing verification method: {}", id)))
                }
            })?;
        }
        Ok(did_doc)
    }
}

impl DidDoc {
    pub fn get_context(&self) -> Vec<String> {
        self.context.clone()
    }

    pub fn get_id(&self) -> String {
        self.id.clone()
    }

    pub fn get_verification_method(&self) -> Vec<VerificationMethod> {
        self.verification_method.clone()
    }

    pub fn get_authentication(&self) -> Vec<VerificationMethod> {
        self.authentication.clone()
    }

    pub fn get_capability_invocation(&self) -> Vec<VerificationMethod> {
        self.capability_invocation.clone()
    }

    pub fn get_capability_delegation(&self) -> Vec<VerificationMethod> {
        self.capability_delegation.clone()
    }

    pub fn get_assertion_method(&self) -> Vec<VerificationMethod> {
        self.assertion_method.clone()
    }

    pub fn get_controller(&self) -> Vec<String> {
        self.controller.clone()
    }

    pub fn get_deactivated(&self) -> bool {
        self.deactivated.unwrap_or(false)
    }

    pub fn from_json(json_content: &str) -> Result<Self, TrustDidWebError> {
        let did_doc: DidDoc = match serde_json::from_str(json_content) {
            Ok(did_doc) => did_doc,
            Err(e) => {
                return Err(TrustDidWebError::DeserializationFailed(format!(
                    "Error parsing DID Document. Make sure the content is correct -> {}",
                    e
                )));
            }
        };
        Ok(did_doc)
    }

    pub fn normalize(&self) -> DidDocNormalized {
        let controller: Option<String> = match self.controller.first() {
            Some(controller) => Some(controller.clone()),
            None => None,
        };

        let mut did_doc_norm = DidDocNormalized {
            context: self.context.clone(), // vec![],
            id: self.id.clone(),
            verification_method: self.verification_method.clone(),
            authentication: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            //controller: self.controller.clone(),
            controller,
            deactivated: self.deactivated,
        };
        if !self.authentication.is_empty() {
            did_doc_norm.authentication = self
                .authentication
                .iter()
                .map(|vm: &VerificationMethod| vm.id.clone())
                .collect::<Vec<String>>();
        }
        if !self.capability_invocation.is_empty() {
            did_doc_norm.capability_invocation = self
                .capability_invocation
                .iter()
                .map(|vm: &VerificationMethod| vm.id.clone())
                .collect::<Vec<String>>();
        }
        if !self.capability_delegation.is_empty() {
            did_doc_norm.capability_delegation = self
                .capability_delegation
                .iter()
                .map(|vm: &VerificationMethod| vm.id.clone())
                .collect::<Vec<String>>();
        }
        if !self.assertion_method.is_empty() {
            did_doc_norm.assertion_method = self
                .assertion_method
                .iter()
                .map(|vm: &VerificationMethod| vm.id.clone())
                .collect::<Vec<String>>();
        }
        if !self.key_agreement.is_empty() {
            did_doc_norm.key_agreement = self
                .key_agreement
                .iter()
                .map(|vm: &VerificationMethod| vm.id.clone())
                .collect::<Vec<String>>();
        }
        did_doc_norm
    }
}
