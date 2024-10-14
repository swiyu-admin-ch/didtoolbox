// SPDX-License-Identifier: MIT
use sha2::{Sha256, Digest};
use hex;
use regex::Regex;
use ssi::dids::{DIDMethod as SSIDIDMethod,
                DIDBuf as SSIDIDBuf,
                resolution::{
                    Error as SSIResolutionError,
                    DIDMethodResolver as SSIDIDMethodResolver,
                    Options as SSIOptions,
                    Output as SSIOutput,
                },
};
use ureq;
use url_escape;
use std::sync::LazyLock;
use crate::did_tdw::TrustDidWeb;

static HAS_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([a-z]|[0-9])\/([a-z]|[0-9])").unwrap());
static HAS_PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\:[0-9]+").unwrap());

impl SSIDIDMethod for TrustDidWeb {
    const DID_METHOD_NAME: &'static str = "tdw";
}

impl SSIDIDMethodResolver for TrustDidWeb {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: SSIOptions,
    ) -> Result<SSIOutput<Vec<u8>>, SSIResolutionError> {
        // TODO Implement DIDMethodResolver for TrustDidWeb
        todo!()
    }
}

/// ssi_dids_core-based parsing helper.
/// TODO Perhaps move it to TrustDidWeb::new_from_did constructor, as it is exclusively used only there
pub fn parse_did_tdw(did_tdw: String, allow_http: Option<bool>) -> Result<Option<(String, String)>, SSIResolutionError> {
    match SSIDIDBuf::from_string(did_tdw.to_owned()) {
        Ok(buf) => {
            if !buf.method_name().starts_with(TrustDidWeb::DID_METHOD_NAME) {
                return Err(SSIResolutionError::MethodNotSupported(buf.method_name().to_owned()));
            };

            match buf.method_specific_id().split_once(":") {
                Some((scid, did_tdw_reduced)) => {
                    let mut decoded_url = String::from("");
                    url_escape::decode_to_string(did_tdw_reduced.replace(":", "/"), &mut decoded_url);

                    let url = match String::from_utf8(decoded_url.into_bytes()) {
                        Ok(url) => {
                            if url.starts_with("localhost") || url.starts_with("127.0.0.1") || allow_http.unwrap_or(false) {
                                format!("http://{}", url)
                            } else {
                                format!("https://{}", url)
                            }
                        }
                        Err(_) => return Err(SSIResolutionError::InvalidMethodSpecificId(did_tdw_reduced.to_owned())),
                    };
                    if HAS_PATH_REGEX.captures(url.as_str()).is_some() || HAS_PORT_REGEX.captures(url.as_str()).is_some() {
                        Ok(Some((scid.to_string(), format!("{}/did.jsonl", url))))
                    } else {
                        Ok(Some((scid.to_string(), format!("{}/.well-known/did.jsonl", url))))
                    }
                }
                None => Err(SSIResolutionError::InvalidMethodSpecificId(buf.method_specific_id().to_owned())),
            }
        }
        Err(_) => Err(SSIResolutionError::InvalidMethodSpecificId(did_tdw)),
    }
}
