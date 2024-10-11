// SPDX-License-Identifier: MIT
use sha2::{Sha256, Digest};
use hex;
use regex::Regex;
use ssi::dids::DIDBuf as SSIDIDBuf;
use ureq;
use url_escape;
use std::sync::LazyLock;

static HAS_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([a-z]|[0-9])\/([a-z]|[0-9])").unwrap());
static HAS_PORT_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\:[0-9]+").unwrap());

/// ssi_dids_core-based parsing helper.
pub fn parse_did_tdw_scid_and_url(did_tdw: String, allow_http: Option<bool>) -> Option<(String, String)> {
    match SSIDIDBuf::from_string(did_tdw) {
        Ok(buf) => {
            let method_specific_id = buf.method_specific_id().to_string();
            let split = method_specific_id.split_once(":").unwrap();

            let scid = split.0.to_string();
            let did_tdw_reduced = split.1.to_string();

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
                Err(_) => panic!("Couldn't convert did_tdw url to utf8 string"),
            };
            if HAS_PATH_REGEX.captures(url.as_str()).is_some() || HAS_PORT_REGEX.captures(url.as_str()).is_some() {
                Some((scid, format!("{}/did.jsonl", url)))
            } else {
                Some((scid, format!("{}/.well-known/did.jsonl", url)))
            }
        }
        Err(e) => None,
    }
}
