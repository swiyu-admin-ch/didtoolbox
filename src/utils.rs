use base64::{engine::general_purpose::STANDARD, Engine as _};

pub const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
pub const MKEY_CONTEXT: &str = "https://w3id.org/security/multikey/v1";
pub const SCID_PLACEHOLDER: &str = "{SCID}";
pub const SCID_MIN_LENGTH: usize = 32;
pub const DATE_TIME_FORMAT : &str = "%Y-%m-%dT%H:%M:%S%.3f%z";

pub fn convert_to_multibase_base64(data: &[u8]) -> String {
    let b64 = STANDARD.encode(data);
    return format!("M{}", b64);
}

pub fn convert_from_multibase_base64(multibase: &str, result: &mut [u8]) -> () {
    let mut raw = multibase.trim_start_matches("M").to_owned();
    STANDARD.decode_slice(raw, result).unwrap();
}