use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

pub const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
pub const MKEY_CONTEXT: &str = "https://w3id.org/security/multikey/v1";
pub const SCID_PLACEHOLDER: &str = "{SCID}";
pub const SCID_MIN_LENGTH: usize = 32;
pub const DATE_TIME_FORMAT : &str = "%Y-%m-%dT%H:%M:%S%.3f%z";
pub const EDDSA_VERIFICATION_KEY_TYPE: &str = "Ed25519VerificationKey2020";

pub fn convert_to_multibase_base64(data: &[u8]) -> String {
    let b64 = URL_SAFE_NO_PAD.encode(data);
    return format!("u{}", b64);
}

pub fn convert_from_multibase_base64(multibase: &str, result: &mut [u8]) -> () {
    if !multibase.starts_with("u") {
        panic!("Invalid multibase format");
    }
    let raw = multibase.chars().skip(1).collect::<String>();
    URL_SAFE_NO_PAD.decode_slice(raw, result).unwrap();
}