use base64::{engine::general_purpose::STANDARD, Engine as _};

pub fn convert_to_multibase_base64(data: &[u8]) -> String {
    let b64 = STANDARD.encode(data);
    return format!("M{}", b64);
}

pub fn convert_from_multibase_base64(multibase: &str, result: &mut [u8]) -> () {
    let mut raw = multibase.trim_start_matches("M").to_owned();
    STANDARD.decode_slice(raw, result).unwrap();
}