use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::{read::ZlibDecoder};
use std::io::{Read};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const SW_KEY: [u8; 16] = [
        71, 114, 52, 83, 50, 101, 105, 78, 108, 55, 122, 113, 53, 77, 114, 85,
    ];
const SW_IV: [u8; 16] = [0u8; 16];

fn decrypt_to_bytes(b64: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let ciphertext = STANDARD.decode(b64.trim_ascii())?;
    let plaintext = Aes128CbcDec::new(&SW_KEY.into(), &SW_IV.into())
        .decrypt_padded_vec::<Pkcs7>(&ciphertext)
        .map_err(|e| format!("AES decrypt/unpad failed: {:?}", e))?;
    Ok(plaintext)
}
pub fn decrypt_request(b64: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = decrypt_to_bytes(b64)?;
    Ok(String::from_utf8(bytes)?)
}

pub fn decrypt_response(b64: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let compressed = decrypt_to_bytes(b64)?;
    let mut decoder = ZlibDecoder::new(&compressed[..]);
    let mut json = String::new();
    decoder.read_to_string(&mut json)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_REQUEST: &str = r#"{"command":"Ping","wizard_id":1,"hello":"world"}"#;
    const SAMPLE_RESPONSE: &str = r#"{"command":"Ping","ret_code":0,"payload":[1,2,3]}"#;

    const REQUEST_BASE64: &str = "p+is24btlT/udsBYTcNdYRbUkiGHQE2lZ6QOhvQdsjqQK1ZFLG1St1quOLAmWnS793B+nz0GHCJikIsH2eqsUA==";
    const RESPONSE_BASE64: &str = "fV9W7uRzfb8Ly3OOcIrGX7oMh34scfnjHj8sNyQexsC1j0gNSp4ViZ4rIgwLsb1AyVsoUCyn5TPj3RI5MGG8IA==";


    #[test]
    fn request() {
        let x = decrypt_request(REQUEST_BASE64.as_bytes())
            .inspect(|json| println!("REQUEST JSON:\n{}\n", json))
            .inspect_err(|e| eprintln!("REQUEST FAILED: {}\n", e));

        println!("=======================================");

        assert!(x.is_ok());
        assert_eq!(x.unwrap(), SAMPLE_REQUEST);
    }

    #[test]
    fn response() {
        let x = decrypt_response(RESPONSE_BASE64.as_bytes())
            .inspect(|json| println!("REQUEST JSON:\n{}\n", json))
            .inspect_err(|e| eprintln!("REQUEST FAILED: {}\n", e));

        println!("=======================================");

        assert!(x.is_ok());
        assert_eq!(x.unwrap(), SAMPLE_RESPONSE);
    }
}
