use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use base64::Engine;
use flate2::read::ZlibDecoder;
use std::io::Read;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

fn decrypt_to_bytes(b64: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let sw_iv: [u8; 16] = [0u8; 16];
    let sw_key: [u8; 16] = [
        71, 114, 52, 83, 50, 101, 105, 78, 108, 55, 122, 113, 53, 77, 114, 85,
    ];

    let ciphertext = base64::engine::general_purpose::STANDARD.decode(b64)?;
    let plaintext = Aes128CbcDec::new(&sw_key.into(), &sw_iv.into())
        .decrypt_padded_vec::<Pkcs7>(&ciphertext)
        .map_err(|e| format!("AES decrypt/unpad failed: {:?}", e))?;
    Ok(plaintext)
}

pub fn decrypt_request(b64: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = decrypt_to_bytes(b64.trim())?;
    Ok(String::from_utf8(bytes)?)
}

pub fn decrypt_response(b64: &str) -> Result<String, Box<dyn std::error::Error>> {
    let compressed = decrypt_to_bytes(b64)?;
    let mut decoder = ZlibDecoder::new(&compressed[..]);
    let mut json = String::new();
    decoder.read_to_string(&mut json)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_request() {
        let req_b64 = "vtgSQBCkzpT+duvn5CVFKBy943E8fjhK8k/mI0AjYkifsgqqIangMvjQK5ExCvz5NQyB9/rsvQAFjMhAHFzD14liV0jxTXzbfnIPQb0RbgXUsbeioa662Wv5aesggfbfqLqm8QAuMCTcvSZdlsHx/xwWGqS8ZCmt2oKlRz4iJEqu32cTtsZ8ekkEUcHLm89G4ncbdaC0ZSH2nP0QSYBsB4abIQn8+dpLsEiX2CmtlCTP7YqsFl1KJ4+x/du6AmZ1ZIP0i6yNaZwkxIGUlh7uOZi4fIrpGjhzU8Xg0SuOqmRvyuPHF30/8ULY4RjVaRzrW7fgcVmcN0OBzRWws9rggEFo0YHaQN3uEVBhAbxVeByzesyrr5WCJfvIEOJQKR04CYc2gJWyzlyr/L2nCS5RLm9y9jTSAPqGbPwa4UMjHGyPcJkkOCnNyjAKb8/acFd1PkbQ7Cx9756pt0GBUFNRsg==";

        println!("=== test_decryption_against_capture ===");

        let x = decrypt_request(req_b64)
            .inspect(|json| println!("REQUEST JSON:\n{}\n", json))
            .inspect_err(|e| eprintln!("REQUEST FAILED: {}\n", e));

        println!("=======================================");

        assert!(x.is_ok());
    }
}
