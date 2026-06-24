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

    #[test]
    fn test_decrypt_response() {
        let req_b64 = "33tZirRCpp4WoYEe0wWTtAdm89YtvRXoVpUz3Ti/FsukjnQlY6Z5n4bB610RD239izC0/lLpTdKLCVWHEnnKLL0nz0PRJglwwiQtTApIWHbPEjRkmNalywSdMNCtYd2X4L4ZBYw1vWfIkzOnRcGTSf0tKvD6YzMuneEoS6rrJEtjJtfnxRBzrgHb1V+4S0c/Eas4fsTnzbpt9FdlN9vRij/mjeMdxy8LoIgJvYBuE+LgRLskpdm1adV3BwDYUj06vaPY6siJX4989CVefwoDfX0FVgsZVJT/ARwZY1CpW82zjnfHeBsLyHg1NLx05sUpCwXNCXLGy338gfXBjvtc71CBgSJsV05eg2ncRa5UdJ0PlmSmRXN0WnAaIUklRMavk3ZyYID0pIWYNxVPYNdK43VAtrZetTdzKBLv/ArPw9QCDkVYGqMPfvQg/dMUvOlaq6qYmU3OLYjdIbLq9Hkpc5LjOCjrqAROFQif2+xMhn4TpOPS75Q6Khl2L0AnK7vCIpw+60KeYXKx0eQLyfZdJfxHiAOLUFWIUiS4U+vlGIMNhvx3e0xV9J6fDlQX5BNBzPWIevVCol8ZQ4+feL50e51D+siA+yAVa6Gukx64Pr0IBaGRi48EvT4Y9M7kzMLLNL0oKGi5pr4Lt8Aw0ngsjX9Gr+CL/5LxAU9R7RXAfO0dHK9TV/Q97YcUe7Vu1DvAcFvhXSVgNsGUk8itCy6lS+BkQu5WWr6btZ8tzpHql4zuKBz4fEgwKfO6VvMiMnO+YduVWa0AmUqD6rT6LpdOatUGY3H1ep9MyW41Pex0l2Z0SLL+SBngcywyjmK8gSPBJ2dAccX6ErfKpq14q6aiMZX6+g74NQV18+jSCfht6c7QlKVfUkW7qvGpHhDW3tyPiOGYoXbFCGsIP/O2rV6IJhuL9l2lI8MIgWFH0N8l35iy/omjQSKZSemV6U5InzZ2xk5VO6QFOEGWKLhdCSHk2Yp8ZHR+EcI1BqjQXHWkVe8=";

        println!("=== test_decryption_against_capture ===");

        let x = decrypt_response(req_b64)
            .inspect(|json| println!("REQUEST JSON:\n{}\n", json))
            .inspect_err(|e| eprintln!("REQUEST FAILED: {}\n", e));

        println!("=======================================");

        assert!(x.is_ok());
    }
}
