enum HttpAssemblyState {
    AwaitingHeaders,
    AwaitingBody { content_length: usize },
}

pub struct HttpAssembler {
    state: HttpAssemblyState,
    header_buf: Vec<u8>, // acumula bytes ate achar \r\n\r\n
    body_buf: Vec<u8>,   // acumula bytes do body ate == content_length
}

impl HttpAssembler {
    pub fn new() -> Self {
        Self {
            state: HttpAssemblyState::AwaitingHeaders,
            header_buf: Vec::new(),
            body_buf: Vec::new(),
        }
    }

    pub fn feed(&mut self, data: &[u8], label: &str, decrypt: impl Fn(&[u8])
        -> Result<String, Box<dyn std::error::Error>>,
    ) {
        let mut pending = data;
        let mut owned_overflow: Vec<u8>;

        loop {
            match &self.state {
                HttpAssemblyState::AwaitingHeaders => {
                    self.header_buf.extend_from_slice(pending);

                    let separator = b"\r\n\r\n";
                    let Some(index) = self
                        .header_buf
                        .windows(separator.len())
                        .position(|window| window == separator)
                    else {
                        return;
                    };

                    let content_length = parse_content_length(&self.header_buf[..index]).unwrap_or(0);

                    let leftover_start = index + separator.len();
                    owned_overflow = self.header_buf[leftover_start..].to_vec();
                    self.header_buf.clear();
                    self.state = HttpAssemblyState::AwaitingBody { content_length };
                    pending = &owned_overflow;
                }
                HttpAssemblyState::AwaitingBody { content_length } => {
                    let content_length = *content_length;
                    self.body_buf.extend_from_slice(pending);

                    if self.body_buf.len() < content_length {
                        return;
                    }

                    match decrypt(&self.body_buf[..content_length]) {
                        Ok(decoded) => println!("{}\n\r{}", label, decoded),
                        Err(e) => eprintln!("{} decode failed: {}", label, e),
                    }

                    owned_overflow = self.body_buf[content_length..].to_vec();
                    self.body_buf.clear();
                    self.state = HttpAssemblyState::AwaitingHeaders;

                    if owned_overflow.is_empty() {
                        return;
                    }
                    pending = &owned_overflow;
                }
            }
        }
    }
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let headers = String::from_utf8_lossy(headers);
    headers.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("content-length") {
            return None;
        }
        value.trim().parse::<usize>().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE_BASE64: &str =
        "fV9W7uRzfb8Ly3OOcIrGX7oMh34scfnjHj8sNyQexsC1j0gNSp4ViZ4rIgwLsb1AyVsoUCyn5TPj3RI5MGG8IA==";

    fn wrap_http(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes()
    }

    fn fake_decrypt(body: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        Ok(String::from_utf8(body.to_vec())?)
    }

    #[test]
    fn fragmented_body_only_decodes_once_complete() {
        use std::cell::Cell;

        let message = wrap_http(RESPONSE_BASE64);
        let mut assembler = HttpAssembler::new();
        let decode_calls = Cell::new(0);
        let counting_decrypt = |body: &[u8]| {
            decode_calls.set(decode_calls.get() + 1);
            fake_decrypt(body)
        };

        let (first, second) = message.split_at(message.len() - 10);
        assembler.feed(first, "Response", counting_decrypt);
        assert_eq!(
            decode_calls.get(),
            0,
            "must not decode before body is complete"
        );

        assembler.feed(second, "Response", counting_decrypt);
        assert_eq!(
            decode_calls.get(),
            1,
            "must decode exactly once when body completes"
        );
    }

    #[test]
    fn state_resets_between_keep_alive_messages() {
        let first_message = wrap_http(RESPONSE_BASE64);
        let second_message = wrap_http(RESPONSE_BASE64);

        let mut assembler = HttpAssembler::new();
        assembler.feed(&first_message, "Response", fake_decrypt);
        assembler.feed(&second_message, "Response", fake_decrypt);

        assert!(matches!(
            assembler.state,
            HttpAssemblyState::AwaitingHeaders
        ));
        assert!(assembler.body_buf.is_empty());
    }

    #[test]
    fn coalesced_messages_in_single_feed_are_both_processed() {
        let first_message = wrap_http(RESPONSE_BASE64);
        let second_message = wrap_http(RESPONSE_BASE64);

        let mut combined = first_message.clone();
        combined.extend_from_slice(&second_message);

        let mut assembler = HttpAssembler::new();
        assembler.feed(&combined, "Response", fake_decrypt);

        assert!(matches!(
            assembler.state,
            HttpAssemblyState::AwaitingHeaders
        ));
        assert!(assembler.body_buf.is_empty());
    }

    #[test]
    fn parses_content_length_case_insensitively() {
        let headers = b"HTTP/1.1 200 OK\r\ncontent-length: 42\r\nOther: x";
        assert_eq!(parse_content_length(headers), Some(42));
    }

    #[test]
    fn missing_content_length_returns_none() {
        let headers = b"HTTP/1.1 200 OK\r\nOther: x";
        assert_eq!(parse_content_length(headers), None);
    }
}
