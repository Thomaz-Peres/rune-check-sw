use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    fs::{self},
    sync::Arc,
};
// use rustls::{ClientConfig, ConfigBuilder, ServerConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
};

// use std::io::{Read, Write};

use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};

#[tokio::main]
async fn main() {
    if !fs::exists("ca.key").unwrap_or(false) || !fs::exists("ca.crt").unwrap_or(false) {
        if let Err(e) = generate_root_ca() {
            eprintln!("Failed to generate CA: {}", e);
        }
    }

    match generate_root_leaf("summonerswar-fn.qpyou.cn") {
        Ok((cert_pem, _key_pem)) => {
            listener(cert_pem, _key_pem).await.unwrap();
        }
        Err(e) => eprintln!("Failed to mint leaf: {}", e),
    }
    println!("Hello world");
}

fn generate_root_ca() -> Result<(), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();

    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Summoners War Rust Proxy CA");

    let key_pair = KeyPair::generate()?;

    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let private_key_pem = key_pair.serialize_pem();

    fs::write("ca.crt", cert_pem)?;
    fs::write("ca.key", private_key_pem)?;

    println!("Success! Certificate and key are saved to the project root.");

    Ok(())
}

fn generate_root_leaf(hostname: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let ca_key_pem = fs::read_to_string("ca.key")?;
    let ca_key_pair = KeyPair::from_pem(&ca_key_pem)?;
    let ca_cert_pem = fs::read_to_string("ca.crt")?;

    let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key_pair)?;

    let leaf_key = KeyPair::generate()?;

    let mut params: CertificateParams = CertificateParams::new(vec![hostname.to_string()])?;
    params.is_ca = IsCa::ExplicitNoCa;

    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);

    let leaf_cert = params.signed_by(&leaf_key, &issuer)?;

    Ok((leaf_cert.pem(), leaf_key.serialize_pem()))
}

async fn listener(cert_pem: String, key_pem: String) -> Result<(), Box<dyn std::error::Error>> {
    let x = vec![CertificateDer::from_pem_slice(cert_pem.as_bytes())?];
    let private_key =
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("Private key not found in file");

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(x, private_key)
        .expect("bad certificate/key");

    let acceptor: tokio_rustls::TlsAcceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:443")
        .await
        .expect("Could not bind to address");

    println!("Listening on port 443");

    loop {
        // Accept a new connection
        let (socket, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        println!("New client connected: {}", addr);

        // Spawn a task to handle the connection concurrently
        tokio::spawn(async move {
            let mut tls_stream = match acceptor.accept(socket).await {
                Ok(s) => {
                    println!("TLS handshake OK with {}", addr);
                    s
                }
                Err(e) => {
                    eprintln!("TSL handshake failed: {:?}", e);
                    return;
                }
            };

            let mut buf = [0u8; 4096];
            match tls_stream.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    println!(
                        "Got {} decrypted bytes: \n---\n{}\n---",
                        n,
                        String::from_utf8_lossy(&buf[..n]));

                    let _ = tls_stream.write_all(b"HTTP/1.1 200 OK\r\nConten-Lenght: 12\r\n\r\nHello, world",).await;
                } // Connection closed
                _ => {}
            };

            // // Echo the data back to the client
            // if let Err(e) = socket.write_all(&buf[0..n]).await {
            //     eprintln!("Failed to write to socket; err = {:?}", e);
            //     return;
            // }
        });
    }
}
