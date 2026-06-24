mod decryptor;
use crate::decryptor::decrypt_response;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use std::{fs::{self}, sync::Arc };
use rcgen::{CertificateParams, IsCa, KeyPair};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() {
    if !fs::exists("ca.key").unwrap_or(false) || !fs::exists("ca.crt").unwrap_or(false) {
        if let Err(e) = generate_root_ca() {
            eprintln!("Failed to generate CA: {}", e);
        }
    }

    match generate_root_leaf("summonerswar-gb-lb.qpyou.cn") {
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

    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key_pair)?;

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

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let listener = TcpListener::bind("127.0.0.1:443")
        .await
        .expect("Could not bind to address");

    println!("Listening on port 443");

    loop {
        // Accept a new connection
        let (socket, addr) = listener.accept().await?;

        let acceptor = acceptor.clone();
        let connector = connector.clone();

        println!("New client connected: {}", addr);

        // Spawn a task to handle the connection concurrently
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, addr, acceptor, connector).await {
                eprintln!("[{}] error: {:?}", addr, e);
            }
            // let mut tls_stream = match acceptor.accept(socket).await {
            //     Ok(s) => {
            //         println!("TLS handshake OK with {}", addr);
            //         s
            //     }
            //     Err(e) => {
            //         eprintln!("TSL handshake failed: {:?}", e);
            //         return;
            //     }
            // };

            // let mut buf = [0u8; 4096];
            // match tls_stream.read(&mut buf).await {
            //     Ok(n) if n > 0 => {
            //         println!(
            //             "Got {} decrypted bytes: \n---\n{}\n---",
            //             n,
            //             String::from_utf8_lossy(&buf[..n]));

            //         let _ = tls_stream.write_all(b"HTTP/1.1 200 OK\r\nConten-Lenght: 12\r\n\r\nHello, world",).await;
            //     } // Connection closed
            //     _ => {}
            // };

            // // // Echo the data back to the client
            // // if let Err(e) = socket.write_all(&buf[0..n]).await {
            // //     eprintln!("Failed to write to socket; err = {:?}", e);
            // //     return;
            // // }
        });
    }
}

async fn handle_connection(client_socket: TcpStream, addr: std::net::SocketAddr,
    acceptor: TlsAcceptor, connector: TlsConnector
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client_tls = acceptor.accept(client_socket).await?;

    println!("[{}] inbound TLS up", addr);

    let swrequest_chunk: Vec<&str> = Vec::new();
    let swresponse_chunk: Vec<&str> = Vec::new();

    // Open TCP to the real Com2us Server
    let upstream_tcp = TcpStream::connect("34.160.216.76:443").await?;

    let server_name = rustls::pki_types::ServerName::try_from("summonerswar-gb-lb.qpyou.cn")?;

    let upstream_tls = connector.connect(server_name, upstream_tcp).await?;
    println!("[{}] inbound TLS up to Com2us", addr);

    let (mut client_rx, mut client_tx) = tokio::io::split(client_tls);
    let (mut server_rx, mut server_tx) = tokio::io::split(upstream_tls);

    let to_upstream = async {
        let mut buf = vec![0u8; 8192];

        loop {
            let n = client_rx.read(&mut buf).await?;
            if n == 0 { break; }

            println!("[{}] →→ {} bytes\n{}", addr, n, String::from_utf8_lossy(&buf[..n]));

            server_tx.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };

        let to_client = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = server_rx.read(&mut buf).await?;
            decrypt_response(&"b64").unwrap();
            // if let Some(json) = decrypt_response(&String::from_utf8_lossy(&buf[..n])).unwrap();
            println!("[{}] ←← {} bytes\n{}", addr, n, String::from_utf8_lossy(&buf[..n]));
            client_tx.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };

    let _ = tokio::try_join!(to_upstream, to_client);
    println!("[{}] closed", addr);
    Ok(())
}
