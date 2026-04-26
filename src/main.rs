use std::fs;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use std::io::{Read, Write};

use rcgen::{CertificateParams, IsCa, KeyPair};

#[tokio::main]
async fn main() {
    if fs::exists("ca.key").is_err() && fs::exists("ca.crt").is_err() {
        if let Err(e) = generate_root_ca() {
            eprintln!("Failed to generate CA: {}", e);
        }
    }

    listener().await;
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

async fn listener() {
    let listener = TcpListener::bind("127.0.0.1:443")
        .await
        .expect("Could not bind to address");

    println!("Listening on port 443");

    loop {
        // Accept a new connection
        let (mut socket, addr) = listener.accept().await.expect("Fail lo load");
        println!("New client connected: {}", addr);

        // Spawn a task to handle the connection concurrently
        tokio::spawn(async move {
            let mut buf = [0; 1024];
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(n) if n == 0 => return, // Connection closed
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Failed to read from socket; err = {:?}", e);
                        return;
                    }
                };

                // Echo the data back to the client
                if let Err(e) = socket.write_all(&buf[0..n]).await {
                    eprintln!("Failed to write to socket; err = {:?}", e);
                    return;
                }
            }
        });
    }
}
