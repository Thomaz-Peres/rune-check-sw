use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::crypto::aws_lc_rs;
use std::{fs, net::SocketAddr};

use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
    certificate_authority::RcgenAuthority,
    hyper::{Request, Response},
};

fn generate_root_ca() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating new Root CA...");

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Summoners War Rust Proxy CA");

    let key_pair = KeyPair::generate()?;

    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let private_key_pem = key_pair.serialize_pem();

    fs::write("ca.crt", cert_pem)?;
    fs::write("ca.key", private_key_pem)?;

    println!("Success! Saved ca.crt and ca.key to the project root.");

    Ok(())
}

#[tokio::main]
async fn main() {
    if fs::exists("ca.key").is_err() {
        if let Err(e) = generate_root_ca() {
            eprintln!("Failed to generate CA: {}", e);
        }
    }

    if let Err(e) = proxy().await {
        eprintln!("Failed to create proxy: {}", e);
    }
}

async fn proxy() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = fs::read_to_string("ca.key").expect("Failed to read ca.key");
    let ca_cert = fs::read_to_string("ca.crt").expect("Failed to read ca.crt");

    let key_pair = KeyPair::from_pem(&private_key).expect("Failed to parse private key");

    let issuer = Issuer::from_ca_cert_pem(&ca_cert, key_pair).expect("Failed to ");

    let ca = RcgenAuthority::new(issuer, 1_100, aws_lc_rs::default_provider());

    //ProxyBui
    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 8080)))
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(SwProxy)
        .build()?;

    println!("Proxy listening on 127.0.0.1:8080. Ready to intercept!");

    tokio::spawn(proxy.start());

    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for Ctrl+c");

    println!("Shutting down proxy");

    Ok(())
}

#[derive(Clone)]
struct SwProxy;

impl HttpHandler for SwProxy {

    async fn handle_request(&mut self, _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        println!("URL: {}", req.uri());

        println!("Body: {:?}", req.body());

        RequestOrResponse::Request(req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext,
        response: Response<Body>,
    ) -> Response<Body> {
        println!("Intercepted a response with status: {}", response.status());

        // _ctx.client_addr

        response
    }
}
