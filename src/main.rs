use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use std::fs;

use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
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

fn main() {
    if let Err(e) = generate_root_ca() {
        eprintln!("Failed to generate CA: {}", e);
    }
}

#[derive(Clone)]
struct SwProxy;

impl HttpHandler for SwProxy {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        RequestOrResponse::Request(req)
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        response: Response<Body>,
    ) -> Response<Body> {
        println!("Intercepted a response with status: {}", response.status());

        // TODO:

        response
    }
}
