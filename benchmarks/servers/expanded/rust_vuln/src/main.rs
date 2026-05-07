use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;
const SECRET: &[u8] = b"rust-benchmark-secret-key";

#[derive(Deserialize)]
struct HmacRequest {
    message: String,
    mac: String,
}

#[post("/api/verify")]
async fn verify_hmac(body: web::Json<HmacRequest>) -> impl Responder {
    let expected_mac = compute_hmac(body.message.as_bytes());
    let provided_mac = hex::decode(&body.mac).unwrap_or_default();

    // VULNERABILITY: non-constant-time comparison with an amplified timing
    // signal. This is intentionally vulnerable benchmark code.
    let mut match_len = 0;
    for i in 0..expected_mac.len() {
        if i >= provided_mac.len() || provided_mac[i] != expected_mac[i] {
            break;
        }
        match_len += 1;
        std::thread::sleep(Duration::from_micros(50));
    }

    if match_len == expected_mac.len() {
        HttpResponse::Ok().json("valid")
    } else {
        HttpResponse::Unauthorized().json("invalid")
    }
}

fn compute_hmac(message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(SECRET).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(verify_hmac))
        .bind("0.0.0.0:8082")?
        .run()
        .await
}
