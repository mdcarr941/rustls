#![cfg(feature = "dangerous_configuration")]

use rustls::{
    client::ClientConfig, server::ServerConfig, Certificate, ConfigBuilder, ConfigSide, PrivateKey,
    WantsCipherSuites, WantsVerifier,
};
use std::sync::Arc;

mod common;
use crate::common::*;

/// This will probably be expired by the time you see it (and the signature is incorrect),
/// but it's the Subject Public Key Info which is relevant to this test.
const SERVER_CERT_DER: &[u8] = include_bytes!("cert.der");
const SERVER_KEY_DER: &[u8] = include_bytes!("key.der");

struct UnsafeCertVerifier;

impl UnsafeCertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for UnsafeCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn common_config<Side: ConfigSide>(
    builder: ConfigBuilder<Side, WantsCipherSuites>,
) -> ConfigBuilder<Side, WantsVerifier> {
    builder
        .with_cipher_suites(&[rustls::cipher_suite::TLS13_AES_128_GCM_SHA256])
        .with_kx_groups(&[&rustls::kx_group::SECP256R1])
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
}

fn client_config() -> ClientConfig {
    common_config(rustls::ClientConfig::builder())
        .with_custom_certificate_verifier(UnsafeCertVerifier::new())
        .with_no_client_auth()
}

fn server_config() -> ServerConfig {
    let cert = Certificate(Vec::from(SERVER_CERT_DER));
    let key = PrivateKey(Vec::from(SERVER_KEY_DER));
    common_config(rustls::ServerConfig::builder())
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap()
}

#[test]
fn repro_handshake_error() {
    let client_config = client_config();
    let server_config = server_config();
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);
}
