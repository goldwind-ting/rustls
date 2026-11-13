//! The provider end to end: a TLS 1.3 handshake between two rustls connections, with
//! application data both ways.
//!
//! The certificate is the one in `tests/data/`, issued by the test CA in the same directory,
//! for the name `localhost`. The key is a test key, and only ever used here.

use std::sync::Arc;

use rustls::crypto::CipherSuite;
use rustls::crypto::Identity;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{
    ClientConfig, ClientSide, Connection, RootCertStore, ServerConfig, ServerSide, Tcp,
    TlsInputBuffer,
};

/// The CA the client trusts
const CA_CERT: &[u8] = include_bytes!("data/ca.der");
/// The server's leaf certificate
const SERVER_CERT: &[u8] = include_bytes!("data/server.der");
/// The server's leaf key, in PKCS#8
const SERVER_KEY: &[u8] = include_bytes!("data/server.pkcs8.der");

/// The time the certificate is checked against: inside its validity
#[derive(Debug)]
struct Now;

impl TimeProvider for Now {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(
            core::time::Duration::from_secs(1_800_000_000),
        ))
    }
}

fn configs() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let time = Arc::new(Now);

    let identity = Arc::from(
        Identity::from_cert_chain(vec![CertificateDer::from_slice(SERVER_CERT)])
            .expect("the server's certificate"),
    );
    let server = Arc::new(
        ServerConfig::builder_with_details(provider.clone(), time.clone())
            .with_no_client_auth()
            .with_single_cert(identity, PrivatePkcs8KeyDer::from(SERVER_KEY).into())
            .expect("the server's configuration"),
    );

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_slice(CA_CERT))
        .expect("the test CA");
    let client = Arc::new(
        ClientConfig::builder_with_details(provider, time)
            .with_root_certificates(roots)
            .with_no_client_auth()
            .expect("the client's configuration"),
    );

    (server, client)
}

/// The bytes a connection has read but not yet been given
#[derive(Default)]
struct Input(Vec<u8>);

impl TlsInputBuffer for Input {
    fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn discard(&mut self, num_bytes: usize) {
        self.0.drain(..num_bytes);
    }

    fn received_close_notify(&mut self) {}

    fn has_seen_eof(&self) -> bool {
        false
    }
}

/// Both sides of a handshake, until it is done
fn handshake(
    client: &mut Connection<ClientSide, Tcp>,
    server: &mut Connection<ServerSide, Tcp>,
    to_server: &mut Vec<u8>,
) {
    let mut client_in = Input::default();
    let mut server_in = Input::default();
    let mut to_client = Vec::new();

    // The client's hello is in `to_server` already
    server_in.0.append(to_server);

    for _ in 0..16 {
        // Each side reads what the peer sent, and writes what it has to say
        let mut sink = Vec::new();
        server
            .read_tls(&mut server_in, &mut to_client)
            .handle_all(&mut sink)
            .expect("the server's reading");
        let mut sink = Vec::new();
        client
            .read_tls(&mut client_in, to_server)
            .handle_all(&mut sink)
            .expect("the client's reading");

        // ... and the bytes go to the peer
        server_in.0.append(to_server);
        client_in.0.append(&mut to_client);

        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
    }
    panic!("the handshake did not finish");
}

#[test]
fn a_tls13_handshake_with_application_data_both_ways() {
    rustls_rustcrypto::set_fill_random(|buf| {
        getrandom::fill(buf).map_err(|_| rustls::Error::FailedToGetRandomBytes)
    });

    let (server_config, client_config) = configs();
    let mut to_server = Vec::new();
    let mut client = client_config
        .connect(ServerName::try_from("localhost").unwrap())
        .build(&mut to_server)
        .expect("the client's connection");
    let mut server = Connection::new(server_config).expect("the server's connection");

    handshake(&mut client, &mut server, &mut to_server);

    assert!(!client.is_handshaking(), "the client is still handshaking");
    assert!(!server.is_handshaking(), "the server is still handshaking");

    // TLS 1.3, with the post-quantum hybrid
    let group = client
        .negotiated_key_exchange_group()
        .expect("the negotiated group");
    assert_eq!(
        group.name(),
        rustls::crypto::kx::NamedGroup::X25519MLKEM768,
    );
    assert_eq!(
        client
            .negotiated_cipher_suite()
            .expect("the negotiated suite")
            .suite(),
        CipherSuite::TLS13_AES_128_GCM_SHA256,
    );

    // The client sends, the server reads
    let mut to_server = Vec::new();
    client
        .write(b"ping".as_slice().into(), &mut to_server)
        .expect("the client's writing");
    let mut server_in = Input(to_server);
    let mut out = Vec::new();
    let mut plain = Vec::new();
    server
        .read_tls(&mut server_in, &mut out)
        .handle_all(&mut plain)
        .expect("the server's reading");
    assert_eq!(plain, b"ping");

    // ... and the server answers, the client reads
    let mut to_client = Vec::new();
    server
        .write(b"pong".as_slice().into(), &mut to_client)
        .expect("the server's writing");
    let mut client_in = Input(to_client);
    let mut out = Vec::new();
    let mut plain = Vec::new();
    client
        .read_tls(&mut client_in, &mut out)
        .handle_all(&mut plain)
        .expect("the client's reading");
    assert_eq!(plain, b"pong");
}
