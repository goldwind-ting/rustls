//! A crypto provider for [rustls], built on [RustCrypto] primitives: no C and no assembly, and
//! `no_std` throughout, so it builds wherever Rust does — including freestanding targets.
//!
//! This is a port of [`rustls-pure`] 0.15.4 (the upstream provider, which targets rustls 0.23
//! and reads its randomness from `getrandom`) to rustls 0.24 and to freestanding targets:
//!
//! - the 0.24 provider API: `RecordEncrypter`/`RecordDecrypter` record layer, `StartedKeyExchange`
//!   with the hybrid path behind `HybridKeyExchange`, `crypto::kx`/`crypto::signer`/`crypto::enums`
//!   paths, consuming `Signer::sign`
//! - `no_std`: core and alloc only
//! - randomness is **installed by the application** — see [`set_fill_random`] — because there is
//!   no OS to ask on a freestanding target: a kernel feeds its own entropy source in
//!
//! [`rustls-pure`]: https://crates.io/crates/rustls-pure
//! [rustls]: https://docs.rs/rustls
//! [RustCrypto]: https://github.com/RustCrypto
//!
//! rustls does the TLS protocol itself; a provider only supplies the primitives. The ones here
//! are deliberately few, which keeps the code small enough to review:
//!
//! - TLS 1.3 only, with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305
//! - key exchange with X25519MLKEM768 (post-quantum, preferred), X25519, P-256 and P-384
//! - server keys and client certificates (for mutual TLS) using ECDSA P-256 / P-384 or Ed25519
//!
//! RSA is not offered, for keys or for verifying certificates: the pure-Rust `rsa` crate has an
//! unfixed timing side channel (RUSTSEC-2023-0071). Certificate chains signed with RSA are
//! refused, so a client for arbitrary public websites, many of which still use RSA, is not what
//! this is for; connections where you choose the certificates are. Certificate authorities,
//! cert-manager and Let's Encrypt all issue ECDSA certificates.
//!
//! The upstream provider has not had an outside security audit, and neither has this port. The
//! input-validation code is checked mechanically: [Kani](https://github.com/model-checking/kani)
//! proofs of what it does with the peer's bytes for every input within bounds remain in the
//! `#[cfg(kani)]` `verification` module in this file. Where the standards allow a choice it
//! refuses: X25519 exchanges that end in an all-zero secret, compressed or malformed key shares,
//! and malleable Ed25519 signatures.
//!
//! [rustls]: https://docs.rs/rustls
//! [RustCrypto]: https://github.com/RustCrypto

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

// The tests use std (files, timing) and the primitives directly.
#[cfg(test)]
extern crate std;

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit, KeySizeUser};
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use ed25519_dalek::pkcs8::{ObjectIdentifier, PrivateKeyInfoRef};
// zeroize through the curve crates' re-export, which is the version they use themselves
use ml_kem::{Decapsulate as _, KeyExport as _};
use once_cell::race::OnceBox;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::elliptic_curve::zeroize::Zeroizing;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaque, Iv, Nonce, OutboundPlain, Record, RecordDecrypter, RecordEncrypter,
    Tls13AeadAlgorithm, UnsupportedOperationError, encode_record_header, make_tls13_aad,
};
use rustls::crypto::kx::{
    ActiveKeyExchange, CompletedKeyExchange, HybridKeyExchange, NamedGroup, SharedSecret,
    StartedKeyExchange, SupportedKxGroup,
};
use rustls::crypto::{
    CipherSuite, CryptoProvider, GetRandomFailed, HashAlgorithm, KeyProvider, SecureRandom,
    SignatureScheme, Signer, SigningKey, TicketerFactory, TicketProducer,
    WebPkiSupportedAlgorithms, hash, hmac as rustls_hmac, public_key_to_spki, tls13,
};
use rustls::error::PeerMisbehaved;
use rustls::enums::ContentType;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, SignatureVerificationAlgorithm,
    SubjectPublicKeyInfoDer, alg_id,
};
use rustls::version::TLS13_VERSION;
use rustls::{
    CipherSuiteCommon, ConnectionTrafficSecrets, Error, Tls13CipherSuite,
};
use sha2::Digest as _;

/// The provider: pass it to `rustls::ServerConfig::builder_with_provider` or
/// `rustls::ClientConfig::builder_with_provider`, with TLS 1.3 as the protocol version
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        tls12_cipher_suites: Cow::Borrowed(&[]),
        tls13_cipher_suites: Cow::Borrowed(ALL_TLS13_CIPHER_SUITES),
        // The post-quantum hybrid first, as rustls's own default provider orders them
        kx_groups: Cow::Borrowed(ALL_KX_GROUPS),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &Random,
        key_provider: &Keys,
        ticketer_factory: &NoTicketer,
    }
}

/// Stateless session resumption: none, so a server built from this provider sends no
/// tickets and the connection continues (clients are unaffected).
#[derive(Debug)]
struct NoTicketer;

impl TicketerFactory for NoTicketer {
    fn ticketer(&self) -> Result<Arc<dyn TicketProducer>, Error> {
        Ok(Arc::new(Self))
    }
}

impl TicketProducer for NoTicketer {
    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn lifetime(&self) -> Duration {
        Duration::from_secs(0)
    }
}

// ---------------------------------------------------------------------------------------------
// Randomness

#[derive(Debug)]
struct Random;

impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        fill_random(buf).map_err(|_| GetRandomFailed)
    }
}

/// Fills `buf` with secret randomness.
type FillRandom = fn(buf: &mut [u8]) -> Result<(), Error>;

/// The installed source of secret randomness; `None` until
/// [`set_fill_random`] runs, and every TLS operation fails loudly
/// before that.
static FILL_RANDOM: OnceBox<FillRandom> = OnceBox::new();

/// Install the source of secret randomness. Call once, before any TLS
/// configuration is built: a freestanding target installs its kernel
/// RNG here, a hosted one `getrandom`.
pub fn set_fill_random(fill: FillRandom) {
    let _ = FILL_RANDOM.set(Box::new(fill));
}

/// Fresh secret bytes, wiped when dropped
fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, Error> {
    let mut bytes = Zeroizing::new([0; N]);
    fill_random(&mut *bytes)?;
    Ok(bytes)
}

/// Fills `bytes` in place, for secrets of a type of their own that would otherwise be copied out
/// of a wiped buffer and left behind unwiped
fn fill_random(bytes: &mut [u8]) -> Result<(), Error> {
    let fill = FILL_RANDOM
        .get()
        .copied()
        .ok_or(Error::FailedToGetRandomBytes)?;
    fill(bytes)
}

// ---------------------------------------------------------------------------------------------
// Hashes and HMAC

struct Sha<D>(core::marker::PhantomData<fn() -> D>);

static SHA256: Sha<sha2::Sha256> = Sha(core::marker::PhantomData);
static SHA384: Sha<sha2::Sha384> = Sha(core::marker::PhantomData);

trait ShaAlgorithm: sha2::Digest + Clone + Send + Sync + 'static {
    const ALGORITHM: HashAlgorithm;
}

impl ShaAlgorithm for sha2::Sha256 {
    const ALGORITHM: HashAlgorithm = HashAlgorithm::SHA256;
}

impl ShaAlgorithm for sha2::Sha384 {
    const ALGORITHM: HashAlgorithm = HashAlgorithm::SHA384;
}

impl<D: ShaAlgorithm> hash::Hash for Sha<D> {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(ShaContext(D::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&D::digest(data))
    }

    fn output_len(&self) -> usize {
        <D as sha2::Digest>::output_size()
    }

    fn algorithm(&self) -> HashAlgorithm {
        D::ALGORITHM
    }
}

struct ShaContext<D>(D);

impl<D: ShaAlgorithm> hash::Context for ShaContext<D> {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

struct Hmac<D>(core::marker::PhantomData<fn() -> D>);

static HMAC_SHA256: Hmac<sha2::Sha256> = Hmac(core::marker::PhantomData);
static HMAC_SHA384: Hmac<sha2::Sha384> = Hmac(core::marker::PhantomData);

impl<D> rustls_hmac::Hmac for Hmac<D>
where
    D: ShaAlgorithm + hmac::EagerHash,
    hmac::Hmac<D>: KeyInit + hmac::Mac + Clone + Send + Sync,
{
    fn with_key(&self, key: &[u8]) -> Box<dyn rustls_hmac::Key> {
        // HMAC takes keys of any length
        Box::new(HmacKey(
            <hmac::Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length"),
        ))
    }

    fn hash_output_len(&self) -> usize {
        <D as sha2::Digest>::output_size()
    }
}

struct HmacKey<M>(M);

impl<M: hmac::Mac + Clone + Send + Sync> rustls_hmac::Key for HmacKey<M> {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> rustls_hmac::Tag {
        let mut mac = self.0.clone();
        mac.update(first);
        for part in middle {
            mac.update(part);
        }
        mac.update(last);
        rustls_hmac::Tag::new(&mac.finalize().into_bytes())
    }

    fn tag_len(&self) -> usize {
        <M as hmac::digest::OutputSizeUser>::output_size()
    }
}

// ---------------------------------------------------------------------------------------------
// Cipher suites (TLS 1.3)

/// AES-128-GCM with SHA-256
static TLS13_AES_128_GCM_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &SHA256,
        // RFC 8446 section 5.5: 2^24.5 full-size records per key for AES-GCM, rounded down
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &tls13::HkdfUsingHmac(&HMAC_SHA256),
    aead_alg: &Aead::<aes_gcm::Aes128Gcm>(core::marker::PhantomData),
    quic: None,
};

static ALL_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] = &[
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
];

/// The key exchange groups, in preference order (the hybrid first, as rustls's own
/// default provider orders them)
static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519MLKEM768, &X25519, &SECP256R1, &SECP384R1];

/// AES-256-GCM with SHA-384
static TLS13_AES_256_GCM_SHA384: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &SHA384,
        confidentiality_limit: 1 << 24,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &tls13::HkdfUsingHmac(&HMAC_SHA384),
    aead_alg: &Aead::<aes_gcm::Aes256Gcm>(core::marker::PhantomData),
    quic: None,
};

/// ChaCha20-Poly1305 with SHA-256
static TLS13_CHACHA20_POLY1305_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &SHA256,
        confidentiality_limit: u64::MAX,
    },
    protocol_version: TLS13_VERSION,
    hkdf_provider: &tls13::HkdfUsingHmac(&HMAC_SHA256),
    aead_alg: &Aead::<chacha20poly1305::ChaCha20Poly1305>(core::marker::PhantomData),
    quic: None,
};

/// A TLS 1.3 AEAD: 12-byte nonces and 16-byte tags, as all three suites have
struct Aead<C>(core::marker::PhantomData<fn() -> C>);

/// What the AEAD must provide: 12-byte nonces and 16-byte tags, as types, so building a nonce
/// needs no check at run time; the key sizes are checked below, at compile time
trait Cipher:
    AeadInOut + AeadCore<NonceSize = U12, TagSize = U16> + KeyInit + Send + Sync + 'static
{
    /// The key length rustls is told, so the keys it derives always fit `new_from_slice`
    const KEY_LEN: usize =
        <<Self as KeySizeUser>::KeySize as aes_gcm::aead::array::typenum::Unsigned>::USIZE;
    fn traffic_secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets;
}

impl Cipher for aes_gcm::Aes128Gcm {
    fn traffic_secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
    }
}

impl Cipher for aes_gcm::Aes256Gcm {
    fn traffic_secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Aes256Gcm { key, iv }
    }
}

impl Cipher for chacha20poly1305::ChaCha20Poly1305 {
    fn traffic_secrets(key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
    }
}

const TAG_LEN: usize = 16;

/// The nonce length of every suite here (and of TLS 1.3)
const NONCE_LEN: usize = 12;

impl<C: Cipher> Tls13AeadAlgorithm for Aead<C> {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordEncrypter> {
        Box::new(Crypter::<C>::new(key.as_ref(), iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn RecordDecrypter> {
        Box::new(Crypter::<C>::new(key.as_ref(), iv))
    }

    fn key_len(&self) -> usize {
        C::KEY_LEN
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(C::traffic_secrets(key, iv))
    }
}

struct Crypter<C> {
    cipher: C,
    iv: Iv,
}

impl<C: Cipher> Crypter<C> {
    fn new(key: &[u8], iv: Iv) -> Self {
        Self {
            cipher: C::new_from_slice(key).expect("key of the suite's length"),
            iv,
        }
    }

    /// The record's nonce: the IV XORed with its sequence number (RFC 8446 section 5.3), so no
    /// two records under one key share one
    fn nonce(&self, seq: u64) -> aes_gcm::aead::Nonce<C> {
        let nonce: [u8; NONCE_LEN] = Nonce::new(&self.iv, seq)
            .to_array()
            .expect("the suite's IV is 12 bytes");
        nonce.into()
    }

    /// Encrypts record `seq` in place and returns its tag
    fn seal(&self, seq: u64, aad: &[u8], text: &mut [u8]) -> Result<aes_gcm::aead::Tag<C>, Error> {
        self.cipher
            .encrypt_inout_detached(&self.nonce(seq), aad, text.into())
            .map_err(|_| Error::EncryptError)
    }

    /// Decrypts record `seq` in place if `tag` is right; the AEAD compares tags in constant time
    fn open(&self, seq: u64, aad: &[u8], text: &mut [u8], tag: &[u8]) -> Result<(), Error> {
        let tag = aes_gcm::aead::Tag::<C>::try_from(tag).map_err(|_| Error::DecryptError)?;
        self.cipher
            .decrypt_inout_detached(&self.nonce(seq), aad, text.into(), &tag)
            .map_err(|_| Error::DecryptError)
    }
}

impl<C: Cipher> RecordEncrypter for Crypter<C> {
    fn encrypt(
        &mut self,
        record: Record<OutboundPlain<'_>>,
        seq: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let total_len = self.encrypted_payload_len(record.payload.len());
        let typ = ContentType::ApplicationData;
        let header = encode_record_header(typ, record.version, total_len as u16);
        out.reserve(header.len() + total_len);
        out.extend_from_slice(&header);
        let start = out.len();
        record.payload.copy_to_vec(out);
        // TLSInnerPlaintext: the content, then its real type (RFC 8446 section 5.2)
        out.extend_from_slice(&record.typ.to_array());
        let tag = self.seal(
            seq,
            &make_tls13_aad(typ, record.version.encode(), total_len),
            &mut out[start..],
        )?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        sealed_payload_len(payload_len)
    }
}

/// A record's payload for `text_len` bytes of content: the content, its type, then the tag
fn sealed_payload_len(text_len: usize) -> usize {
    text_len + 1 + TAG_LEN
}

/// How much of a record's payload of `payload_len` bytes is the encrypted text, before its tag;
/// a payload too short for a tag is refused
fn sealed_text_len(payload_len: usize) -> Option<usize> {
    payload_len.checked_sub(TAG_LEN)
}

impl<C: Cipher> RecordDecrypter for Crypter<C> {
    fn decrypt<'a>(
        &mut self,
        mut record: Record<InboundOpaque<'a>>,
        seq: u64,
    ) -> Result<Record<&'a [u8]>, Error> {
        let payload = &mut record.payload;
        let plain_len = sealed_text_len(payload.len()).ok_or(Error::DecryptError)?;
        let aad = make_tls13_aad(record.typ, record.version.version(), payload.len());
        let (text, tag) = payload.split_at_mut(plain_len);
        self.open(seq, &aad, text, tag)?;
        payload.truncate(plain_len);
        record.into_tls13_unpadded_record()
    }
}

// The sizes the code above relies on, for every suite: the tag `TAG_LEN` stands for, and the
// key that RFC 8446 gives the suite (rustls derives keys of `KEY_LEN`, so the `expect`s on
// `new_from_slice` cannot fail)
const _: () = {
    use aes_gcm::aead::array::typenum::Unsigned;
    macro_rules! check {
        ($($cipher:ty => $key:expr),*) => {$(
            assert!(<$cipher as Cipher>::KEY_LEN == $key);
            assert!(<<$cipher as AeadCore>::TagSize as Unsigned>::USIZE == TAG_LEN);
        )*};
    }
    check!(
        aes_gcm::Aes128Gcm => 16,
        aes_gcm::Aes256Gcm => 32,
        chacha20poly1305::ChaCha20Poly1305 => 32
    );
};

// ---------------------------------------------------------------------------------------------
// Key exchange

// The shape of the peer's key share, checked here before any of it reaches a curve or ML-KEM:
// apart from the cryptography, and without rustls's `Error` (whose drop Kani cannot bound), so
// Kani proves these on every input (`mod verification`)

fn invalid_key_share() -> Error {
    PeerMisbehaved::InvalidKeyShare.into()
}

/// An X25519 share: 32 bytes
fn x25519_share(share: &[u8]) -> Option<[u8; X25519_SHARE_LEN]> {
    share.try_into().ok()
}

/// A P-256 or P-384 share: an uncompressed point, 4 then both coordinates, as TLS 1.3 requires
/// (RFC 8446 section 4.2.8.2); compressed points and the point at infinity are refused
fn ec_share(share: &[u8], coordinate_len: usize) -> Option<&[u8]> {
    match share {
        [4, coordinates @ ..] if coordinates.len() == 2 * coordinate_len => Some(share),
        _ => None,
    }
}

/// An X25519MLKEM768 share: ML-KEM's part of `mlkem_len` bytes (the client's encapsulation key or
/// the server's ciphertext), then X25519's, and nothing else
fn hybrid_share(share: &[u8], mlkem_len: usize) -> Option<(&[u8], &[u8])> {
    (share.len() == mlkem_len + X25519_SHARE_LEN).then(|| share.split_at(mlkem_len))
}

/// `first`, then `second`: the hybrid's shares and its secret
fn concat(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(first.len() + second.len());
    bytes.extend_from_slice(first);
    bytes.extend_from_slice(second);
    bytes
}

#[derive(Debug)]
struct X25519Group;
static X25519: X25519Group = X25519Group;

impl SupportedKxGroup for X25519Group {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        Ok(StartedKeyExchange::Single(Box::new(X25519Exchange::new()?)))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct X25519Exchange {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl X25519Exchange {
    /// A fresh random key
    fn new() -> Result<Self, Error> {
        let secret = x25519_dalek::StaticSecret::from(*random::<32>()?);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Self { secret, public })
    }
}

impl X25519Exchange {
    /// The secret shared with the peer, refused if it is all zeros
    fn agree(self, peer_pub_key: &[u8]) -> Result<x25519_dalek::SharedSecret, Error> {
        let peer = x25519_share(peer_pub_key).ok_or_else(invalid_key_share)?;
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // An all-zero result means a low-order peer key (RFC 8446 section 7.4.2)
        if all_zero(shared.as_bytes()) {
            return Err(invalid_key_share());
        }
        Ok(shared)
    }
}

/// Whether an X25519 result is all zeros, in constant time: every byte is ORed in, with no
/// early exit, and only whether the result is zero, which is public, is compared. (The same as
/// x25519-dalek's `was_contributory`, since its results are always fully reduced, but here the
/// whole check is rustls-pure's own.) Out of line, so its machine code can be checked for
/// branches (`ct-asm.sh`).
#[inline(never)]
fn all_zero(secret: &[u8; 32]) -> bool {
    core::hint::black_box(secret.iter().fold(0, |acc, byte| acc | byte)) == 0
}

impl ActiveKeyExchange for X25519Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        Ok(SharedSecret::from(
            &self.agree(peer_pub_key)?.as_bytes()[..],
        ))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

#[derive(Debug)]
struct Secp256r1Group;
static SECP256R1: Secp256r1Group = Secp256r1Group;

impl SupportedKxGroup for Secp256r1Group {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        // A random scalar; out-of-range values (chance below 2^-32) are drawn again
        let secret = loop {
            if let Ok(secret) = p256::SecretKey::from_slice(random::<32>()?.as_slice()) {
                break secret;
            }
        };
        let public = secret.public_key().to_sec1_bytes().into_vec();
        Ok(StartedKeyExchange::Single(Box::new(Secp256r1Exchange {
            secret,
            public,
        })))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

struct Secp256r1Exchange {
    secret: p256::SecretKey,
    /// Uncompressed, as TLS requires
    public: Vec<u8>,
}

impl ActiveKeyExchange for Secp256r1Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer = p256::PublicKey::from_sec1_bytes(
            ec_share(peer_pub_key, 32).ok_or_else(invalid_key_share)?,
        )
        .map_err(|_| invalid_key_share())?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(SharedSecret::from(&shared.raw_secret_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

#[derive(Debug)]
struct Secp384r1Group;
static SECP384R1: Secp384r1Group = Secp384r1Group;

impl SupportedKxGroup for Secp384r1Group {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        let secret = loop {
            if let Ok(secret) = p384::SecretKey::from_slice(random::<48>()?.as_slice()) {
                break secret;
            }
        };
        let public = secret.public_key().to_sec1_bytes().into_vec();
        Ok(StartedKeyExchange::Single(Box::new(Secp384r1Exchange {
            secret,
            public,
        })))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }
}

struct Secp384r1Exchange {
    secret: p384::SecretKey,
    public: Vec<u8>,
}

impl ActiveKeyExchange for Secp384r1Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer = p384::PublicKey::from_sec1_bytes(
            ec_share(peer_pub_key, 48).ok_or_else(invalid_key_share)?,
        )
        .map_err(|_| invalid_key_share())?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(SharedSecret::from(&shared.raw_secret_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }
}

/// X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem): ML-KEM-768 (FIPS 203) and X25519 at once, so
/// the secret stays safe as long as either holds, including against a future quantum computer.
/// Shares and the secret put ML-KEM's part first and X25519's second, as rustls's own providers
/// do. The X25519 part is checked as the plain X25519 group checks it.
#[derive(Debug)]
struct X25519MlKem768Group;
static X25519MLKEM768: X25519MlKem768Group = X25519MlKem768Group;

/// The client's ML-KEM-768 share: its encapsulation key
const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;
/// The server's ML-KEM-768 share: the ciphertext
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const X25519_SHARE_LEN: usize = 32;

impl X25519MlKem768Group {
    /// The client's side, from an ML-KEM seed (64 random bytes) and an X25519 key
    fn start_with(seed: ml_kem::Seed, x25519: X25519Exchange) -> X25519MlKem768Exchange {
        let decapsulation = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(seed);
        let share = concat(
            &decapsulation.encapsulation_key().to_bytes(),
            x25519.public.as_bytes(),
        );
        X25519MlKem768Exchange {
            decapsulation,
            x25519,
            share,
        }
    }

    /// The server's side: encapsulates to the client's ML-KEM key with `m` (32 random bytes),
    /// and does X25519 with `x25519`
    fn respond(
        client_share: &[u8],
        m: &ml_kem::B32,
        x25519: X25519Exchange,
    ) -> Result<CompletedKeyExchange, Error> {
        let (key, x25519_share) = hybrid_share(client_share, MLKEM768_ENCAPSULATION_KEY_LEN)
            .ok_or_else(invalid_key_share)?;
        let key = ml_kem::Key::<ml_kem::EncapsulationKey<ml_kem::MlKem768>>::try_from(key)
            .map_err(|_| invalid_key_share())?;
        // Refuses keys whose coefficients are not reduced (FIPS 203 section 7.2)
        let key = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new(&key)
            .map_err(|_| invalid_key_share())?;
        let (ciphertext, mlkem_secret) = key.encapsulate_deterministic(m);
        let mlkem_secret = Zeroizing::new(mlkem_secret);
        let pub_key = concat(&ciphertext, x25519.public.as_bytes());
        let x25519_secret = x25519.agree(x25519_share)?;
        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key,
            secret: hybrid_secret(mlkem_secret.as_ref(), x25519_secret.as_bytes()),
        })
    }
}

/// ML-KEM's secret, then X25519's
fn hybrid_secret(mlkem: &[u8; 32], x25519: &[u8; 32]) -> SharedSecret {
    let mut secret = Zeroizing::new([0; 64]);
    put_together(&mut secret, mlkem, x25519);
    // rustls's SharedSecret wipes its copy when dropped
    SharedSecret::from(&secret[..])
}

/// The two secrets side by side, copied without looking at them. Out of line, so its machine
/// code can be checked for branches (`ct-asm.sh`).
#[inline(never)]
fn put_together(secret: &mut [u8; 64], mlkem: &[u8; 32], x25519: &[u8; 32]) {
    let (first, second) = secret.split_at_mut(32);
    first.copy_from_slice(mlkem);
    second.copy_from_slice(x25519);
}

impl SupportedKxGroup for X25519MlKem768Group {
    fn start(&self) -> Result<StartedKeyExchange, Error> {
        let seed = random::<64>()?;
        Ok(StartedKeyExchange::Hybrid(Box::new(Self::start_with(
            ml_kem::Seed::from(*seed),
            X25519Exchange::new()?,
        ))))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        // `m` gives away ML-KEM's secret, so it is made where it is wiped and only lent out
        let mut m = Zeroizing::new(ml_kem::B32::default());
        fill_random(&mut m)?;
        Self::respond(client_share, &m, X25519Exchange::new()?)
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

struct X25519MlKem768Exchange {
    decapsulation: ml_kem::DecapsulationKey<ml_kem::MlKem768>,
    x25519: X25519Exchange,
    /// The encapsulation key, then the X25519 public key
    share: Vec<u8>,
}

impl ActiveKeyExchange for X25519MlKem768Exchange {
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        let (ciphertext, x25519_share) =
            hybrid_share(server_share, MLKEM768_CIPHERTEXT_LEN).ok_or_else(invalid_key_share)?;
        let ciphertext = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(ciphertext)
            .map_err(|_| invalid_key_share())?;
        // A ciphertext that was tampered with gives an unrelated secret (FIPS 203's implicit
        // rejection), so the handshake fails at the Finished messages
        let mlkem_secret = Zeroizing::new(self.decapsulation.decapsulate(&ciphertext));
        let x25519_secret = self.x25519.agree(x25519_share)?;
        Ok(hybrid_secret(
            mlkem_secret.as_ref(),
            x25519_secret.as_bytes(),
        ))
    }

    /// The X25519 part is offered on its own too, so a server without ML-KEM can pick it with
    /// no HelloRetryRequest
    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

impl HybridKeyExchange for X25519MlKem768Exchange {
    /// The X25519 component, offered alongside the hybrid so a server without ML-KEM
    /// needs no HelloRetryRequest
    fn component(&self) -> (NamedGroup, &[u8]) {
        (NamedGroup::X25519, self.x25519.public.as_bytes())
    }

    fn complete_component(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        Box::new(self.x25519).complete(peer_pub_key)
    }

    fn as_key_exchange(&self) -> &(dyn ActiveKeyExchange + 'static) {
        self
    }

    fn into_key_exchange(self: Box<Self>) -> Box<dyn ActiveKeyExchange> {
        self
    }
}

// ---------------------------------------------------------------------------------------------
// The server's private key

#[derive(Debug)]
struct Keys;

impl KeyProvider for Keys {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Box<dyn SigningKey>, Error> {
        let unsupported = |what: &str| {
            Error::General(format!(
                "{what}; rustls-pure takes ECDSA P-256 / P-384 or Ed25519 keys"
            ))
        };
        let key: Box<dyn SigningKey> = match &key_der {
            PrivateKeyDer::Pkcs8(der) => {
                let der = der.secret_pkcs8_der();
                if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
                    Box::new(EcdsaKey::P256(Arc::new(key)))
                } else if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
                    Box::new(EcdsaKey::P384(Arc::new(key)))
                } else if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
                    Box::new(Ed25519Key(Arc::new(key)))
                } else {
                    return Err(unsupported(&unsupported_pkcs8(der)));
                }
            }
            PrivateKeyDer::Sec1(der) => {
                let der = der.secret_sec1_der();
                if let Ok(key) = p256::SecretKey::from_sec1_der(der) {
                    Box::new(EcdsaKey::P256(Arc::new(key.into())))
                } else if let Ok(key) = p384::SecretKey::from_sec1_der(der) {
                    Box::new(EcdsaKey::P384(Arc::new(key.into())))
                } else {
                    return Err(unsupported("unsupported EC key curve"));
                }
            }
            PrivateKeyDer::Pkcs1(_) => return Err(unsupported("RSA keys are not supported")),
            _ => return Err(unsupported("unsupported key format")),
        };
        Ok(key)
    }
}

/// What is wrong with a PKCS#8 key none of the parsers took: its algorithm, from the key itself
fn unsupported_pkcs8(der: &[u8]) -> String {
    const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    let Ok(info) = PrivateKeyInfoRef::try_from(der) else {
        return "not a valid PKCS#8 key".to_string();
    };
    let algorithm = info.algorithm;
    if algorithm.oid == RSA {
        "RSA keys are not supported".to_string()
    } else if algorithm.oid == EC {
        match algorithm.parameters_oid() {
            Ok(curve) => format!("unsupported EC key curve {curve}"),
            Err(_) => "an EC key without a named curve".to_string(),
        }
    } else {
        format!("unsupported PKCS#8 key algorithm {}", algorithm.oid)
    }
}

/// The key, shared with the signer rustls asks for in each handshake rather than copied into it,
/// so the secret is in memory once
#[derive(Clone)]
enum EcdsaKey {
    P256(Arc<p256::ecdsa::SigningKey>),
    P384(Arc<p384::ecdsa::SigningKey>),
}

impl fmt::Debug for EcdsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material
        f.write_str(match self {
            Self::P256(_) => "EcdsaKey(P-256)",
            Self::P384(_) => "EcdsaKey(P-384)",
        })
    }
}

impl EcdsaKey {
    fn scheme(&self) -> SignatureScheme {
        match self {
            Self::P256(_) => SignatureScheme::ECDSA_NISTP256_SHA256,
            Self::P384(_) => SignatureScheme::ECDSA_NISTP384_SHA384,
        }
    }
}

impl SigningKey for EcdsaKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&self.scheme())
            .then(|| Box::new(EcdsaSigner(self.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        let spki = match self {
            Self::P256(key) => public_key_to_spki(
                &alg_id::ECDSA_P256,
                key.verifying_key().to_sec1_point(false).as_bytes(),
            ),
            Self::P384(key) => public_key_to_spki(
                &alg_id::ECDSA_P384,
                key.verifying_key().to_sec1_point(false).as_bytes(),
            ),
        };
        Some(spki)
    }
}

#[derive(Debug)]
struct EcdsaSigner(EcdsaKey);

impl Signer for EcdsaSigner {
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, Error> {
        use p256::ecdsa::signature::Signer as _;
        // Deterministic nonces (RFC 6979); DER-encoded, as TLS sends them
        let der = match &self.0 {
            EcdsaKey::P256(key) => {
                let signature: p256::ecdsa::Signature = key
                    .try_sign(message)
                    .map_err(|e| Error::General(e.to_string()))?;
                signature.to_der().to_bytes().into_vec()
            }
            EcdsaKey::P384(key) => {
                let signature: p384::ecdsa::Signature = key
                    .try_sign(message)
                    .map_err(|e| Error::General(e.to_string()))?;
                signature.to_der().to_bytes().into_vec()
            }
        };
        Ok(der)
    }

    fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }
}

/// Shared with each handshake's signer, as [`EcdsaKey`] is
struct Ed25519Key(Arc<ed25519_dalek::SigningKey>);

impl fmt::Debug for Ed25519Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519Key")
    }
}

impl SigningKey for Ed25519Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(Self(self.0.clone())) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(
            &alg_id::ED25519,
            self.0.verifying_key().as_bytes(),
        ))
    }
}

impl Signer for Ed25519Key {
    fn sign(self: Box<Self>, message: &[u8]) -> Result<Vec<u8>, Error> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(message).to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

// ---------------------------------------------------------------------------------------------
// Signature verification, for client certificates and their chains

/// ECDSA on `curve` with the message hashed by `hash`
#[derive(Debug)]
struct EcdsaVerify {
    curve: Curve,
    hash: Prehash,
}

#[derive(Debug, Clone, Copy)]
enum Curve {
    P256,
    P384,
}

/// The hashes ECDSA signatures are verified with; two, so every match on them is exhaustive
#[derive(Debug, Clone, Copy)]
enum Prehash {
    Sha256,
    Sha384,
}

impl Prehash {
    /// The message's digest, kept on the stack
    fn digest(self, message: &[u8]) -> hash::Output {
        match self {
            Self::Sha256 => hash::Output::new(&sha2::Sha256::digest(message)),
            Self::Sha384 => hash::Output::new(&sha2::Sha384::digest(message)),
        }
    }
}

static ECDSA_P256_SHA256: EcdsaVerify = EcdsaVerify {
    curve: Curve::P256,
    hash: Prehash::Sha256,
};
static ECDSA_P256_SHA384: EcdsaVerify = EcdsaVerify {
    curve: Curve::P256,
    hash: Prehash::Sha384,
};
static ECDSA_P384_SHA256: EcdsaVerify = EcdsaVerify {
    curve: Curve::P384,
    hash: Prehash::Sha256,
};
static ECDSA_P384_SHA384: EcdsaVerify = EcdsaVerify {
    curve: Curve::P384,
    hash: Prehash::Sha384,
};

impl SignatureVerificationAlgorithm for EcdsaVerify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        // The key and the signature are parsed first: a malformed one is refused before the
        // message is hashed
        match self.curve {
            Curve::P256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let signature =
                    p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                key.verify_prehash(self.hash.digest(message).as_ref(), &signature)
                    .map_err(|_| InvalidSignature)
            }
            Curve::P384 => {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| InvalidSignature)?;
                let signature =
                    p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                key.verify_prehash(self.hash.digest(message).as_ref(), &signature)
                    .map_err(|_| InvalidSignature)
            }
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        match self.curve {
            Curve::P256 => alg_id::ECDSA_P256,
            Curve::P384 => alg_id::ECDSA_P384,
        }
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.hash {
            Prehash::Sha256 => alg_id::ECDSA_SHA256,
            Prehash::Sha384 => alg_id::ECDSA_SHA384,
        }
    }
}

#[derive(Debug)]
struct Ed25519Verify;
static ED25519: Ed25519Verify = Ed25519Verify;

impl SignatureVerificationAlgorithm for Ed25519Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let (key, signature) = ed25519_parts(public_key, signature)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature);
        // Strict: rejects malleable signatures and small-order keys
        key.verify_strict(message, &signature)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

/// An Ed25519 public key and signature: 32 and 64 bytes, as RFC 8032 has them; the key is the
/// raw one inside the certificate's SubjectPublicKeyInfo, which webpki takes out
fn ed25519_parts(
    public_key: &[u8],
    signature: &[u8],
) -> Result<([u8; 32], [u8; 64]), InvalidSignature> {
    match (public_key.try_into(), signature.try_into()) {
        (Ok(key), Ok(signature)) => Ok((key, signature)),
        _ => Err(InvalidSignature),
    }
}

static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = match WebPkiSupportedAlgorithms::new(
    &[
        &ECDSA_P256_SHA256,
        &ECDSA_P256_SHA384,
        &ECDSA_P384_SHA256,
        &ECDSA_P384_SHA384,
        &ED25519,
    ],
    &[
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[&ECDSA_P384_SHA384, &ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[&ECDSA_P256_SHA256, &ECDSA_P384_SHA256],
        ),
        (SignatureScheme::ED25519, &[&ED25519]),
    ],
) {
    Ok(algs) => algs,
    Err(_) => panic!("bad WebPkiSupportedAlgorithms"),
};

// The provider's own tests: known answers and known attacks (Wycheproof vectors, plus the glue
// between rustls and the primitives that the vectors cannot see), and the broken-input
// properties. They are unit tests because they reach into the crate's internals.
#[cfg(test)]
mod tests;

// Kani's proofs of the code above that takes the peer's bytes: every input up to the bounds
// given, not samples. The cryptography is the RustCrypto crates' and the protocol rustls's, so
// these cover what this provider itself does with a share, a record or a signature before
// handing it on. `cargo kani -p rustls-rustcrypto` (Linux).
#[cfg(kani)]
mod verification {
    use super::*;

    /// Any length up to `N`
    fn any_len<const N: usize>() -> usize {
        kani::any_where(|&len: &usize| len <= N)
    }

    /// Exactly the 32-byte shares are taken for X25519, as they are
    #[kani::proof]
    #[kani::unwind(41)]
    fn x25519_shares_are_exactly_32_bytes() {
        let bytes: [u8; 40] = kani::any();
        let share = &bytes[..any_len::<40>()];
        match x25519_share(share) {
            Some(key) => {
                assert!(share.len() == 32);
                let i = kani::any_where(|&i: &usize| i < 32);
                assert!(key[i] == share[i]);
            }
            None => {
                assert!(share.len() != 32);
            }
        }
    }

    /// P-256 and P-384 take exactly the uncompressed points of their size, and pass them on
    /// untouched: the curve crates never see a compressed point, the point at infinity or bytes
    /// past the point
    #[kani::proof]
    fn ec_shares_are_uncompressed_points_of_the_curve() {
        let bytes: [u8; 100] = kani::any();
        let share = &bytes[..any_len::<100>()];
        let coordinate_len = if kani::any() { 32 } else { 48 };
        let uncompressed = share.len() == 1 + 2 * coordinate_len && share[0] == 4;
        match ec_share(share, coordinate_len) {
            Some(point) => {
                assert!(uncompressed);
                assert!(point.as_ptr() == share.as_ptr() && point.len() == share.len());
            }
            None => {
                assert!(!uncompressed);
            }
        }
    }

    /// A hybrid share of any length: refused unless it is ML-KEM's part and X25519's exactly,
    /// and split where ML-KEM's ends, for the client's share and the server's
    #[kani::proof]
    fn hybrid_shares_split_where_ml_kem_ends() {
        const MAX: usize = MLKEM768_ENCAPSULATION_KEY_LEN + X25519_SHARE_LEN + 8;
        // Only the length matters to the split, so the bytes need not be symbolic
        let bytes = [0u8; MAX];
        let share = &bytes[..any_len::<MAX>()];
        let mlkem_len = if kani::any() {
            MLKEM768_ENCAPSULATION_KEY_LEN
        } else {
            MLKEM768_CIPHERTEXT_LEN
        };
        match hybrid_share(share, mlkem_len) {
            Some((mlkem, x25519)) => {
                assert!(share.len() == mlkem_len + X25519_SHARE_LEN);
                assert!(mlkem.as_ptr() == share.as_ptr() && mlkem.len() == mlkem_len);
                assert!(x25519.as_ptr() == share[mlkem_len..].as_ptr());
                assert!(x25519.len() == X25519_SHARE_LEN);
            }
            None => {
                assert!(share.len() != mlkem_len + X25519_SHARE_LEN);
            }
        }
    }

    /// What one side puts together, the other takes apart into the same two parts
    fn hybrid_round_trip<const MLKEM: usize>() {
        let mlkem: [u8; MLKEM] = kani::any();
        let x25519: [u8; X25519_SHARE_LEN] = kani::any();
        let share = concat(&mlkem, &x25519);
        assert!(share.len() == MLKEM + X25519_SHARE_LEN);
        let (mlkem_part, x25519_part) = hybrid_share(&share, MLKEM).unwrap();
        let i = kani::any_where(|&i: &usize| i < MLKEM);
        assert!(mlkem_part.len() == MLKEM && mlkem_part[i] == mlkem[i]);
        let j = kani::any_where(|&j: &usize| j < X25519_SHARE_LEN);
        assert!(x25519_part.len() == X25519_SHARE_LEN && x25519_part[j] == x25519[j]);
        assert!(x25519_share(x25519_part).unwrap() == x25519);
    }

    /// The client's share (encapsulation key, then X25519's key), as the server reads it
    #[kani::proof]
    #[kani::unwind(33)]
    fn client_hybrid_shares_round_trip() {
        hybrid_round_trip::<MLKEM768_ENCAPSULATION_KEY_LEN>();
    }

    /// The server's share (ciphertext, then X25519's key), as the client reads it
    #[kani::proof]
    #[kani::unwind(33)]
    fn server_hybrid_shares_round_trip() {
        hybrid_round_trip::<MLKEM768_CIPHERTEXT_LEN>();
    }

    /// The hybrid's secret: ML-KEM's 32 bytes, then X25519's 32, nothing else (the bound covers
    /// its wiping when dropped)
    #[kani::proof]
    #[kani::unwind(65)]
    fn the_hybrid_secret_is_ml_kem_then_x25519() {
        let mlkem: [u8; 32] = kani::any();
        let x25519: [u8; 32] = kani::any();
        let secret = hybrid_secret(&mlkem, &x25519);
        let bytes = secret.secret_bytes();
        let i = kani::any_where(|&i: &usize| i < 32);
        assert!(bytes.len() == 64 && bytes[i] == mlkem[i] && bytes[32 + i] == x25519[i]);
    }

    /// A record's payload of any length: refused if shorter than a tag, never an underflow; and
    /// a record this side seals, of any content up to TLS's largest (2^14 bytes and up to 256 of
    /// padding, RFC 8446 section 5.2), opens to its content and type
    #[kani::proof]
    fn record_lengths_never_underflow_or_overflow() {
        let payload_len: usize = kani::any();
        match sealed_text_len(payload_len) {
            Some(text_len) => {
                assert!(text_len + TAG_LEN == payload_len);
            }
            None => {
                assert!(payload_len < TAG_LEN);
            }
        }
        let text_len = kani::any_where(|&len: &usize| len <= (1 << 14) + 256);
        assert!(sealed_text_len(sealed_payload_len(text_len)) == Some(text_len + 1));
    }

    /// Exactly the 32-byte keys and 64-byte signatures go on to Ed25519, as they are
    #[kani::proof]
    #[kani::unwind(73)]
    fn ed25519_keys_and_signatures_have_their_sizes() {
        let key_bytes: [u8; 40] = kani::any();
        let signature_bytes: [u8; 72] = kani::any();
        let key = &key_bytes[..any_len::<40>()];
        let signature = &signature_bytes[..any_len::<72>()];
        match ed25519_parts(key, signature) {
            Ok((key_part, signature_part)) => {
                assert!(key.len() == 32 && signature.len() == 64);
                let i = kani::any_where(|&i: &usize| i < 32);
                let j = kani::any_where(|&j: &usize| j < 64);
                assert!(key_part[i] == key[i] && signature_part[j] == signature[j]);
            }
            Err(_) => {
                assert!(key.len() != 32 || signature.len() != 64);
            }
        }
    }
}
