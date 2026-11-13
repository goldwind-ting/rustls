# rustls-rustcrypto

A [`rustls`] crypto provider built on [RustCrypto] primitives: TLS 1.3 only,
no C and no assembly, `no_std` throughout, with the randomness source
installed by the application.

## What it provides

- TLS 1.3 only, with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305
- Key exchange: X25519MLKEM768 (post-quantum, preferred), X25519, P-256, P-384
- Server keys and client certificates: ECDSA P-256 / P-384 or Ed25519
- Certificate verification against those same signature algorithms

RSA is deliberately not offered: the pure-Rust `rsa` crate has an unfixed
timing side channel (RUSTSEC-2023-0071). Certificate chains signed with RSA
are refused.

## API

```rust
// once, before building any TLS configuration:
rustls_rustcrypto::set_fill_random(my_fill_function);

// then, as with any provider:
let provider = Arc::new(rustls_rustcrypto::provider());
```

`set_fill_random` takes `fn(&mut [u8]) -> Result<(), rustls::Error>`. Every
secret byte the provider needs flows through that one function — there is no
`getrandom` dependency and no OS assumption, so a freestanding target (a
kernel, a hypervisor guest) wires in its own entropy source. Every call
before `set_fill_random` fails loudly with `Error::FailedToGetRandomBytes`.

Time comes from the application too: pass a `TimeProvider` to
`rustls::ClientConfig::builder_with_details` /
`rustls::ServerConfig::builder_with_details`, as rustls 0.24 requires of
`no_std` users.

## Origin and maintenance

Derived from [`rustls-pure`] 0.15.4, ported to rustls 0.24 and `no_std`:

- 0.24 provider API: `RecordEncrypter`/`RecordDecrypter` record layer
  (full wire-format records, sequence-derived nonces), `StartedKeyExchange`
  with the hybrid path behind `HybridKeyExchange`, the
  `crypto::kx`/`crypto::signer`/`crypto::enums` module layout, consuming
  `Signer::sign`
- `CryptoProvider` construction for the 0.24 shape: split TLS 1.2/1.3 suite
  lists (none for 1.2), a no-op ticketer factory (servers built from this
  provider send no session tickets)
- `WebPkiSupportedAlgorithms` via its const constructor

Upstream's Kani proofs of the input-validation code are kept in this crate's
`#[cfg(kani)]` `verification` module (`cargo kani -p rustls-rustcrypto`).
Upstream's Wycheproof test suite lives in upstream's `tests.rs` and is not
carried over here; the port is instead exercised by its consumers (DaoOS
cross-checked against OpenSSL on the host).

[`rustls`]: https://docs.rs/rustls
[RustCrypto]: https://github.com/RustCrypto
[`rustls-pure`]: https://crates.io/crates/rustls-pure
