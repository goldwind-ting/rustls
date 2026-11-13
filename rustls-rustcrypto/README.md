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

## Tests

```sh
cargo test -p rustls-rustcrypto
```

- `src/tests.rs`: known answers and known attacks. The Wycheproof vectors in
  `wycheproof/` (from [C2SP/wycheproof]'s `testvectors_v1/`, taken from the
  `wycheproof-ng-rs` crate's `src/data/`) are run against every algorithm the
  provider offers: inputs that must be accepted and inputs that must be
  refused, such as forged signatures, points off the curve, altered tags and
  low-order keys. The rest checks the glue between rustls and the primitives,
  which the vectors cannot see: nonces, sequence numbers, the record layer's
  binding to place and content, randomness and the wiping of keys.
- `src/tests/properties.rs`: broken input in place of fuzzing — key shares of
  every group, ML-KEM ciphertexts, signatures and records, each of which must
  be refused (or, for ML-KEM ciphertexts, give an unrelated secret), never
  accepted and never a panic.
- `src/tests/constant_time.rs`: dudect-style timing tests, `#[ignore]`d
  because they need a release build and an idle machine:
  `cargo test --release -p rustls-rustcrypto --lib constant_time -- --ignored --nocapture`.
- `tests/handshake.rs`: the provider end to end — a TLS 1.3 handshake between
  two rustls connections, with application data both ways, against the test
  certificate in `tests/data/`.
- `tests/randomness_*.rs`: the randomness source is the application's: before
  one is installed, every request fails.

[C2SP/wycheproof]: https://github.com/C2SP/wycheproof

[`rustls`]: https://docs.rs/rustls
[RustCrypto]: https://github.com/RustCrypto
[`rustls-pure`]: https://crates.io/crates/rustls-pure
