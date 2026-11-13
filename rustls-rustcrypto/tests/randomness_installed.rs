//! Once the application installs a source of randomness, the provider takes its secret bytes
//! from there.

#[test]
fn randomness_works_once_the_application_installs_a_source() {
    rustls_rustcrypto::set_fill_random(|buf| {
        getrandom::fill(buf).map_err(|_| rustls::Error::FailedToGetRandomBytes)
    });
    let provider = rustls_rustcrypto::provider();
    let (mut a, mut b) = ([0; 32], [0; 32]);
    provider.secure_random.fill(&mut a).unwrap();
    provider.secure_random.fill(&mut b).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, [0; 32]);
}
