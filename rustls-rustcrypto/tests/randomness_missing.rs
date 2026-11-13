//! The randomness source is the application's, and until it installs one, nothing works.
//!
//! This is a test of its own, in its own process: the source is installed once per process,
//! so a test that needs it to be missing cannot share a process with one that installs it.

#[test]
fn randomness_fails_before_the_application_installs_a_source() {
    let provider = rustls_rustcrypto::provider();
    let mut buf = [0; 32];
    assert!(
        provider.secure_random.fill(&mut buf).is_err(),
        "the provider handed out bytes without a source"
    );
    assert_eq!(buf, [0; 32], "the buffer was filled anyway");
}
