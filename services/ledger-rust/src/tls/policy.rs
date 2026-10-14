//! Cipher-suite policy for the ledger's internal links (branch sync, operator consoles, DR
//! replica). Public-facing clients such as the bank feeds use the library defaults instead.

use rustls::SupportedCipherSuite;
use rustls::crypto::aws_lc_rs::cipher_suite;

/// Suites offered and accepted on internal links, in preference order.
pub static LEDGER_TLS13_SUITES: &[SupportedCipherSuite] = &[
    cipher_suite::TLS13_AES_256_GCM_SHA384,
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];

/// Names of the configured suites, for the admin status page.
pub fn suite_names() -> Vec<String> {
    LEDGER_TLS13_SUITES
        .iter()
        .map(|s| format!("{:?}", s.suite()))
        .collect()
}
