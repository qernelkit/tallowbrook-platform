//! The settings file shipped with the service must load: every key present, every value valid.

use std::path::Path;

use ledger::model::AccountId;
use ledger::settings::Settings;

fn shipped() -> Settings {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/ledger.toml");
    Settings::load(&path).expect("config/ledger.toml loads")
}

#[test]
fn shipped_settings_load() {
    let settings = shipped();
    assert_eq!(settings.ledger.instance, "ledger-eu-1");
    assert_eq!(settings.bankfeed.banks.len(), 3);
    assert!(settings.bank("meridian-trust").is_some());
    assert!(settings.bank("unknown-bank").is_none());
}

#[test]
fn bank_settlement_accounts_are_ledger_accounts() {
    for bank in &shipped().bankfeed.banks {
        assert!(
            AccountId::new(bank.settlement_account).is_some(),
            "bank {} settles to {}",
            bank.code,
            bank.settlement_account
        );
    }
}

#[test]
fn listeners_do_not_share_a_port() {
    let settings = shipped();
    assert_ne!(settings.tls.listen.port(), settings.tls.admin_listen.port());
}
