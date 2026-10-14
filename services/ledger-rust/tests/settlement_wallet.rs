//! Settlement instructions signed by the wallet must recover to the wallet's public point, which
//! is what the escrow contract checks.

use ledger::model::{Currency, Period};
use ledger::settlement::{InstructionKind, SettlementInstruction, SettlementWallet};

const FIXTURE_WALLET_KEY: &str = "854f1614f8e86f9f2ca934a0e68c64347d5a543321a428c8138452d962daea01";

fn fixture_wallet() -> SettlementWallet {
    let secret = k256::SecretKey::from_slice(&hex::decode(FIXTURE_WALLET_KEY).unwrap()).unwrap();
    SettlementWallet::from_secret(secret)
}

fn release() -> SettlementInstruction {
    SettlementInstruction {
        contract: "freight-escrow".into(),
        sequence: 41,
        kind: InstructionKind::Release,
        consignment: "TBK-2026-118842".into(),
        payee: "carrier:northbound-haulage".into(),
        amount_minor: 1_284_500,
        currency: Currency::EUR,
        period: Period::new(2026, 9).unwrap(),
    }
}

#[test]
fn signature_recovers_to_the_wallet() {
    let wallet = fixture_wallet();
    let signed = wallet.sign(&release());
    assert_eq!(signed.signature.len(), 65);
    let recovered = SettlementWallet::recover(&signed).unwrap();
    assert_eq!(recovered, wallet.public_sec1());
}

#[test]
fn changed_amount_does_not_recover_to_the_wallet() {
    let wallet = fixture_wallet();
    let mut signed = wallet.sign(&release());
    signed.instruction.amount_minor += 100;
    let recovered = SettlementWallet::recover(&signed);
    assert!(recovered.map_or(true, |point| point != wallet.public_sec1()));
}

#[test]
fn instruction_limits() {
    let mut instruction = release();
    assert!(instruction.check(50_000_000).is_ok());
    instruction.amount_minor = 0;
    assert!(instruction.check(50_000_000).is_err());
}
