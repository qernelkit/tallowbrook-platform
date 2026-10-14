//! Bank account numbers must not appear in clear in debug logs, but support needs to match a
//! log line to a customer's account when they are on the phone. Debug logs therefore carry the
//! account number masked with the pad in `LEDGER_LOG_MASK` (hex); support unmasks it with the
//! same pad from the runbook tool.

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MaskError {
    #[error("LEDGER_LOG_MASK is not set or not hex")]
    NoPad,
    #[error("masked value is not hex")]
    NotHex,
}

pub struct AccountMask {
    pad: Vec<u8>,
}

impl AccountMask {
    pub fn from_env() -> Result<Self, MaskError> {
        let hex_pad = std::env::var("LEDGER_LOG_MASK").map_err(|_| MaskError::NoPad)?;
        let pad = hex::decode(hex_pad.trim()).map_err(|_| MaskError::NoPad)?;
        if pad.is_empty() {
            return Err(MaskError::NoPad);
        }
        Ok(Self { pad })
    }

    fn apply_pad(&self, bytes: &mut [u8]) {
        let pad = &self.pad;
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte ^= pad[i % pad.len()];
        }
    }

    /// Masks an account number for a debug log line.
    pub fn mask_account(&self, account_number: &str) -> String {
        let mut bytes = account_number.as_bytes().to_vec();
        self.apply_pad(&mut bytes);
        format!("acct~{}", hex::encode(bytes))
    }

    /// Reverses `mask_account`.
    pub fn unmask(&self, masked: &str) -> Result<String, MaskError> {
        let hex_part = masked.strip_prefix("acct~").unwrap_or(masked);
        let mut bytes = hex::decode(hex_part).map_err(|_| MaskError::NotHex)?;
        self.apply_pad(&mut bytes);
        String::from_utf8(bytes).map_err(|_| MaskError::NotHex)
    }
}
