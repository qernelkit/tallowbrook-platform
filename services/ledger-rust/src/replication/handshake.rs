//! Session setup for the branch sync link.
//!
//! The branch opens a session with a hello carrying a fresh session id and an ephemeral public
//! value. The head office answers with its own, and both sides derive one key per direction.
//! Messages on the session are numbered; the sequence number is the per-message nonce.

use ring::rand::SystemRandom;
use ring::{aead, agreement, hkdf};

const HANDSHAKE_KX: &agreement::Algorithm = &agreement::X25519;

const BRANCH_TO_HEAD: &[u8] = b"tallowbrook ledger sync branch to head";
const HEAD_TO_BRANCH: &[u8] = b"tallowbrook ledger sync head to branch";

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("session setup failed")]
    Setup,
    #[error("message {0} failed authentication")]
    Rejected(u64),
    #[error("message {got} arrived out of order, expected {expected}")]
    OutOfOrder { got: u64, expected: u64 },
}

impl From<ring::error::Unspecified> for SyncError {
    fn from(_: ring::error::Unspecified) -> Self {
        SyncError::Setup
    }
}

/// First message from either side.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Hello {
    pub session_id: [u8; 16],
    pub branch: String,
    pub public_key: Vec<u8>,
}

/// An established session, from the head office's point of view.
pub struct SyncSession {
    pub session_id: [u8; 16],
    pub branch: String,
    inbound: aead::LessSafeKey,
    outbound: aead::LessSafeKey,
    next_in: u64,
    next_out: u64,
}

pub struct SyncResponder {
    rng: SystemRandom,
}

impl Default for SyncResponder {
    fn default() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }
}

impl SyncResponder {
    /// Answers a branch hello. Returns the reply to send back and the established session.
    pub fn respond(&self, hello: &Hello) -> Result<(Hello, SyncSession), SyncError> {
        let ours = agreement::EphemeralPrivateKey::generate(HANDSHAKE_KX, &self.rng)?;
        let our_value = ours.compute_public_key()?;
        let peer = agreement::UnparsedPublicKey::new(HANDSHAKE_KX, &hello.public_key);
        let transcript = [&hello.session_id[..], &hello.public_key, our_value.as_ref()].concat();
        let (inbound, outbound) = agreement::agree_ephemeral(ours, &peer, |shared| {
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA384, &transcript);
            let prk = salt.extract(shared);
            Ok::<_, SyncError>((
                channel_key(&prk, BRANCH_TO_HEAD)?,
                channel_key(&prk, HEAD_TO_BRANCH)?,
            ))
        })??;
        let reply = Hello {
            session_id: hello.session_id,
            branch: hello.branch.clone(),
            public_key: our_value.as_ref().to_vec(),
        };
        log::info!("sync session opened with branch {}", hello.branch);
        let session = SyncSession {
            session_id: hello.session_id,
            branch: hello.branch.clone(),
            inbound,
            outbound,
            next_in: 0,
            next_out: 0,
        };
        Ok((reply, session))
    }
}

fn channel_key(prk: &hkdf::Prk, label: &[u8]) -> Result<aead::LessSafeKey, SyncError> {
    let info = [label];
    let okm = prk.expand(&info, &aead::CHACHA20_POLY1305)?;
    Ok(aead::LessSafeKey::new(aead::UnboundKey::from(okm)))
}

fn sequence_iv(seq: u64) -> aead::Nonce {
    let mut iv = [0u8; aead::NONCE_LEN];
    iv[4..].copy_from_slice(&seq.to_be_bytes());
    aead::Nonce::assume_unique_for_key(iv)
}

impl SyncSession {
    /// Seals the next outbound message (a checkpoint or an acknowledgement).
    pub fn seal(&mut self, payload: &[u8]) -> Result<(u64, Vec<u8>), SyncError> {
        let seq = self.next_out;
        let mut buf = payload.to_vec();
        self.outbound.seal_in_place_append_tag(
            sequence_iv(seq),
            aead::Aad::from(self.session_id),
            &mut buf,
        )?;
        self.next_out += 1;
        Ok((seq, buf))
    }

    /// Opens the next inbound message; messages must arrive in order.
    pub fn open(&mut self, seq: u64, sealed: &[u8]) -> Result<Vec<u8>, SyncError> {
        if seq != self.next_in {
            return Err(SyncError::OutOfOrder {
                got: seq,
                expected: self.next_in,
            });
        }
        let mut buf = sealed.to_vec();
        let plain = self
            .inbound
            .open_in_place(sequence_iv(seq), aead::Aad::from(self.session_id), &mut buf)
            .map_err(|_| SyncError::Rejected(seq))?;
        self.next_in += 1;
        Ok(plain.to_vec())
    }
}
