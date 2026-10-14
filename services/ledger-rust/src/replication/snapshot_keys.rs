//! Keys for disaster-recovery snapshots shipped from the primary to the DR replica.
//!
//! For every snapshot session the replica makes a fresh key pair and offers the public half; the
//! primary encapsulates to it and seals the snapshot under the resulting shared key. Nothing is
//! stored on either side once the snapshot is applied.

use ml_kem::{Decapsulate, DecapsulationKey768, Encapsulate, Kem, KeyExport, MlKem768};
use ml_kem::{SharedKey, TryKeyInit};
use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("snapshot offer {0} is malformed")]
    BadOffer(u64),
    #[error("snapshot for session {0} is malformed")]
    BadSnapshot(u64),
    #[error("snapshot for session {0} failed authentication")]
    Rejected(u64),
    #[error("random source failed")]
    Random,
}

impl From<ring::error::Unspecified> for SnapshotError {
    fn from(_: ring::error::Unspecified) -> Self {
        SnapshotError::Random
    }
}

/// Sent by the replica when it is ready for a snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotOffer {
    pub session_id: u64,
    pub encapsulation_key: Vec<u8>,
}

/// Sent by the primary: the encapsulated key, the IV and the sealed snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SealedSnapshot {
    pub session_id: u64,
    pub encapsulated: Vec<u8>,
    pub iv: [u8; aead::NONCE_LEN],
    pub sealed: Vec<u8>,
}

/// Replica side of one snapshot session.
pub struct SnapshotSession {
    pub session_id: u64,
    decap: DecapsulationKey768,
}

impl SnapshotSession {
    pub fn start(session_id: u64) -> (SnapshotSession, SnapshotOffer) {
        let (decap, encap) = MlKem768::generate_keypair();
        let offer = SnapshotOffer {
            session_id,
            encapsulation_key: encap.to_bytes().to_vec(),
        };
        (SnapshotSession { session_id, decap }, offer)
    }

    /// Opens the snapshot the primary sent for this session.
    pub fn open(&self, snapshot: &SealedSnapshot) -> Result<Vec<u8>, SnapshotError> {
        if snapshot.session_id != self.session_id {
            return Err(SnapshotError::BadSnapshot(snapshot.session_id));
        }
        let shared = self
            .decap
            .decapsulate_slice(&snapshot.encapsulated)
            .map_err(|_| SnapshotError::BadSnapshot(snapshot.session_id))?;
        let key = snapshot_key(&shared)?;
        let mut buf = snapshot.sealed.clone();
        let plain = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(snapshot.iv),
                aead::Aad::from(snapshot.session_id.to_be_bytes()),
                &mut buf,
            )
            .map_err(|_| SnapshotError::Rejected(snapshot.session_id))?;
        Ok(plain.to_vec())
    }
}

/// Primary side: seals `snapshot` for the replica that sent `offer`.
pub fn seal_for(
    offer: &SnapshotOffer,
    snapshot: &[u8],
    rng: &SystemRandom,
) -> Result<SealedSnapshot, SnapshotError> {
    let peer = ml_kem::EncapsulationKey768::new_from_slice(&offer.encapsulation_key)
        .map_err(|_| SnapshotError::BadOffer(offer.session_id))?;
    let (encapsulated, shared) = peer.encapsulate();
    let key = snapshot_key(&shared)?;
    let mut iv = [0u8; aead::NONCE_LEN];
    rng.fill(&mut iv)?;
    let mut sealed = snapshot.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(iv),
        aead::Aad::from(offer.session_id.to_be_bytes()),
        &mut sealed,
    )?;
    Ok(SealedSnapshot {
        session_id: offer.session_id,
        encapsulated: encapsulated.to_vec(),
        iv,
        sealed,
    })
}

fn snapshot_key(shared_key: &SharedKey) -> Result<aead::LessSafeKey, SnapshotError> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, shared_key.as_slice())?;
    Ok(aead::LessSafeKey::new(key))
}
