//! Group messaging for operators. Treasury operators coordinate approvals and incidents in an
//! MLS room the ledger creates; the ledger bot also runs an alerts room for on-call staff.

pub mod alerts_room;
pub mod operator_room;
pub mod signer;
pub mod state_store;

use std::collections::BTreeMap;

use openmls::prelude::Ciphersuite;

/// Suite of the treasury operators' room. Every console that joins must support it.
pub const OPERATOR_ROOM_SUITE: Ciphersuite =
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87;

#[derive(Debug, thiserror::Error)]
pub enum RoomError {
    #[error("cannot create the room member key: {0:?}")]
    MemberKey(openmls::prelude::CryptoError),
    #[error("room operation failed: {0}")]
    Group(String),
    #[error("cannot encode room message: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("room {0} is not registered")]
    UnknownRoom(String),
}

impl From<openmls::prelude::CryptoError> for RoomError {
    fn from(e: openmls::prelude::CryptoError) -> Self {
        RoomError::MemberKey(e)
    }
}

/// Maps any openmls error into a room error; their error types are generic over the storage.
pub(crate) fn group_err(e: impl std::fmt::Display) -> RoomError {
    RoomError::Group(e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomKind {
    Operators,
    Alerts,
}

/// Rooms this ledger instance is a member of, by configured name.
#[derive(Debug, Default)]
pub struct RoomRegistry {
    rooms: BTreeMap<String, RoomKind>,
}

impl RoomRegistry {
    pub fn register(&mut self, name: &str, kind: RoomKind) {
        self.rooms.insert(name.to_owned(), kind);
    }

    pub fn kind(&self, name: &str) -> Result<RoomKind, RoomError> {
        self.rooms
            .get(name)
            .copied()
            .ok_or_else(|| RoomError::UnknownRoom(name.to_owned()))
    }
}
