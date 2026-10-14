//! The treasury operators' room. The ledger creates the room and is its first member; operator
//! consoles publish key packages and the ledger adds them. Approval requests for held batches are
//! posted to the room so that the approvers see them in their consoles.

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::Serialize;

use super::signer::ProviderSigner;
use super::{OPERATOR_ROOM_SUITE, RoomError, group_err};
use crate::approvals::ApprovalStep;

/// Posted to the room when a batch is held for approval or changes step.
#[derive(Debug, Serialize)]
pub struct ApprovalNotice<'a> {
    pub batch_id: u64,
    pub step: ApprovalStep,
    pub largest_line_minor: i64,
    pub currency: &'a str,
    pub summary: &'a str,
}

/// Messages the ledger sends to the room, already encoded for the transport.
#[derive(Debug)]
pub struct Outgoing {
    pub commit: Option<Vec<u8>>,
    pub welcome: Option<Vec<u8>>,
    pub application: Option<Vec<u8>>,
}

pub struct OperatorRoom {
    provider: OpenMlsRustCrypto,
    signer: ProviderSigner,
    group: MlsGroup,
}

fn credential_for(identity: &str, signer: &ProviderSigner) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(identity.as_bytes().to_vec()).into(),
        signature_key: signer.public().into(),
    }
}

impl OperatorRoom {
    /// Creates the room with the ledger as its only member.
    pub fn create(identity: &str) -> Result<Self, RoomError> {
        let provider = OpenMlsRustCrypto::default();
        let signer =
            ProviderSigner::generate(provider.crypto(), OPERATOR_ROOM_SUITE.signature_algorithm())?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(OPERATOR_ROOM_SUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new(
            &provider,
            &signer,
            &config,
            credential_for(identity, &signer),
        )
        .map_err(group_err)?;
        log::info!("operator room created by {identity}");
        Ok(Self {
            provider,
            signer,
            group,
        })
    }

    /// The key package an operator console publishes before it can be added to the room.
    pub fn console_key_package(
        provider: &OpenMlsRustCrypto,
        signer: &ProviderSigner,
        identity: &str,
    ) -> Result<KeyPackage, RoomError> {
        let credential = credential_for(identity, signer);
        let bundle = KeyPackage::builder()
            .build(OPERATOR_ROOM_SUITE, provider, signer, credential)
            .map_err(group_err)?;
        Ok(bundle.key_package().clone())
    }

    /// Adds an operator console. The commit goes to existing members, the welcome to the console.
    pub fn add_operator(&mut self, key_package: KeyPackage) -> Result<Outgoing, RoomError> {
        let (commit, welcome, _group_info) = self
            .group
            .add_members(&self.provider, &self.signer, &[key_package])
            .map_err(group_err)?;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(group_err)?;
        Ok(Outgoing {
            commit: Some(commit.to_bytes().map_err(group_err)?),
            welcome: Some(welcome.to_bytes().map_err(group_err)?),
            application: None,
        })
    }

    /// Posts an approval notice for a held batch.
    pub fn post_notice(&mut self, notice: &ApprovalNotice<'_>) -> Result<Outgoing, RoomError> {
        let body = serde_json::to_vec(notice)?;
        let message = self
            .group
            .create_message(&self.provider, &self.signer, &body)
            .map_err(group_err)?;
        Ok(Outgoing {
            commit: None,
            welcome: None,
            application: Some(message.to_bytes().map_err(group_err)?),
        })
    }

    pub fn members(&self) -> usize {
        self.group.members().count()
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }
}
