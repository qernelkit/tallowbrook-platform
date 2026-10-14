"""Gateway attestation keys and the batch attestations depots send with their readings."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from eth_typing import BLSPubkey, BLSSignature
from py_ecc.bls import G2ProofOfPossession as bls

log = logging.getLogger(__name__)


class AttestationError(Exception):
    pass


class GatewayKeys:
    """Registered gateway keys, loaded from the depot registry at startup."""

    def __init__(self) -> None:
        self._keys: dict[str, BLSPubkey] = {}

    def register_gateway_key(self, gateway_id: str, pubkey: bytes, proof: bytes) -> None:
        if not bls.PopVerify(BLSPubkey(pubkey), BLSSignature(proof)):
            raise AttestationError(f"gateway {gateway_id} sent an invalid proof of possession")
        self._keys[gateway_id] = BLSPubkey(pubkey)
        log.info("registered attestation key for gateway %s", gateway_id)

    def verify_batch_attestation(
        self, gateway_ids: Sequence[str], batch_hash: bytes, aggregate_signature: bytes
    ) -> bool:
        unknown = [g for g in gateway_ids if g not in self._keys]
        if unknown or not gateway_ids:
            log.warning("attestation names unregistered gateways %s", unknown)
            return False
        pubkeys = [self._keys[g] for g in gateway_ids]
        return bls.FastAggregateVerify(pubkeys, batch_hash, BLSSignature(aggregate_signature))

    def __len__(self) -> int:
        return len(self._keys)
