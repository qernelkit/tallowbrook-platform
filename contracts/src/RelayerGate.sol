// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title Relayer gate
/// @notice Order authorisations from the relayer that predates the escrow contract.
/// Partners still integrated with it send the relayer's v, r, s over an order hash.
contract RelayerGate {
    address public immutable relayer;
    mapping(bytes32 => bool) public used;

    event Authorised(bytes32 indexed orderHash, address indexed caller);

    error NotRelayer();
    error AlreadyUsed(bytes32 orderHash);

    constructor(address relayer_) {
        relayer = relayer_;
    }

    /// @notice Marks an order as authorised if the relayer signed its hash.
    /// @param orderHash computed off-chain by the partner's order system
    function authorise(bytes32 orderHash, uint8 v, bytes32 r, bytes32 s) external {
        if (used[orderHash]) revert AlreadyUsed(orderHash);
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", orderHash));
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0) || signer != relayer) revert NotRelayer();
        used[orderHash] = true;
        emit Authorised(orderHash, msg.sender);
    }
}
