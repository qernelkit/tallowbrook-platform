// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @title Courier passkeys
/// @notice Couriers register the passkey on their phone once; later, depot handovers are
/// approved with a WebAuthn assertion from that passkey instead of a wallet signature.
contract CourierPasskeys {
    struct RegisteredKey {
        bytes32 qx;
        bytes32 qy;
        uint64 registeredAt;
    }

    mapping(address => RegisteredKey) public passkeys;

    event PasskeyRegistered(address indexed courier, bytes32 qx, bytes32 qy);
    event PasskeyRemoved(address indexed courier);

    error NoPasskey(address courier);
    error InvalidKey();

    /// @notice Registers (or replaces) the caller's passkey public coordinates.
    function register(bytes32 qx, bytes32 qy) external {
        if (qx == bytes32(0) || qy == bytes32(0)) revert InvalidKey();
        passkeys[msg.sender] = RegisteredKey(qx, qy, uint64(block.timestamp));
        emit PasskeyRegistered(msg.sender, qx, qy);
    }

    /// @notice Removes the caller's passkey.
    function remove() external {
        delete passkeys[msg.sender];
        emit PasskeyRemoved(msg.sender);
    }

    /// @notice Checks a WebAuthn assertion made with the courier's registered passkey.
    /// @param authenticatorData as returned by the authenticator
    /// @param clientDataJSON as returned by the browser; the relayer checks its challenge
    function verifyAssertion(
        address courier,
        bytes calldata authenticatorData,
        bytes calldata clientDataJSON,
        bytes32 r,
        bytes32 s
    ) public view returns (bool) {
        RegisteredKey memory key = passkeys[courier];
        if (key.registeredAt == 0) revert NoPasskey(courier);
        bytes32 qx = key.qx;
        bytes32 qy = key.qy;
        bytes32 message = sha256(abi.encodePacked(authenticatorData, sha256(clientDataJSON)));
        return P256.verify(message, r, s, qx, qy);
    }
}
