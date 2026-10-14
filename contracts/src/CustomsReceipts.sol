// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {RSA} from "@openzeppelin/contracts/utils/cryptography/RSA.sol";

/// @title Customs clearance receipts
/// @notice Records that the customs authority cleared a shipment. The authority's
/// signing key is fixed at deployment; a new key means a new deployment.
contract CustomsReceipts {
    bytes private _authorityExponent;
    bytes private _authorityModulus;

    mapping(uint256 => uint64) public clearedAt;

    event Cleared(uint256 indexed shipmentId, uint64 clearedAt);

    error ReceiptRejected(uint256 shipmentId);
    error AlreadyCleared(uint256 shipmentId);

    constructor(bytes memory authorityExponent, bytes memory authorityModulus) {
        _authorityExponent = authorityExponent;
        _authorityModulus = authorityModulus;
    }

    /// @notice Stores a clearance for a shipment if the receipt carries the authority's signature.
    /// @param receipt the receipt bytes exactly as issued
    /// @param signature the authority's signature over `receipt`
    function recordClearance(uint256 shipmentId, bytes calldata receipt, bytes calldata signature) external {
        if (clearedAt[shipmentId] != 0) revert AlreadyCleared(shipmentId);
        if (!_authorityIssued(receipt, signature)) revert ReceiptRejected(shipmentId);
        clearedAt[shipmentId] = uint64(block.timestamp);
        emit Cleared(shipmentId, uint64(block.timestamp));
    }

    function _authorityIssued(bytes calldata receipt, bytes calldata signature) private view returns (bool) {
        return RSA.pkcs1Sha256(receipt, signature, _authorityExponent, _authorityModulus);
    }
}
