// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IFreightEscrow} from "./interfaces/IFreightEscrow.sol";

/// @title Freight escrow
/// @notice Holds a shipper's payment until the courier proves delivery. The courier
/// confirms with a signed Delivery and the PIN the consignee was given; the shipper
/// then signs the release. Unclaimed deposits go back to the shipper after the deadline.
contract FreightEscrow is IFreightEscrow, EIP712, ReentrancyGuard {
    bytes32 public constant SIGNATURE_VERSION = "v2";
    bytes32 private constant DELIVERY_TYPEHASH = keccak256("Delivery(uint256 shipmentId,address courier,uint64 deliveredAt)");
    event Hashed(uint256 indexed shipmentId, bytes32 commitment);

    struct Shipment {
        address shipper;
        address courier;
        uint128 amount;
        uint64 deadline;
        uint64 deliveredAt;
        bytes32 pinCommitment;
        Status status;
    }

    mapping(uint256 => Shipment) private _shipments;

    constructor() EIP712("Tallowbrook Freight Escrow", "1") {}

    /// @notice Funds the escrow for a shipment.
    /// @param shipmentId numeric part of the gateway's shipment id
    /// @param courier courier wallet that will be paid
    /// @param deadline unix time after which the shipper may take the deposit back
    function deposit(uint256 shipmentId, address courier, uint64 deadline) external payable {
        if (msg.value == 0) revert ZeroDeposit();
        Shipment storage s = _shipments[shipmentId];
        if (s.status != Status.None) revert AlreadyFunded(shipmentId);
        s.shipper = msg.sender;
        s.courier = courier;
        s.amount = uint128(msg.value);
        s.deadline = deadline;
        s.status = Status.Funded;
        emit Deposited(shipmentId, msg.sender, msg.value);
    }

    /// @notice Records the commitment to the consignee's delivery PIN, made at pickup.
    /// @param commitment computed off-chain by the gateway from the PIN, a salt and the courier
    function commitPin(uint256 shipmentId, bytes32 commitment) external {
        Shipment storage s = _shipments[shipmentId];
        if (msg.sender != s.shipper) revert NotShipper(shipmentId);
        if (s.status != Status.Funded) revert WrongStatus(shipmentId, s.status);
        s.pinCommitment = commitment;
        emit Hashed(shipmentId, commitment);
    }

    /// @notice Courier proves delivery: a Delivery signature from the courier wallet and the PIN reveal.
    function confirmDelivery(
        uint256 shipmentId,
        uint64 deliveredAt,
        bytes32 pinCode,
        bytes32 salt,
        bytes calldata courierSignature
    ) external {
        Shipment storage s = _shipments[shipmentId];
        if (s.status != Status.Funded) revert WrongStatus(shipmentId, s.status);
        if (keccak256(abi.encodePacked(pinCode, salt, s.courier)) != s.pinCommitment) revert PinMismatch(shipmentId);
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(DELIVERY_TYPEHASH, shipmentId, s.courier, deliveredAt)));
        address signer = ECDSA.recover(digest, courierSignature);
        if (signer != s.courier) revert NotCourier(shipmentId);
        s.deliveredAt = deliveredAt;
        s.status = Status.Delivered;
        emit DeliveryConfirmed(shipmentId, s.courier, deliveredAt);
    }

    /// @notice Pays the courier once the shipper has signed the release.
    /// @param shipperSignature personal_sign over the release hash, made in the shipper's wallet
    function release(uint256 shipmentId, bytes calldata shipperSignature) external nonReentrant {
        Shipment storage s = _shipments[shipmentId];
        if (s.status != Status.Delivered) revert WrongStatus(shipmentId, s.status);
        bytes32 releaseHash = keccak256(abi.encode(shipmentId, s.amount, block.chainid));
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(releaseHash);
        if (ECDSA.recover(digest, shipperSignature) != s.shipper) revert NotShipper(shipmentId);
        s.status = Status.Released;
        uint256 amount = s.amount;
        _pay(s.courier, amount);
        emit Released(shipmentId, s.courier, amount);
    }

    /// @notice Returns the deposit to the shipper after the deadline if delivery was never confirmed.
    function refund(uint256 shipmentId) external nonReentrant {
        Shipment storage s = _shipments[shipmentId];
        if (s.status != Status.Funded) revert WrongStatus(shipmentId, s.status);
        if (block.timestamp < s.deadline) revert DeadlineNotReached(shipmentId, s.deadline);
        s.status = Status.Refunded;
        uint256 amount = s.amount;
        _pay(s.shipper, amount);
        emit Refunded(shipmentId, s.shipper, amount);
    }

    /// @inheritdoc IFreightEscrow
    function shipmentStatus(uint256 shipmentId) external view returns (Status) {
        return _shipments[shipmentId].status;
    }

    function _pay(address to, uint256 amount) private {
        (bool ok, ) = payable(to).call{value: amount}("");
        if (!ok) revert TransferFailed(to, amount);
    }
}
