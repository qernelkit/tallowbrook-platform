// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title Freight escrow events and errors
/// @notice Shared with the gateway's relayer, which decodes them from receipts.
interface IFreightEscrow {
    enum Status {
        None,
        Funded,
        Delivered,
        Released,
        Refunded
    }

    event Deposited(uint256 indexed shipmentId, address indexed shipper, uint256 amount);
    event DeliveryConfirmed(uint256 indexed shipmentId, address indexed courier, uint64 deliveredAt);
    event Released(uint256 indexed shipmentId, address indexed courier, uint256 amount);
    event Refunded(uint256 indexed shipmentId, address indexed shipper, uint256 amount);

    error AlreadyFunded(uint256 shipmentId);
    error WrongStatus(uint256 shipmentId, Status status);
    error PinMismatch(uint256 shipmentId);
    error NotCourier(uint256 shipmentId);
    error NotShipper(uint256 shipmentId);
    error DeadlineNotReached(uint256 shipmentId, uint64 deadline);
    error TransferFailed(address to, uint256 amount);
    error ZeroDeposit();

    /// @notice Current status of a shipment's escrow.
    function shipmentStatus(uint256 shipmentId) external view returns (Status);
}
