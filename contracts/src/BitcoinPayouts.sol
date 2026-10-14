// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title Carrier payouts in bitcoin
/// @notice Carriers paid in BTC register the compressed key of their payout wallet. The
/// treasury's payout service reads the key hash and pays to the matching P2WPKH address.
/// Balances are kept in satoshi, two 128-bit counters packed into one slot.
contract BitcoinPayouts {
    uint256 private constant AMOUNT_MASK = 0xffffffffffffffffffffffffffffffff;

    address public immutable treasury;
    mapping(address => bytes20) public payoutKeyHash;
    mapping(address => uint256) private _balances;

    event PayoutKeyRegistered(address indexed carrier, bytes20 keyHash);
    event Accrued(address indexed carrier, uint128 sats);
    event Paid(address indexed carrier, uint128 sats);

    error BadKey();
    error OnlyTreasury();
    error Overdrawn(uint128 pending, uint128 requested);

    constructor(address treasury_) {
        treasury = treasury_;
    }

    modifier onlyTreasury() {
        if (msg.sender != treasury) revert OnlyTreasury();
        _;
    }

    /// @notice Registers the caller's payout key (33-byte compressed public key).
    function registerPayoutKey(bytes calldata compressedPubKey) external {
        if (compressedPubKey.length != 33 || (compressedPubKey[0] != 0x02 && compressedPubKey[0] != 0x03)) revert BadKey();
        bytes32 inner = sha256(compressedPubKey);
        bytes20 pubKeyHash = ripemd160(abi.encodePacked(inner));
        payoutKeyHash[msg.sender] = pubKeyHash;
        emit PayoutKeyRegistered(msg.sender, pubKeyHash);
    }

    /// @notice Adds earned satoshi to a carrier's pending balance.
    function accrue(address carrier, uint128 sats) external onlyTreasury {
        (uint128 pending, uint128 paid) = _unpack(_balances[carrier]);
        _balances[carrier] = _pack(pending + sats, paid);
        emit Accrued(carrier, sats);
    }

    /// @notice Moves satoshi from pending to paid once the BTC transaction has confirmed.
    function markPaid(address carrier, uint128 sats) external onlyTreasury {
        (uint128 pending, uint128 paid) = _unpack(_balances[carrier]);
        if (sats > pending) revert Overdrawn(pending, sats);
        _balances[carrier] = _pack(pending - sats, paid + sats);
        emit Paid(carrier, sats);
    }

    /// @notice Pending and lifetime-paid satoshi for a carrier.
    function balances(address carrier) external view returns (uint128 pending, uint128 paid) {
        return _unpack(_balances[carrier]);
    }

    function _pack(uint128 pending, uint128 paid) private pure returns (uint256) {
        return (uint256(paid) << 128) | uint256(pending);
    }

    function _unpack(uint256 packed) private pure returns (uint128 pending, uint128 paid) {
        pending = uint128(packed & AMOUNT_MASK);
        paid = uint128(packed >> 128);
    }
}
