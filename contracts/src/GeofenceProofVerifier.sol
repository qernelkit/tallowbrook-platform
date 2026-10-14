// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @title Geofence proof verifier
/// @notice Checks the zero-knowledge proofs couriers' phones produce to show a drop-off
/// happened inside a customer's geofence without revealing the coordinates. The
/// verifying key comes from the circuit's setup and is passed in at deployment.
contract GeofenceProofVerifier {
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    uint256 private constant FIELD_MODULUS = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 private constant SCALAR_MODULUS = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    G1Point private _alpha;
    G2Point private _beta;
    G2Point private _gamma;
    G2Point private _delta;
    G1Point[] private _ic;

    error PrecompileFailed();
    error BadInputCount(uint256 expected, uint256 got);
    error InputOutOfRange(uint256 index);

    constructor(G1Point memory alpha, G2Point memory beta, G2Point memory gamma, G2Point memory delta, G1Point[] memory ic) {
        _alpha = alpha;
        _beta = beta;
        _gamma = gamma;
        _delta = delta;
        for (uint256 i = 0; i < ic.length; i++) {
            _ic.push(ic[i]);
        }
    }

    /// @notice Returns true when the proof is valid for the given public inputs.
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        if (publicInputs.length + 1 != _ic.length) revert BadInputCount(_ic.length - 1, publicInputs.length);
        G1Point memory vkX = _ic[0];
        for (uint256 i = 0; i < publicInputs.length; i++) {
            if (publicInputs[i] >= SCALAR_MODULUS) revert InputOutOfRange(i);
            vkX = _add(vkX, _mul(_ic[i + 1], publicInputs[i]));
        }
        G1Point[4] memory g1 = [_negate(G1Point(a[0], a[1])), _alpha, vkX, G1Point(c[0], c[1])];
        G2Point[4] memory g2 = [G2Point(b[0], b[1]), _beta, _gamma, _delta];
        return _productIsOne(g1, g2);
    }

    function _negate(G1Point memory p) private pure returns (G1Point memory) {
        if (p.x == 0 && p.y == 0) return p;
        return G1Point(p.x, FIELD_MODULUS - (p.y % FIELD_MODULUS));
    }

    function _add(G1Point memory p, G1Point memory q) private view returns (G1Point memory r) {
        (bool ok, bytes memory out) = address(0x06).staticcall(abi.encode(p.x, p.y, q.x, q.y));
        if (!ok) revert PrecompileFailed();
        (r.x, r.y) = abi.decode(out, (uint256, uint256));
    }

    function _mul(G1Point memory p, uint256 scalar) private view returns (G1Point memory r) {
        (bool ok, bytes memory out) = address(0x07).staticcall(abi.encode(p.x, p.y, scalar));
        if (!ok) revert PrecompileFailed();
        (r.x, r.y) = abi.decode(out, (uint256, uint256));
    }

    function _productIsOne(G1Point[4] memory g1, G2Point[4] memory g2) private view returns (bool) {
        uint256[24] memory words;
        for (uint256 i = 0; i < 4; i++) {
            words[i * 6] = g1[i].x;
            words[i * 6 + 1] = g1[i].y;
            words[i * 6 + 2] = g2[i].x[0];
            words[i * 6 + 3] = g2[i].x[1];
            words[i * 6 + 4] = g2[i].y[0];
            words[i * 6 + 5] = g2[i].y[1];
        }
        bytes memory input = abi.encodePacked(words);
        (bool ok, bytes memory out) = address(0x08).staticcall(input);
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }
}
