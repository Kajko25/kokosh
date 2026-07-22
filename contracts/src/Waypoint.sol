// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Waypoint
/// @notice Owner-only on-chain key/value profile registry for kajko24.base.eth.
contract Waypoint {
    address public immutable owner;

    mapping(bytes32 => string) private _entries;

    event EntrySet(bytes32 indexed keyHash, string key, string value);

    error NotOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address _owner) {
        owner = _owner;
    }

    function set(string calldata key, string calldata value) external onlyOwner {
        _entries[keccak256(bytes(key))] = value;
        emit EntrySet(keccak256(bytes(key)), key, value);
    }

    function get(string calldata key) external view returns (string memory) {
        return _entries[keccak256(bytes(key))];
    }
}
