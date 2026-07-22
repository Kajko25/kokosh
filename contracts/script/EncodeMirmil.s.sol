// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {B20FactoryLib} from "../lib/base-std/src/lib/B20FactoryLib.sol";
import {IB20} from "../lib/base-std/src/interfaces/IB20.sol";
import {IB20Factory} from "../lib/base-std/src/interfaces/IB20Factory.sol";

/// @notice Pure local encoder — no chain interaction, just prints the bytes needed
///         for the real `cast send` call to B20Factory.createB20.
contract EncodeMirmil is Script {
    address constant ADMIN = 0x2984Bb4953cfCE2cEc957388BE686D6c38779234;

    function run() external view {
        bytes memory params = B20FactoryLib.encodeAssetCreateParams("Mirmil", "MIR", ADMIN, 18);

        bytes[] memory roleGrants = B20FactoryLib.buildRoleGrants(
            B20FactoryLib.B20AssetRoleHolders({
                minter: ADMIN,
                burner: ADMIN,
                burnBlocker: ADMIN,
                pauser: ADMIN,
                unpauser: ADMIN,
                metadataAdmin: ADMIN,
                operator: ADMIN
            })
        );

        bytes[] memory mintCall = new bytes[](1);
        mintCall[0] = abi.encodeCall(IB20.mint, (ADMIN, 100_000 * 10 ** 18));

        bytes[] memory initCalls = B20FactoryLib.concat(roleGrants, mintCall);

        console.log("--- params ---");
        console.logBytes(params);

        console.log("--- initCalls count ---");
        console.logUint(initCalls.length);
        for (uint256 i = 0; i < initCalls.length; i++) {
            console.log("--- initCalls[%s] ---", i);
            console.logBytes(initCalls[i]);
        }

        bytes32 salt = keccak256("kokosh-mirmil-v1");
        console.log("--- salt ---");
        console.logBytes32(salt);
    }
}
