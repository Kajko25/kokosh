// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Waymarks} from "../src/Waymarks.sol";

contract WaymarksTest is Test {
    Waymarks waymarks;
    address owner = address(0xA11CE);
    address stranger = address(0xB0B);

    function setUp() public {
        waymarks = new Waymarks(owner);
    }

    function test_OwnerCanMint() public {
        vm.prank(owner);
        uint256 tokenId = waymarks.mint(owner, "Genesis");
        assertEq(tokenId, 1);
        assertEq(waymarks.ownerOf(1), owner);
        assertEq(waymarks.stageName(1), "Genesis");
    }

    function test_StrangerCannotMint() public {
        vm.prank(stranger);
        vm.expectRevert(Waymarks.NotOwner.selector);
        waymarks.mint(stranger, "Fake");
    }

    function test_TokenIdsIncrement() public {
        vm.startPrank(owner);
        uint256 id1 = waymarks.mint(owner, "First");
        uint256 id2 = waymarks.mint(owner, "Second");
        vm.stopPrank();
        assertEq(id1, 1);
        assertEq(id2, 2);
    }

    function test_TokenURIContainsDataPrefix() public {
        vm.prank(owner);
        waymarks.mint(owner, "Genesis");
        string memory uri = waymarks.tokenURI(1);
        assertTrue(bytes(uri).length > 0);
        assertEq(_slice(uri, 0, 29), "data:application/json;base64,");
    }

    function test_RevertOnNonexistentToken() public {
        vm.expectRevert();
        waymarks.tokenURI(999);
    }

    function _slice(string memory str, uint256 start, uint256 len) internal pure returns (string memory) {
        bytes memory b = bytes(str);
        bytes memory out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = b[start + i];
        }
        return string(out);
    }
}
