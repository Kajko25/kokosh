// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Waypoint} from "../src/Waypoint.sol";

contract WaypointTest is Test {
    Waypoint waypoint;
    address owner = address(0xA11CE);
    address stranger = address(0xB0B);

    function setUp() public {
        waypoint = new Waypoint(owner);
    }

    function test_OwnerCanSetAndGet() public {
        vm.prank(owner);
        waypoint.set("agent", "https://kokosh.kajko24.base.eth");
        assertEq(waypoint.get("agent"), "https://kokosh.kajko24.base.eth");
    }

    function test_StrangerCannotSet() public {
        vm.prank(stranger);
        vm.expectRevert(Waypoint.NotOwner.selector);
        waypoint.set("agent", "https://evil.example");
    }

    function test_UnsetKeyReturnsEmpty() public view {
        assertEq(waypoint.get("nonexistent"), "");
    }

    function test_OwnerCanOverwrite() public {
        vm.startPrank(owner);
        waypoint.set("repo", "https://github.com/old/old");
        waypoint.set("repo", "https://github.com/new/new");
        vm.stopPrank();
        assertEq(waypoint.get("repo"), "https://github.com/new/new");
    }

    function testFuzz_SetGetRoundTrip(string memory key, string memory value) public {
        vm.assume(bytes(key).length > 0);
        vm.prank(owner);
        waypoint.set(key, value);
        assertEq(waypoint.get(key), value);
    }
}
