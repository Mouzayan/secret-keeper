// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {SecretKeeper} from "../src/SecretKeeper.sol";

// run with `forge test --match-contract SecretKeeperTest`
contract SecretKeeperTest is Test {
    SecretKeeper public secretKeeper;

    function setUp() public {
        secretKeeper = new SecretKeeper();
    }

    function test_RevertIfParty2IsZeroAddress() public {
        address party1 = address(this);
        address party2 = address(0);
        bytes32 secretHash = keccak256(abi.encodePacked("secret"));
        bytes memory party1Signature = ""; // Dummy signature
        bytes memory party2Signature = ""; // Dummy signature

        vm.expectRevert("Zero address");
        secretKeeper.createAgreement(party1, party2, secretHash, party1Signature, party2Signature);
    }
}
