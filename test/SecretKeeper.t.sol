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

    // In createAgreement:
    // √ confrim that the functoni reverts if pary2 is address zero
    // confirm that the code reverts is Party1 and Party2 are the same address
    // the function reverts if Party1 signature is not valid
    // the function reverts if Party2 signature is not valid
    // confirm that the event is emitted with the correct arguments
    // confirm that the agreement is stored in the agreements mapping

    // In revealSecret:
    // confirm that the agreement exitst
    // confirm that if msg.sender is not either party1 or party2, the function reverts
    // confirm that the secret is valid
    // confirm the call block number is greater than the created block
    // confirm the agreement is deleted from storage after the secret is revealed
    // confirm the event is emitted with the correct arguments

    function test_RevertIfParty2IsZeroAddress() public {
        address party2 = address(0);
        bytes32 secretHash = keccak256(abi.encodePacked("secret"));
        bytes memory party1Signature = ""; // Dummy signature
        bytes memory party2Signature = ""; // Dummy signature

        vm.expectRevert("Zero address");
        secretKeeper.createAgreement(party2, secretHash, party1Signature, party2Signature);
    }

    function test_RevertIfParty2IsMsgSender() public {
        address caller = address(0x1234);
        bytes32 secretHash = keccak256(abi.encodePacked("secret"));
        bytes memory dummySignature = new bytes(65);

        vm.prank(caller);
        vm.expectRevert("Party1 and Party2 cannot be the same");
        secretKeeper.createAgreement(caller, secretHash, dummySignature, dummySignature);
    }
}
