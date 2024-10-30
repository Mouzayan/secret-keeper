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

    event SecretStored(
        bytes32 indexed agreementId,
        address indexed party1,
        address indexed party2,
        uint256 storedBlock
    );

    // helper for signature creation
    function createSignatures(
        uint256 party1PrivateKey,
        uint256 party2PrivateKey,
        address party1,
        address party2,
        bytes32 secretHash
    ) internal view returns (bytes memory party1Signature, bytes memory party2Signature) {
        bytes32 digest = getDigest(party1, party2, secretHash);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(party1PrivateKey, digest);
        party1Signature = abi.encodePacked(r1, s1, v1);

        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(party2PrivateKey, digest);
        party2Signature = abi.encodePacked(r2, s2, v2);
    }

    // helper for digest creation
    function getDigest(
        address party1,
        address party2,
        bytes32 secretHash
    ) internal view returns (bytes32) {
        // create hash of agreement type
        bytes32 _AGREEMENT_TYPEHASH = keccak256(
            "SecretAgreement(address party1,address party2,bytes32 secretHash)"
        );
        // hash the actual data of the agreement
        bytes32 structHash = keccak256(
            abi.encode(_AGREEMENT_TYPEHASH, party1, party2, secretHash)
        );

        // create the EIP-712 compliant digest
        // with domain separator info, chain ID, contract address
        string memory name = "SecretKeeper";
        string memory version = "1";
        bytes32 TYPE_HASH = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

        bytes32 domainSeparator = keccak256(
            abi.encode(
                TYPE_HASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(secretKeeper)
            )
        );

        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    // In revealSecret:
    // √ confirm that the functoin reverts if the agreement does not exist
    // √ confirm that if msg.sender is not either party1 or party2, the function reverts
    // √ confirm that the secret is valid
    // confirm the call block number is greater than the created block
    // confirm the agreement is deleted from storage after the secret is revealed
    // confirm the event is emitted with the correct arguments

    function test_RevertIfParty2IsZeroAddress() public {
        address party2 = address(0);
        bytes32 secretHash = keccak256(abi.encodePacked("secret"));
        bytes memory party1Signature = new bytes(65);
        bytes memory party2Signature = new bytes(65);

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

    function test_RevertIfInvalidSignature() public {
        address party2 = address(0x1234);
        bytes32 secretHash = keccak256(abi.encodePacked("secret"));
        bytes memory dummySignature = new bytes(65);

        vm.expectRevert(abi.encodeWithSignature("ECDSAInvalidSignature()"));
        secretKeeper.createAgreement(party2, secretHash, dummySignature, dummySignature);
    }

    function test_EmitSecretStoredEvent() public {
        // setup parties
        uint256 party1PrivateKey = 1;
        address party1 = vm.addr(party1PrivateKey);
        uint256 party2PrivateKey = 2;
        address party2 = vm.addr(party2PrivateKey);

        // hash the secret
        bytes32 secretHash = keccak256(abi.encodePacked("secret"));

        // signatures creation
        (bytes memory party1Signature, bytes memory party2Signature) = createSignatures(
            party1PrivateKey,
            party2PrivateKey,
            party1,
            party2,
            secretHash
        );

        // create agreementId
        bytes32 agreementId = keccak256(abi.encodePacked(party1, party2, block.timestamp));

        // msg.sender is party1
        vm.prank(party1);
        vm.expectEmit(true, true, true, true);
        emit SecretStored(agreementId, party1, party2, block.number);

        secretKeeper.createAgreement(party2, secretHash, party1Signature, party2Signature);
    }

    function test_AgreementIsStored() public {
        // setup parties
        uint256 party1PrivateKey = 1;
        address party1 = vm.addr(party1PrivateKey);
        uint256 party2PrivateKey = 2;
        address party2 = vm.addr(party2PrivateKey);

        // secret hash creation
        bytes32 secretHash = keccak256(abi.encodePacked("secret"));

        // signatures creation
        (bytes memory party1Signature, bytes memory party2Signature) = createSignatures(
            party1PrivateKey,
            party2PrivateKey,
            party1,
            party2,
            secretHash
        );

        // msg.sender is party1
        vm.prank(party1);
        // create the agreement
        bytes32 agreementId = secretKeeper.createAgreement(
            party2,
            secretHash,
            party1Signature,
            party2Signature
        );

        // retrieve stored agreement values
        (
            address storedParty1,
            address storedParty2,
            bytes32 storedSecretHash,
            uint256 storedBlockNumber
        ) = secretKeeper.agreements(agreementId);

        assertEq(storedParty1, party1, "Party1 not stored correctly");
        assertEq(storedParty2, party2, "Party2 not stored correctly");
        assertEq(storedSecretHash, secretHash, "Secret hash not stored correctly");
        assertEq(storedBlockNumber, block.number, "Block number not stored correctly");
    }

    function test_RevertIfAgreementDoesNotExist() public {
        bytes32 agreementId = keccak256(abi.encodePacked("agreementId"));
        vm.expectRevert("Agreement does not exist");
        secretKeeper.revealSecret(agreementId, "secret");
    }

    function test_RevertIfCallerIsNotAuthorized() public {
        // setup parties
        uint256 party1PrivateKey = 1;
        address party1 = vm.addr(party1PrivateKey);
        uint256 party2PrivateKey = 2;
        address party2 = vm.addr(party2PrivateKey);
        uint256 callerPrivateKey = 3;
        address caller = vm.addr(callerPrivateKey);

        // create the secret
        string memory secret = "mysecret";
        bytes32 secretHash = keccak256(abi.encodePacked(secret));

        // get the signatures
        (bytes memory party1Signature, bytes memory party2Signature) = createSignatures(
            party1PrivateKey,
            party2PrivateKey,
            party1,
            party2,
            secretHash
        );

        // create the agreement
        vm.prank(party1);
        bytes32 agreementId = secretKeeper.createAgreement(
            party2,
            secretHash,
            party1Signature,
            party2Signature
        );

        // unauthorized caller tries to reveal secret
        vm.prank(caller);
        vm.expectRevert("Not authorized");
        secretKeeper.revealSecret(agreementId, secret);
    }

    function test_RevertIfTheSecretIsInvalid() public {
        // setup parties
        uint256 party1PrivateKey = 1;
        address party1 = vm.addr(party1PrivateKey);
        uint256 party2PrivateKey = 2;
        address party2 = vm.addr(party2PrivateKey);

        // create secret
        string memory secret = "secret";
        bytes32 secretHash = keccak256(abi.encodePacked(secret));

        // create signatures
        (bytes memory party1Signature, bytes memory party2Signature) = createSignatures(
            party1PrivateKey,
            party2PrivateKey,
            party1,
            party2,
            secretHash
        );

        // create agreement
        vm.prank(party1);
        bytes32 agreementId = secretKeeper.createAgreement(
            party2,
            secretHash,
            party1Signature,
            party2Signature
        );

        // reverts when revealing invalid secret
        string memory invalidSecret = "invalidSecret";
        vm.prank(party1);
        vm.expectRevert("Invalid secret");
        secretKeeper.revealSecret(agreementId, invalidSecret);
    }
}
