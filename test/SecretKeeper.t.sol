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

    event SecretRevealed(
        bytes32 indexed agreementId,
        address indexed revealer,
        string secret
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

    function test_RevertsIfRevealBlockNotGreaterThanCreateBlock() public {
        // setup parties
        uint256 party1PrivateKey = 1;
        address party1 = vm.addr(party1PrivateKey);
        uint256 party2PrivateKey = 2;
        address party2 = vm.addr(party2PrivateKey);

        // create the secret
        string memory secret = "mysecret";
        bytes32 secretHash = keccak256(abi.encodePacked(secret));

        uint256 createdBlockNumber = block.number;
        // get signatures
        (bytes memory party1Signature, bytes memory party2Signature) = createSignatures(
            party1PrivateKey,
            party2PrivateKey,
            party1,
            party2,
            secretHash
        );

        // make agreement
        vm.prank(party1);
        bytes32 agreementId = secretKeeper.createAgreement(
            party2,
            secretHash,
            party1Signature,
            party2Signature
        );

        uint256 revealedBlockNumber = block.number;

        // revert when revealing in the same block
        vm.prank(party1);
        vm.expectRevert("Must reveal in a later block");
        secretKeeper.revealSecret(agreementId, secret);

        // the block numbers are equal
        assertEq(createdBlockNumber, revealedBlockNumber, "Block numbers are not equal");
    }

    function test_SuccessfulRevealInLaterBlock() public {
        // setup parties
        uint256 party1PrivateKey = 1;
        address party1 = vm.addr(party1PrivateKey);
        uint256 party2PrivateKey = 2;
        address party2 = vm.addr(party2PrivateKey);

        // create secret
        string memory secret = "mysecret";
        bytes32 secretHash = keccak256(abi.encodePacked(secret));

        uint256 createdBlockNumber = block.number;
        // get signatures
        (bytes memory party1Signature, bytes memory party2Signature) = createSignatures(
            party1PrivateKey,
            party2PrivateKey,
            party1,
            party2,
            secretHash
        );

        // make agreement
        vm.prank(party1);
        bytes32 agreementId = secretKeeper.createAgreement(
            party2,
            secretHash,
            party1Signature,
            party2Signature
        );

        // advance to next block
        vm.roll(block.number + 1);

        uint256 revealedBlockNumber = block.number;

        // reveal should succeed
        vm.prank(party1);
        secretKeeper.revealSecret(agreementId, secret);

        // confirm reveal block number is greater
        assertGt(revealedBlockNumber, createdBlockNumber, "Reveal block should be greater than create block");
    }

    function test_AgreementDeletedAfterReveal() public {
        // setup parties
        uint256 party1PrivateKey = 1;
        address party1 = vm.addr(party1PrivateKey);
        uint256 party2PrivateKey = 2;
        address party2 = vm.addr(party2PrivateKey);

        // create secret
        string memory secret = "mysecret";
        bytes32 secretHash = keccak256(abi.encodePacked(secret));

        // get signatures
        (bytes memory party1Signature, bytes memory party2Signature) = createSignatures(
            party1PrivateKey,
            party2PrivateKey,
            party1,
            party2,
            secretHash
        );

        // make the agreement
        vm.prank(party1);
        bytes32 agreementId = secretKeeper.createAgreement(
            party2,
            secretHash,
            party1Signature,
            party2Signature
        );

        // advance to next block
        vm.roll(block.number + 1);

        // reveal secret
        vm.prank(party1);
        secretKeeper.revealSecret(agreementId, secret);

        // check storage after reveal
        (
            address storedParty1,
            address storedParty2,
            bytes32 storedSecretHash,
            uint256 storedBlockNumber
        ) = secretKeeper.agreements(agreementId);

        // verify all values are zero
        assertEq(storedParty1, address(0), "Party1 should be zero address");
        assertEq(storedParty2, address(0), "Party2 should be zero address");
        assertEq(storedSecretHash, bytes32(0), "Secret hash should be empty");
        assertEq(storedBlockNumber, 0, "Block number should be zero");
    }

    function test_EmitSecretRevealedEvent() public {
        // setup parties
        uint256 party1PrivateKey = 1;
        address party1 = vm.addr(party1PrivateKey);
        uint256 party2PrivateKey = 2;
        address party2 = vm.addr(party2PrivateKey);

        // create secret
        string memory secret = "mysecret";
        bytes32 secretHash = keccak256(abi.encodePacked(secret));

        // signatures creation
        (bytes memory party1Signature, bytes memory party2Signature) = createSignatures(
            party1PrivateKey,
            party2PrivateKey,
            party2,
            party1,
            secretHash
        );

        // create agreement
        vm.prank(party2);
        bytes32 agreementId = secretKeeper.createAgreement(
            party1,
            secretHash,
            party2Signature,
            party1Signature
        );

        // advance block for reveal
        vm.roll(block.number + 1);

        // expect SecretRevealed event with correct arguments
        vm.prank(party1);
        vm.expectEmit(true, true, false, true);
        emit SecretRevealed(agreementId, party1, secret);

        // reveal the secret
        secretKeeper.revealSecret(agreementId, secret);
    }
}
