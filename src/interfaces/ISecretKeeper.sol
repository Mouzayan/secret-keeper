// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

interface ISecretKeeper {
    // ================================================= EVENTS ==================================================

    event SecretStored(
        bytes32 indexed agreementId, address indexed party1, address indexed party2, uint256 storedBlock
    );

    event SecretRevealed(bytes32 indexed agreementId, address indexed revealer, string secret);

    // ================================================ STRUCTS ==================================================

    struct SecretAgreement {
        address party1;
        address party2;
        bytes32 secretHash;
        uint256 createdBlock;
    }

    // =========================================== MUTATIVE FUNCTIONS ===========================================

    function createAgreement(
        address _party2,
        bytes32 _secretHash,
        bytes memory _party1Signature,
        bytes memory _party2Signature
    ) external returns (bytes32);

    function revealSecret(bytes32 _agreementId, string memory _secret) external returns (string memory);

    // ============================================ VIEW FUNCTIONS ==============================================

    function agreements(bytes32 agreementId)
        external
        view
        returns (address party1, address party2, bytes32 secretHash, uint256 createdBlock);
}
