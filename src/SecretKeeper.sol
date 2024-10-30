// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import {ISecretKeeper} from "./interfaces/ISecretKeeper.sol";

/**
 * @title SecretKeeper
 * @author em_mutable
 * @notice The contract allows any two parties to store and later reveal a mutually
 *         agreed-upon secret on-chain. It uses off-chain signatures to verify the
 *         agreement between the parties, requiring each party to provide a digital
 *         signature to confirm their consent. The secret is stored in a hashed format
 *         to ensure privacy. At any time after the secret is stored, either party can
 *         reveal its original value on-chain. Upon revelation, the contract emits an
 *         event with the revealed value and removes the stored secret from storage.
 *         The entire process of registering the secret, including both parties’
 *         signature verification and the hashed secret storage, occurs in a single
 *         transaction, ensuring atomicity and consistent block-level timestamping.
 */
contract SecretKeeper is ISecretKeeper, EIP712 {
    // ============================================ STATE ==============================================

    /// @notice EIP712 type hash for Agreement
    bytes32 private constant _AGREEMENT_TYPEHASH =
        keccak256("SecretAgreement(address party1,address party2,bytes32 secretHash)");

    /// @notice Mapping from hash-based IDs to secret agreement structs
    mapping(bytes32 => SecretAgreement) public agreements;

    // ========================================== CONSTRUCTOR ===========================================

    /**
     * @notice Sets up the contract by initializing EIP712 domain separator.
     */
    constructor() EIP712("SecretKeeper", "1") {}

    // ======================================== MUTATIVE FUNCTIONS ====================================

    /**
     * @notice Creates a new secret agreement between two parties with signatures.
     *
     * @param _party2                     The address of the non-calling party in the agreement.
     * @param _secretHash                 The keccak256 hash of the secret being stored.
     * @param _party1Signature            The EIP712 signature of the first party (msg.sender).
     * @param _party2Signature            The EIP712 signature of the second party.
     *
     * @return                            The unique id for the created agreement.
     */
    function createAgreement(
        address _party2,
        bytes32 _secretHash,
        bytes memory _party1Signature,
        bytes memory _party2Signature
    ) external returns (bytes32) {
        require(_party2 != address(0), "Zero address");
        require(_party2 != msg.sender, "Party1 and Party2 cannot be the same");

        // create EIP-712 typed data hash
        bytes32 structHash = keccak256(abi.encode(_AGREEMENT_TYPEHASH, msg.sender, _party2, _secretHash));
        bytes32 hash = _hashTypedDataV4(structHash);

        // address recovery
        require(ECDSA.recover(hash, _party1Signature) == msg.sender, "ECDSAInvalidSignature");
        require(ECDSA.recover(hash, _party2Signature) == _party2, "ECDSAInvalidSignature");

        bytes32 agreementId = keccak256(abi.encodePacked(msg.sender, _party2, block.timestamp));

        agreements[agreementId] =
            SecretAgreement({party1: msg.sender, party2: _party2, secretHash: _secretHash, createdBlock: block.number});

        emit SecretStored(agreementId, msg.sender, _party2, block.number);
        return agreementId;
    }

    /**
     * @notice Reveals a previously stored secret and then deletes the agreement.
     *
     * @param _agreementId               The unique id of the agreement.
     * @param _secret                    The original secret being revealed.
     *
     * @return                           The revealed secret string.
     */
    function revealSecret(bytes32 _agreementId, string memory _secret) external returns (string memory) {
        SecretAgreement storage agreement = agreements[_agreementId];

        // check secret existence by verifying party1 not zero address
        require(agreement.party1 != address(0), "Agreement does not exist");
        require(msg.sender == agreement.party1 || msg.sender == agreement.party2, "Not authorized");
        require(keccak256(abi.encodePacked(_secret)) == agreement.secretHash, "Invalid secret");
        require(block.number > agreement.createdBlock, "Must reveal in a later block");

        delete agreements[_agreementId];

        emit SecretRevealed(_agreementId, msg.sender, _secret);
        return _secret;
    }
}
