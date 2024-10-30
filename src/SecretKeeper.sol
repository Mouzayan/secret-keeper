// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import {ISecretKeeper} from "./interfaces/ISecretKeeper.sol";

// TODO: add contract description
// TODO: ADD Natspec
contract SecretKeeper is ISecretKeeper, EIP712 {
    // ============================================ STATE ==============================================
    // =================== Constants =====================
    bytes32 private constant _AGREEMENT_TYPEHASH =
        keccak256("SecretAgreement(address party1,address party2,bytes32 secretHash)");

    // ================ Agreements State =================
    // Incremental IDs are predictable (1, 2, 3...)
    // Attackers can predict the next ID and potentially front-run transactions
    // Hash-based IDs are pseudorandom and harder to predict
    // incremental IDs do have advantages: Lower gas cost (no hashing required), easier to track total number of items, simpler to iterate through, human-readable
    mapping(bytes32 => SecretAgreement) public agreements;

    /**
     * @notice Sets up the contract by initializing EIP712 domain separator.
     */
    constructor() EIP712("SecretKeeper", "1") {}

    /**
     * @notice Creates a new secret agreement between two parties with signatures.
     *
     * @param _party2                     The address of the second party in the agreement.
     * @param _secretHash                 The keccak256 hash of the secret being stored.
     * @param _party1Signature            The EIP712 signature of the first party (msg.sender).
     * @param _party2Signature            The EIP712 signature of the second party.
     *
     * @return                            The unique identifier for the created agreement.
     */
    function createAgreement(
        address _party2,
        bytes32 _secretHash,
        bytes memory _party1Signature,
        bytes memory _party2Signature
    ) external returns (bytes32) {
        // Checks
        require(_party2 != address(0), "Zero address");
        require(_party2 != msg.sender, "Party1 and Party2 cannot be the same");

        // Create the EIP-712typed data hash
        bytes32 structHash = keccak256(abi.encode(_AGREEMENT_TYPEHASH, msg.sender, _party2, _secretHash));
        // make the hash compatible with wallet signatures
        bytes32 hash = _hashTypedDataV4(structHash);

        // verify the signatures by recovering the signer's address using the hash and the signatures
        require(ECDSA.recover(hash, _party1Signature) == msg.sender, "ECDSAInvalidSignature");
        require(ECDSA.recover(hash, _party2Signature) == _party2, "ECDSAInvalidSignature");

        // Effects
        bytes32 agreementId = keccak256(abi.encodePacked(msg.sender, _party2, block.timestamp));

        agreements[agreementId] = SecretAgreement({
            party1: msg.sender,
            party2: _party2,
            secretHash: _secretHash, // Only the hash is stored on-chain (privacy)
            createdBlock: block.number
        });

        emit SecretStored(agreementId, msg.sender, _party2, block.number);
        return agreementId; // check if we name the return variable, if we can eleminiate the return statement.
    }

    /**
     * @notice Reveals a previously stored secret and deletes the agreement.
     *
     * @param _agreementId               The unique identifier of the agreement.
     * @param _secret                    The original secret being revealed.
     *
     * @return                           The revealed secret string.
     */
    function revealSecret(
        bytes32 _agreementId,
        string memory _secret // The original secret is needed to reveal (proof of knowledge)
    ) external returns (string memory) {
        SecretAgreement storage agreement = agreements[_agreementId];

        // Check secret existence by verifying party1 is not zero address (default value)
        require(agreement.party1 != address(0), "Agreement does not exist");
        require(msg.sender == agreement.party1 || msg.sender == agreement.party2, "Not authorized");
        require(keccak256(abi.encodePacked(_secret)) == agreement.secretHash, "Invalid secret");
        require(block.number > agreement.createdBlock, "Must reveal in a later block");

        // Delete the agreement from storage
        // This sets all values in the struct to their default values (0, false, etc.)
        // After deletion, any attempt to access this agreement will return default values
        // It also frees up blockchain storage space, resulting in a gas refund ???? CONFIRM ABOUT THE GAS REFUND
        delete agreements[_agreementId];

        emit SecretRevealed(_agreementId, msg.sender, _secret);
        return _secret; // check if we name the return variable, if we can eleminiate the return statement.
    }
}
