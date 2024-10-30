// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

// TODO: CREATE interface for the contract
// TODO: add contract description
// TODO: ADD Natspec
contract SecretKeeper is EIP712 {
    struct SecretAgreement {
        address party1;
        address party2;
        bytes32 secretHash;
        uint256 createdBlock;
    }

    bytes32 private constant _AGREEMENT_TYPEHASH =
        keccak256("SecretAgreement(address party1,address party2,bytes32 secretHash)");

    // Incremental IDs are predictable (1, 2, 3...)
    // Attackers can predict the next ID and potentially front-run transactions
    // Hash-based IDs are pseudorandom and harder to predict
    // incremental IDs do have advantages: Lower gas cost (no hashing required), easier to track total number of items, simpler to iterate through, human-readable
    mapping(bytes32 => SecretAgreement) public agreements;

    event SecretStored(
        bytes32 indexed agreementId, address indexed party1, address indexed party2, uint256 storedBlock
    ); // check if the storedBlock needs to be indexed. and if the agreementId needs to be indexed.
    event SecretRevealed(bytes32 indexed agreementId, address indexed revealer, string secret);

    constructor() EIP712("SecretKeeper", "1") {}

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
