## SecretKeeper 🤫

**SecretKeeper Smart Contract**

This repository contains a Solidity smart contract that allows any two parties to store and later reveal a mutually agreed-upon secret on-chain. This contract can be used as a proof that both parties agreed on something at a specific block, and it allows either party to reveal the secret at a later time.

**Contract Functionality**

- **Storing a Secret:**
  - The contract enables any two parties to agree and sign off on a secret. Both parties must provide their digital signatures to confirm their agreement, allowing the secret to be securely stored on-chain.
  - The secret is stored in a hashed format, ensuring that its value remains hidden from observers and cannot be deduced directly from on-chain data.

- **Revealing the Secret:**
  - At any future block after storing the secret, either of the two parties can reveal its actual value on-chain.
  - Upon revelation, the contract emits an event specifying the revealing party and the real value of the secret. The original stored secret is then deleted from the contract’s storage.

- **Single Transaction Registration:**
  - The secret must be registered in a single transaction, ensuring that both parties’ signatures and the secret itself are stored in the same block. This guarantees that the agreement is atomic and timestamped at the block level.

**Implementation Details**

- **Signature Validation:**
  - The contract uses off-chain signatures to verify the agreement between the two parties. Both parties sign the secret off-chain, and their signatures are validated on-chain when the secret is stored.

This contract can be adapted for various use cases where proof of a mutual agreement is required, with the option to reveal and remove the information at a later date.

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```


