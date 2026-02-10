# Mental Poker with Bayer-Groth Shuffle

A Rust implementation of a Mental Poker protocol using the Bayer-Groth verifiable shuffle scheme. This allows multiple players to play poker (or other card games) over a network without requiring a trusted dealer.

## Overview

Mental Poker enables distributed card games where:
- All players can shuffle and deal cards
- Card values remain encrypted and secret
- Shuffles are verifiable via zero-knowledge proofs
- No single player can see card values before they're dealt

## Cryptographic Protocol

### Core Components

1. **Deck Initialization**: 52 cards mapped to secp256k1 curve points using SHA-256 hash-to-point derivation
2. **ElGamal Encryption**: Cards encrypted with the dealer's public key
3. **Bayer-Groth Shuffle**: 
   - Applies random permutation to ciphertexts
   - Rerandomizes each ciphertext with fresh random values
   - Generates zero-knowledge proof (commitments A_i, B_i, responses c_i, r_i)
4. **Verification**: Aggregate proof checks that rerandomization was correct
5. **Dealing**: Cards popped from front of shuffled deck

### Security Guarantees

- No single player can see card values
- Shuffles are verifiable by all parties
- Deck integrity is maintained throughout
- Cards can only be decrypted by the dealer

## Usage

```bash
cargo run
```

This runs a simulation demonstrating:
1. Player setup and key generation
2. Multiple shuffle rounds with proof verification
3. Card dealing to players
4. Decryption phase
5. Security verification checks

## Running Tests

```bash
cargo test
```

## Project Structure

```
koblitzelgamal/
├── Cargo.toml          # Rust project manifest
├── Cargo.lock          # Dependency lock file
├── README.md           # This file
└── src/
    └── main.rs         # Main implementation
```

## Dependencies

- **k256**: secp256k1 elliptic curve cryptography
- **rand**: Random number generation (OsRng)
- **hex**: Hex encoding utilities
- **sha2**: SHA-256 hashing
- **thiserror**: Error handling

## Limitations

- Single-party decryption (dealer holds secret key)
- Shuffle verification checks aggregate properties but not full permutation proof
- No network protocol layer for real multi-player communication

## Security Considerations

**Important Limitations:**

1. **Aggregate Proof Only**: The current shuffle verification (`verify_shuffle`) only checks aggregate properties of the shuffle. It verifies that the sum of rerandomization commitments matches the ciphertext differences, but it does NOT fully verify that the correct permutation was applied. A sophisticated attacker could potentially manipulate individual ciphertexts while preserving the aggregate sums.

2. **Centralized Decryption**: All cards are encrypted with the dealer's public key, meaning only the dealer can decrypt cards. In a true multi-party mental poker protocol, threshold decryption should be used where multiple parties must collaborate to decrypt cards.

3. **No Replay Attack Protection**: The protocol does not include nonce or timestamp mechanisms to prevent replay attacks.

4. **Lack of Formal Security Proofs**: This implementation has not undergone formal cryptographic verification.

For production deployment, additional work is needed for:
- Threshold decryption (multi-party computation)
- Full permutation proof verification (complete Bayer-Groth proof)
- Network protocol layer
- Comprehensive security review
- Formal verification of cryptographic properties
