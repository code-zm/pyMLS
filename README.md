# pyMLS - Message Layer Security (MLS) Implementation

**pyMLS** is a Python implementation of the Message Layer Security (MLS) protocol, designed for secure and efficient group messaging. This project aims to adhere to the RFC 9420 standard.

---

## Current Functionality

- **HandshakeMessages**: Add, Update, Remove, Commit message handling with RFC-compliant structures.
- **KeyPackage**: Construction, signing, serialization, and validation.
- **KeySchedule**: Epoch secret derivation with support for PSK injection.
- **MessageFraming**: Encoding/decoding for Public and Private messages with AES-GCM encryption.
- **Proposals**: AddProposal, UpdateProposal, RemoveProposal with validation.
- **RatchetTree**: Efficient group state management through tree-based cryptography.
- **SecretTree**: Secure key and nonce derivation for handshake and application messages.
- **TranscriptHashManager**: Ensures transcript consistency across group state transitions.
- **WelcomeMessage**: Secure group creation and member onboarding.

---

## TODO

#### KeyPackage
1. Add detailed validation for fields (e.g., HPKE key checks, signature expiration).
2. Incorporate support for pre-shared keys (PSKs) for external initialization.

#### KeySchedule
1. Complete integration with the `SecretTree` for encryption key derivation.
2. Validate derived secrets against expected outputs for compliance with RFC Section 9.1.

#### MessageFraming
1. Add robust nonce management to prevent AES-GCM nonce reuse.
2. Implement padding mechanisms to obscure message length (Section 15.1).

#### Proposals
1. Validate proposal inputs (e.g., KeyPackages in AddProposal) against group capabilities.
2. Implement proposal list validation checks (RFC Section 12.2).

#### RatchetTree
1. Add functions for validating parent and tree hash calculations (Sections 7.8 and 7.9).
2. Implement synchronization mechanisms for distributed tree views (Section 7.5).

#### SecretTree
1. Enforce deletion schedules for leaf nodes (Section 9.2).
2. Enhance support for epoch transitions and synchronization.

#### TranscriptHashManager
1. Add base hash integrity checks for stronger validation.

#### WelcomeMessage
1. Add support for group context extensions (Section 11.1).
2. Improve validation for encrypted fields (e.g., nonce and ciphertext checks) to ensure consistency.

---

## Contributions

Contributions are welcome! Please create an issue or submit a pull request.

---
