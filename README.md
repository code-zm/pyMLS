# Messaging Layer Security (MLS) Library

This library is a work-in-progress implementation of the Messaging Layer Security (MLS) protocol, designed in accordance with RFC 9420. It provides the foundations for a secure group messaging framework, including key management, message protection, and transcript hash integrity.

**⚠️ Disclaimer**: This library is **not ready for production use**. It is currently under development and has not undergone sufficient testing or validation for security-critical environments.

---

## Features

- **Group Management**: Create and manage groups with secure membership changes.
- **Message Protection**: Encrypt, sign, and authenticate group messages.
- **Cryptographic Primitives**: Secure cryptographic operations for key derivation and encryption.
- **Transcript Hash Integrity**: Ensure that all group operations maintain a consistent cryptographic transcript hash.
- **Extensibility**: Modular design for additional MLS features and custom integrations.

## Components

The library is modular, with each component implementing specific MLS functionalities:

### 1. **Commit**

Handles Commit messages, which are used to propose and confirm group state changes.

- **Features**:
    - Serialize and deserialize Commit messages.
    - Sign and verify Commit messages.
    - Apply group state changes (e.g., member addition/removal).

---

### 2. **HandshakeMessages**

Implements the MLS handshake messages, including Add, Update, Remove, and Commit types.

- **Features**:
    - Serialize and deserialize handshake messages.
    - Validate and verify handshake operations.
    - Manage group member updates.

---

### 3. **KeySchedule**

Manages the cryptographic key schedule for secure group communications.

- **Features**:
    - Derive epoch secrets and keys.
    - Transition keys after Commit operations.
    - Validate key schedule updates.

---

### 4. **MessageFraming**

Handles the framing and encryption of MLS messages.

- **Features**:
    - Encrypt and decrypt group messages.
    - Authenticate and validate message integrity.
    - Detect and handle tampered ciphertexts.

---

### 5. **Proposals**

Implements MLS proposal types, including Add, Remove, and Update.

- **Features**:
    - Serialize and deserialize proposals.
    - Sign and verify proposal integrity.
    - Validate proposal types and fields.

---

### 6. **RatchetTree**

Manages the binary Ratchet Tree used for key derivation and group state representation.

- **Features**:
    - Initialize and update the Ratchet Tree.
    - Synchronize tree states across members.
    - Validate tree operations.

---

### 7. **TranscriptHashManager**

Centralized manager for transcript hash updates and validation.

- **Features**:
    - Compute transcript hashes for all operations.
    - Update hashes after each group operation.
    - Validate hashes against expected values.

---

### 8. **WelcomeMessage**

Manages Welcome messages, which are used to onboard new members to the group.

- **Features**:
    - Serialize and deserialize Welcome messages.
    - Encrypt and decrypt group secrets for new members.
    - Synchronize the group state.

---

### 9. **Tests**

Comprehensive test suite to validate the functionality of all components.

- **Features**:
    - Unit tests for individual components.
    - Integration tests for full group workflows.
    - Performance tests for large groups.

---

## TODO List

### 1. Core Protocol Implementation

- [ ]  Verify group state consistency during dynamic membership changes.
- [ ]  Test all proposal types for serialization, deserialization, and validation.
- [ ]  Finalize Commit and Welcome message handling.

### 2. Cryptographic Operations

- [ ]  Validate epoch secret derivation and transitions.
- [ ]  Optimize Ratchet Tree updates for performance.
- [ ]  Ensure tamper detection for all messages.

### 3. Testing

- [ ]  Write unit tests for all edge cases and error scenarios.
- [ ]  Simulate full group workflows with known-good test vectors.
- [ ]  Benchmark large group operations (e.g., 1000 members).

### 4. Documentation

- [ ]  Add examples for using each component.
- [ ]  Write a developer guide for library internals.

### 5. Packaging

- [ ]  Prepare the library for distribution as a pip package.
- [ ]  Publish to GitHub with a clear project structure.
- [ ]  Publish to PyPI after thorough testing.

