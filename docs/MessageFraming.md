#### Overview

The `MessageFraming.py` script implements the core functionality for securely handling message framing as specified by the MLS protocol (RFC 9420). It supports both public and private messages with encryption, signing, and decoding capabilities.

#### Classes
1. `PublicMessage`:
    - Represents a public message with metadata, signature, and content.
    - Methods:
        - `encode()`: Serializes the message for transmission.
        - `decode(encoded_message: bytes)`: Deserializes the message from bytes.

2. `PrivateMessage`:
    - Represents a private message with encrypted sender data, ciphertext, and an authentication tag.
    - Methods:
        - `encode()`: Serializes the private message.
        - `decode(encoded_message: bytes)`: Deserializes the private message, extracting sender data, ciphertext, and the authentication tag.

3. `MessageFraming`:
    - Provides core functionality for encrypting, decrypting, signing, and verifying messages.
    - Methods:
        - `encrypt_sender_data(sender_data, group_id, epoch)`: Encrypts metadata such as group ID and epoch.
        - `encrypt_message(plaintext, group_id, epoch)`: Encrypts a message, encapsulating metadata, ciphertext, and authentication tag into a `PrivateMessage`.
        - `decrypt_message(private_message, group_id, epoch)`: Decrypts a private message while validating metadata.
        - `sign_message(plaintext, group_id, epoch)`: Signs a message using Ed25519.
        - `verify_signature(public_message, public_key, expected_group_id, expected_epoch)`: Verifies the signature of a public message while validating group metadata.
        - `create_public_message(content, group_id, epoch)`: Creates a signed public message.
        - `process_public_message(encoded_message, public_key)`: Processes an encoded public message, verifying its signature and metadata.

#### Key Features
- Public Messages:
    - Signed for authenticity.
    - Includes group metadata (`group_id` and `epoch`) for validation.
- Private Messages:
    - Encrypted using AES-GCM for confidentiality and integrity.
    - Includes `sender_data`, which encapsulates metadata like `group_id`, `epoch`, and `nonce`.
