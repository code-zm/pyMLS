#### Overview
The `WelcomeMessage` class facilitates the creation and processing of Welcome messages in the Messaging Layer Security (MLS) protocol. It includes methods to construct, serialize, and deserialize Welcome messages, ensuring secure group operations.

#### Class: `WelcomeMessage`

Attributes:
- `groupContext`: Represents the group context (group ID, epoch, etc.) for the MLS group.
- `ratchetTree`: An instance of `RatchetTree` used to maintain group state.
- `keySchedule`: Instance of `KeySchedule` for deriving and managing cryptographic secrets.
- `groupVersion`: Version of the MLS protocol.
- `groupCipherSuite`: Cipher suite used for cryptographic operations.
- `keyPackage`: A `KeyPackage` instance for managing key-related information of the new member.

Methods:
1. `createWelcome(self, keyPackage: KeyPackage) -> Dict[str, Any]`
    - Generates a Welcome message for a new member using their `KeyPackage`.
    - Includes encryption of the `epochSecret` and serialization of the public ratchet tree.
    - Returns: Dictionary containing the Welcome message fields.

2. `processWelcome(self, welcomeMessage: Dict[str, Any], privateKey: bytes)`
    - Processes an incoming Welcome message to initialize a new member's state.
    - Decrypts group secrets and synchronizes the ratchet tree with the provided public state.

3. `serialize(self) -> bytes`
    - Serializes the Welcome message into a JSON-compatible format for storage or transmission.

4. `deserialize(data: bytes) -> "WelcomeMessage"`
    - Static method to deserialize a Welcome message from a JSON format back into a `WelcomeMessage` instance.

Exceptions:
- Throws `ValueError` for invalid `KeyPackage` inputs or mismatched encryption/decryption states.

Dependencies:
- Uses cryptographic primitives from the `cryptography` library, such as `HKDF` and `AESGCM`.
