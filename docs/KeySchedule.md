### KeySchedule.py
The `KeySchedule.py` module implements the key schedule for the Messaging Layer Security (MLS) protocol, as defined in RFC 9420. It handles the derivation of cryptographic secrets for each epoch, ensuring secure transitions and maintaining group state integrity.

#### Class: `KeySchedule`
Represents the key schedule for secure derivation and management of cryptographic secrets in the MLS protocol.

##### Attributes:
- `initSecret (bytes)`: The initial input to the key schedule, used to bootstrap the derivation process.
- `currentEpochSecret (Optional[bytes])`: The secret for the current epoch, used as input for deriving other secrets.
- `epoch (int)`: The current epoch number, incremented with each transition.
- `encryptionSecret (Optional[bytes])`: The derived encryption secret for the epoch.
- `authenticationSecret (Optional[bytes])`: The derived authentication secret for the epoch.
- `exporterSecret (Optional[bytes])`: The secret used for exporting application-specific keys.
- `resumptionSecret (Optional[bytes])`: The secret for resumption in subsequent sessions.
- `confirmationKey (Optional[bytes])`: The key used for confirmation during epoch transitions.
- `epochAuthenticator (Optional[bytes])`: The authenticator derived for the current epoch.

##### Methods:
1. `__init__(self, initialSecret: bytes)` Initializes the key schedule with an initial secret.
    - Parameters:
        - `initialSecret`: A byte string used as the input to initialize the key schedule.

2. `deriveSecret(self, inputSecret: bytes, label: str, context: bytes, length: int = 32) -> bytes` Derives a new secret using HKDF with a specific label and context.
    - Parameters:
        - `inputSecret`: The input key material (IKM).
        - `label`: A string label for the derivation.
        - `context`: Contextual information to bind the derivation.
        - `length`: Length of the derived secret in bytes (default: 32).
    - Returns:
        - A byte string of the derived secret.

3. `injectPreSharedKey(self, psk: bytes)` Injects a pre-shared key (PSK) into the current key schedule.
    - Parameters:
        - `psk`: The pre-shared key to inject as a byte string.

4. `exportSecret(self, label: str, context: bytes, length: int = 32) -> bytes` Exports a derived secret for external protocols.
    - Parameters:
        - `label`: Label for the derivation.
        - `context`: Contextual information to bind the derivation.
        - `length`: Length of the exported secret in bytes (default: 32).
    - Returns:
        - A byte string of the exported secret.

5. `deriveEpochAuthenticator(self, confirmationKey: bytes) -> bytes` Derives an epoch authenticator to bind the epoch state.
    - Parameters:
        - `confirmationKey`: The confirmation key from the key schedule.
    - Returns:
        - The epoch authenticator as a byte string.

6. `nextEpoch(self, commitSecret: bytes, context: bytes, hashManager: TranscriptHashManager, psk: Optional[bytes] = None)` Derives the secrets for the next epoch using the commitSecret, context, and transcript hash.
    - Parameters:
        - `commitSecret`: Fresh entropy introduced during the Commit phase.
        - `context`: The group context (e.g., group ID, epoch, etc.).
        - `hashManager`: A centralized manager for transcript hashes.
        - `psk`: Optional pre-shared key to inject.

7. `updateForCommit(self, commitSecret: bytes, context: bytes, hashManager: TranscriptHashManager, psk: Optional[bytes] = None)` Updates the key schedule for a new epoch after a commit.
    - Parameters:
        - `commitSecret`: Secret derived from the Commit message.
        - `context`: The updated group context.
        - `hashManager`: The centralized transcript hash manager.
        - `psk`: Optional pre-shared key to inject.

8. `getEpochSecrets(self) -> dict` Returns all secrets for the current epoch as a dictionary.
    - Returns:
        - A dictionary containing the current epoch secrets (`epochSecret`, `encryptionSecret`, etc.).
