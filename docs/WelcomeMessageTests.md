#### Overview
This script contains unit tests for the `WelcomeMessage` class, validating its correctness against expected functionality.

#### Tests

Test Class: `TestWelcomeMessage`
Setup (`setUp`):
- Initializes mock components like `RatchetTree`, `KeySchedule`, `KeyPackage`, and group-related parameters.
- Prepares an instance of the `WelcomeMessage` class for testing.

Test Cases:
1. `testCreateWelcomeMessage`
    - Validates the creation of a Welcome message.
    - Checks for the presence of required fields (`groupContext`, `encryptedGroupSecrets`, etc.) in the output.

2. `testSerializeWelcomeMessage`
    - Ensures the Welcome message can be serialized into a JSON-compatible byte format.

3. `testDeserializeWelcomeMessage`
    - Verifies that a serialized Welcome message can be deserialized back into a `WelcomeMessage` object.

4. `testProcessWelcomeMessage`
    - Simulates processing an incoming Welcome message.
    - Ensures decryption and group state synchronization are performed correctly.

Mocks:
- `MockRatchetTree`: Simulates a complete binary tree structure for the ratchet tree.
- `MockKeySchedule`: Provides epoch secrets and other cryptographic parameters.

Dependencies:
- Uses the `unittest` framework and the `cryptography` library for cryptographic primitives.
- Requires the `pyMLS` package containing the `WelcomeMessage` class and related modules.
