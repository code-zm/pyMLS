#### Overview
The `test_messageframing.py` script contains a suite of unit tests for validating the `MessageFraming` implementation. The tests ensure compliance with the MLS protocol and verify the robustness of encryption, decryption, signing, and decoding functionalities.

#### Test Cases
1. `test_encrypt_sender_data`:
    - Verifies that the `encrypt_sender_data` method produces the expected output length (nonce + sender data + tag).

2. `test_encrypt_and_decrypt_message`:
    - Ensures that an encrypted message can be decrypted correctly, preserving the original plaintext.

3. `test_sign_and_verify_message`:
    - Validates the signing and verification of public messages, ensuring the signature binds the message to the metadata.

4. `test_public_message_encoding_decoding`:
    - Tests the encoding and decoding of public messages, verifying that no data is lost during the process.

5. `test_private_message_encoding_decoding`:
    - Validates the encoding and decoding of private messages, ensuring sender data, ciphertext, and authentication tag remain consistent.
