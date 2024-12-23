import unittest
import os
from pyMLS.MessageFraming import MessageFraming, PublicMessage, PrivateMessage
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

class TestMessageFraming(unittest.TestCase):
    def setUp(self):
        # Generate valid Ed25519 keys for testing
        private_key = Ed25519PrivateKey.generate()
        self.authentication_secret = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Convert the authentication secret to a hex string for compatibility
        self.authentication_secret_hex = self.authentication_secret.hex()

        self.public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Use a fixed encryption secret
        self.encryption_secret = "00112233445566778899aabbccddeeff"

        # Initialize MessageFraming instance
        self.mf = MessageFraming(self.encryption_secret, self.authentication_secret_hex)

        # Use fixed group ID and epoch for consistency
        self.group_id = b"TestGroupID12345"  # Fixed 16-byte group ID
        self.epoch = 1

    def test_encrypt_sender_data(self):
        sender_data = self.group_id + self.epoch.to_bytes(4, 'big')
        encrypted_sender_data = self.mf.encrypt_sender_data(sender_data, self.group_id, self.epoch)
        expected_length = 12 + len(sender_data) + 16  # nonce + sender_data + tag
        self.assertEqual(len(encrypted_sender_data), expected_length)

    def test_encrypt_and_decrypt_message(self):
        plaintext = b"Hello, MLS!"
        private_message = self.mf.encrypt_message(plaintext, self.group_id, self.epoch)
        decrypted_message = self.mf.decrypt_message(private_message, self.group_id, self.epoch)
        self.assertEqual(plaintext, decrypted_message)


    def test_sign_and_verify_message(self):
        content = b"This is a public message."
        public_message = self.mf.create_public_message(content, self.group_id, self.epoch)
        verification_result = self.mf.verify_signature(public_message, self.public_key_bytes, self.group_id, self.epoch)
        self.assertTrue(verification_result)


    def test_public_message_encoding_decoding(self):
        content = b"Public message content."
        signature = self.mf.sign_message(content, self.group_id, self.epoch)
        public_message = PublicMessage(content, signature, self.group_id, self.epoch)
        encoded_message = public_message.encode()
        decoded_message = PublicMessage.decode(encoded_message)
        self.assertEqual(public_message.content, decoded_message.content)
        self.assertEqual(public_message.signature, decoded_message.signature)
        self.assertEqual(public_message.group_id, decoded_message.group_id)
        self.assertEqual(public_message.epoch, decoded_message.epoch)

    def test_private_message_encoding_decoding(self):
        sender_data = b"Sender data"
        ciphertext = b"Ciphertext data"
        auth_tag = b"Auth tag"

        private_message = PrivateMessage(sender_data, ciphertext, auth_tag)
        encoded_message = private_message.encode()
        decoded_message = PrivateMessage.decode(encoded_message)

        self.assertEqual(private_message.sender_data, decoded_message.sender_data)
        self.assertEqual(private_message.ciphertext, decoded_message.ciphertext)
        self.assertEqual(private_message.auth_tag, decoded_message.auth_tag)



            
if __name__ == "__main__":
    unittest.main()
