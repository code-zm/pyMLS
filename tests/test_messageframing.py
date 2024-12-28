import unittest
import os
from pyMLS.MessageFraming import MessageFraming, PublicMessage, PrivateMessage
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


class TestMessageFraming(unittest.TestCase):
    def setUp(self):
        # Mock key schedule with fixed secrets
        class MockKeySchedule:
            def __init__(self):
                self.handshakeKey = b'\x01' * 32
                self.handshakeNonce = b'\x02' * 12
                self.applicationKey = b'\x03' * 32
                self.applicationNonce = b'\x04' * 12

            def getLeafSecrets(self, leafIndex, epoch):
                return {
                    "handshakeKey": self.handshakeKey,
                    "handshakeNonce": self.handshakeNonce,
                    "applicationKey": self.applicationKey,
                    "applicationNonce": self.applicationNonce,
                }

        self.key_schedule = MockKeySchedule()

        # Generate public key from the mock handshakeKey
        signing_key = Ed25519PrivateKey.from_private_bytes(self.key_schedule.handshakeKey)
        self.public_key_bytes = signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Use fixed encryption secret
        self.encryption_secret = "00112233445566778899aabbccddeeff"

        # Use fixed group ID, epoch, and leaf index for consistency
        self.group_id = b"TestGroupID12345"  # Fixed 16-byte group ID
        self.epoch = 1
        self.leaf_index = 0

        # Initialize MessageFraming instance
        self.mf = MessageFraming(self.key_schedule, self.epoch, self.leaf_index)

    def testEncryptSenderData(self):
        sender_data = self.group_id + self.epoch.to_bytes(4, 'big')
        encrypted_sender_data = self.mf.encryptSenderData(sender_data, self.group_id)
        expected_length = 12 + len(sender_data) + 16  # nonce + sender_data + tag
        self.assertEqual(len(encrypted_sender_data), expected_length)

    def testEncryptAndDecryptMessage(self):
        plaintext = b"Hello, MLS!"
        private_message = self.mf.encryptMessage(plaintext, self.group_id)
        decrypted_message = self.mf.decryptMessage(private_message, self.group_id)
        self.assertEqual(plaintext, decrypted_message)

    def testSignAndVerifyMessage(self):
        content = b"This is a public message."
        public_message = self.mf.createPublicMessage(content, self.group_id)
        verification_result = self.mf.verifySignature(public_message, self.public_key_bytes)
        self.assertTrue(verification_result)

    def testPublicMessageEncodingDecoding(self):
        content = b"Public message content."
        signature = self.mf.signMessage(content, self.group_id)
        public_message = PublicMessage(content, signature, self.group_id, self.epoch)
        encoded_message = public_message.encode()
        decoded_message = PublicMessage.decode(encoded_message)
        self.assertEqual(public_message.content, decoded_message.content)
        self.assertEqual(public_message.signature, decoded_message.signature)
        self.assertEqual(public_message.groupId, decoded_message.groupId)
        self.assertEqual(public_message.epoch, decoded_message.epoch)

    def testPrivateMessageEncodingDecoding(self):
        sender_data = b"Sender data"
        ciphertext = b"Ciphertext data"
        auth_tag = b"Auth tag"

        private_message = PrivateMessage(sender_data, ciphertext, auth_tag)
        encoded_message = private_message.encode()
        decoded_message = PrivateMessage.decode(encoded_message)

        self.assertEqual(private_message.senderData, decoded_message.senderData)
        self.assertEqual(private_message.ciphertext, decoded_message.ciphertext)
        self.assertEqual(private_message.authTag, decoded_message.authTag)


if __name__ == "__main__":
    unittest.main()
